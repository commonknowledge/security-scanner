"""Check every website listed in Linear (see linear_sites.py).

Every site:
- it's up, on HTTPS with a valid certificate that isn't about to expire. A staging site that's
  down is skipped silently (staging is often switched off);
- nothing that should be private is public: an exposed .git directory or .env file, and on
  WordPress an exposed debug.log or a browsable uploads directory. (WordPress's public user list
  isn't reported: it's low risk, and the CK Health plugin closes it.)

Maintained WordPress sites, through the CK Health plugin (signed request, see wp-plugin/README.md):
- the plugin answers and is the latest release;
- WordPress, plugins and themes have no updates waiting, and PHP is still supported;
- no account has an easily guessed password;
- login rate limiting is on, and sees the scanner's real IP address;
- WordPress is still checking for updates (otherwise the update information is stale).
A WordPress site whose plugin doesn't answer also gets its XML-RPC endpoint reported, since without
the plugin nothing rate-limits logins through it.

Sites not maintained by us (labelled no-maintained-website) only get the first
two groups, reported separately.
"""
import base64, collections, json, os, re, socket, ssl, time, urllib.error, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import date

HERE = os.path.dirname(os.path.abspath(__file__))
UA = "ck-security-scanner (+https://github.com/commonknowledge/security-scanner)"
TIMEOUT = 20
CERT_WARN_DAYS = 14
UPDATE_CHECK_STALE_DAYS = 3
REPO = "commonknowledge/security-scanner"
SIGNED_MESSAGE_PREFIX = b"ck-health-v1\n"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(url, headers=None, limit=300_000, follow=True):
    """(status, final_url, headers, body) without raising on HTTP errors. Raises on network/TLS errors."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            return r.status, r.geturl(), r.headers, r.read(limit)
    except urllib.error.HTTPError as err:
        return err.code, err.geturl() or url, err.headers, err.read(limit) if err.fp else b""


def cert_days_left(host, port=443):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock, ctx.wrap_socket(sock, server_hostname=host) as tls:
        return (ssl.cert_time_to_seconds(tls.getpeercert()["notAfter"]) - time.time()) / 86400


def version_key(version):
    parts = [int(p) for p in re.findall(r"\d+", str(version).split("-")[0])]
    return tuple(parts + [0] * (4 - len(parts)))


CHALLENGE_TITLES = re.compile(rb"<title[^>]*>\s*(One moment, please|Just a moment|Attention Required|Checking your browser|"
                              rb"Please wait|DDoS-Guard|Security check)", re.I)


def is_challenge(body, headers):
    """A bot-protection page (hosting firewall, Cloudflare) instead of the site: it answers 200 or
    403/503, but nothing behind it can be checked."""
    return ((headers.get("cf-mitigated") or "").lower() == "challenge"   # Cloudflare
            or (headers.get("sg-captcha") or "").lower() == "challenge"   # SiteGround (answers 202)
            or b"/.well-known/sgcaptcha/" in body[:5000]
            or bool(CHALLENGE_TITLES.search(body[:5000])))


def is_wordpress(body, headers, host):
    """WordPress serves its own /wp-content/ or /wp-includes/ files, and advertises its REST API
    (rel="https://api.w.org/"). A link to some other WordPress site doesn't count."""
    if "api.w.org" in (headers.get("Link") or ""):
        return True
    own = rb"(?:https?:)?//" + re.escape(host.encode()) + rb"/wp-(?:content|includes)/"
    return bool(re.search(rb"""(?:href|src)=["'](?:""" + own + rb"|/wp-(?:content|includes)/)", body)
                or re.search(rb"""rel=["']https://api\.w\.org/["']""", body)
                or re.search(rb"""<meta name=["']generator["'] content=["']WordPress""", body, re.I))


def unique_sites(sites):
    """Merge Linear's site entries by URL: one site can be listed on several projects.
    It counts as maintained if any of them is, and as live if any of them lists it as live."""
    merged = {}
    for s in sites:
        key = s["url"].strip().rstrip("/").lower()
        m = merged.setdefault(key, {"url": s["url"].strip(), "kind": s["kind"], "maintained": False, "projects": []})
        m["maintained"] |= s["maintained"]
        m["kind"] = "live" if "live" in (m["kind"], s["kind"]) else "staging"
        if s["project"] not in m["projects"]:
            m["projects"].append(s["project"])
    return list(merged.values())


# ---------------------------------------------------------------------------
# Signing (CK Health)
# ---------------------------------------------------------------------------

def plugin_public_key():
    src = open(os.path.join(HERE, "wp-plugin", "ck-health", "health.php")).read()
    return re.search(r"const SCANNER_PUBLIC_KEY = '([^']+)'", src)[1]


def signer(secret_b64):
    """A function returning signed request headers, or a problem string if signing can't work."""
    if not secret_b64:
        return "CK HEALTH NOT CHECKED: CK_HEALTH_SIGNING_KEY is not set"
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        return "CK HEALTH NOT CHECKED: the cryptography package isn't installed (pip install -r requirements.txt)"
    try:
        secret = base64.b64decode(secret_b64.strip(), validate=True)
        key = Ed25519PrivateKey.from_private_bytes(secret[:32])  # libsodium keys are seed + public key
    except ValueError as err:
        return f"CK HEALTH NOT CHECKED: CK_HEALTH_SIGNING_KEY isn't a valid key ({err})"
    public = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    if public != plugin_public_key():
        return "CK HEALTH NOT CHECKED: CK_HEALTH_SIGNING_KEY doesn't match the public key in the plugin"

    def headers():
        ts = str(int(time.time()))
        return {"X-CK-Health-Timestamp": ts,
                "X-CK-Health-Signature": base64.b64encode(key.sign(SIGNED_MESSAGE_PREFIX + ts.encode())).decode()}
    return headers


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def exposure(base, wordpress):
    """Things that should never be public. Each check needs a specific response, so a site that
    answers everything with its homepage isn't flagged."""
    out = []
    status, _, _, body = fetch(base + "/.git/HEAD", follow=False)
    if status == 200 and body.startswith(b"ref: "):
        out.append("its .git directory is public (source code and history can be downloaded)")
    status, _, headers, body = fetch(base + "/.env", follow=False)
    if status == 200 and "html" not in (headers.get("Content-Type") or "") and re.search(rb"^[A-Z][A-Z0-9_]+=", body, re.M):
        out.append("its .env file is public (likely contains secrets)")
    if wordpress:
        status, _, _, body = fetch(base + "/wp-content/debug.log", follow=False)
        if status == 200 and re.search(rb"PHP (Warning|Notice|Fatal|Deprecated|Parse)", body):
            out.append("wp-content/debug.log is public (leaks file paths and errors)")
        status, _, _, body = fetch(base + "/wp-content/uploads/", follow=False)
        if status == 200 and b"Index of /" in body:
            out.append("wp-content/uploads/ can be browsed (directory listing is on)")
    return out


def health_problems(report, latest_plugin, php_eol, scanner_ip):
    """Problems in a CK Health status report."""
    out = []
    if latest_plugin and version_key(report.get("plugin_version", "0")) < version_key(latest_plugin):
        out.append(f"CK Health is {report.get('plugin_version')}, latest is {latest_plugin} (turn on its auto-updates)")
    wp = report.get("wordpress") or {}
    if wp.get("update_available"):
        out.append(f"WordPress {wp.get('version')} has an update waiting: {wp['update_available']}")
    checked = wp.get("updates_last_checked")
    if checked and time.time() - checked > UPDATE_CHECK_STALE_DAYS * 86400:
        out.append(f"WordPress hasn't checked for updates since {date.fromtimestamp(checked)} "
                   f"(WP-Cron may not be running), so its update information is out of date")
    for kind in ("plugins", "themes"):
        for item in report.get(kind) or []:
            if item.get("update_available"):
                state = "" if item.get("active") else ", inactive"
                out.append(f"{kind[:-1]} {item.get('name')} {item.get('version')} has an update waiting: "
                           f"{item['update_available']}{state}")
    php = (report.get("php") or {}).get("version", "")
    eol = php_eol.get(".".join(php.split(".")[:2]))
    if eol:
        out.append(f"PHP {php} has been unsupported since {eol} (no more security fixes)")
    weak = (report.get("passwords") or {}).get("weak") or []
    if weak:
        out.append(f"easily guessed password on {len(weak)} account{'s' if len(weak) != 1 else ''}: {', '.join(weak)}")
    limit = report.get("login_limit") or {}
    visitor = limit.get("visitor") or {}
    if not limit.get("active"):
        out.append(f"login rate limiting is off: the plugin can't tell visitors apart safely "
                   f"(connection from {visitor.get('remote_addr')})")
    elif scanner_ip and visitor.get("ip") != scanner_ip:
        out.append(f"login rate limiting sees the scanner as {visitor.get('ip')} (via {visitor.get('via')}), "
                   f"but most sites see {scanner_ip}: visitor detection is wrong, so it may lock out the wrong people")
    return out


def check_site(site, sign):
    """{"site", "skip", "problems", "report"} for one site. report is the CK Health status, if any."""
    url = site["url"].rstrip("/")
    result = {"site": site, "skip": False, "problems": [], "report": None}
    p = result["problems"]
    try:
        status, final, headers, body = fetch(url)
    except (urllib.error.URLError, OSError, ValueError) as err:
        reason = getattr(err, "reason", err)
        if site["kind"] == "staging":
            result["skip"] = True
        elif isinstance(reason, ssl.SSLCertVerificationError):
            p.append(f"its HTTPS certificate isn't valid: {reason.verify_message}")
        else:
            p.append(f"is down: {reason}")
        return result
    if is_challenge(body, headers):
        p.append("a bot-protection page blocked the scanner, so nothing could be checked "
                 "(allowlist the scanner in the site's firewall)")
        return result
    if site["kind"] == "staging" and status >= 500:
        result["skip"] = True
        return result
    parsed = urllib.parse.urlparse(final)
    if parsed.scheme != "https":
        p.append(f"isn't served over HTTPS (ends up at {final})")
    else:
        try:
            days = cert_days_left(parsed.hostname, parsed.port or 443)
            if days < CERT_WARN_DAYS:
                p.append(f"its HTTPS certificate expires in {max(0, int(days))} days")
        except (OSError, ValueError) as err:
            p.append(f"its HTTPS certificate couldn't be checked: {err}")
    if status >= 400:
        # 401: behind a login (fine, common for staging). Anything else stops the checks too, and on a
        # live site is worth knowing: 403 usually means it's blocking the scanner.
        if status != 401 and site["kind"] == "live":
            p.append(f"answers {status} to the scanner")
        return result
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
    wordpress = is_wordpress(body, headers, parsed.netloc)
    try:
        p += exposure(base, wordpress)
    except (urllib.error.URLError, OSError, ValueError) as err:
        p.append(f"exposure checks failed part-way: {getattr(err, 'reason', err)}")
    if wordpress and site["maintained"] and callable(sign):
        try:
            hstatus, _, _, hbody = fetch(base + "/?rest_route=/ck-health/v1/status", headers=sign(), limit=2_000_000)
        except (urllib.error.URLError, OSError, ValueError) as err:
            hstatus, hbody = None, str(getattr(err, "reason", err)).encode()
        if hstatus == 200:
            try:
                result["report"] = json.loads(hbody)
            except ValueError:
                p.append("the CK Health plugin answered, but not with JSON")
        elif hstatus == 404:
            p.append("the CK Health plugin isn't answering (not installed, deactivated, or PHP older than 7.2)")
        else:
            p.append(f"the CK Health plugin couldn't be reached ({hstatus or hbody.decode()[:100]})")
    if wordpress and result["report"] is None and site["maintained"]:
        xstatus, _, _, xbody = fetch(base + "/xmlrpc.php", follow=False)
        if xstatus == 405 and b"XML-RPC server accepts POST requests only" in xbody:
            p.append("XML-RPC is open with no login rate limiting (the CK Health plugin would limit it)")
    return result


def latest_plugin_release(github_token=None):
    try:
        req = urllib.request.Request(f"https://api.github.com/repos/{REPO}/releases/latest",
                                     headers={"User-Agent": UA, "Accept": "application/json",
                                              **({"Authorization": f"Bearer {github_token}"} if github_token else {})})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.load(r)["tag_name"].lstrip("v")
    except (urllib.error.URLError, OSError, KeyError, ValueError):
        return None


def php_end_of_life():
    """{"8.1": "2025-12-31", ...} for PHP versions past their end of life."""
    try:
        req = urllib.request.Request("https://endoflife.date/api/php.json", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            cycles = json.load(r)
    except (urllib.error.URLError, OSError, ValueError):
        return {}
    today = date.today().isoformat()
    return {c["cycle"]: c["eol"] for c in cycles if isinstance(c.get("eol"), str) and c["eol"] <= today}


def problems(sites, signing_key=None, github_token=None, workers=8):
    """(maintained, not_maintained): digest lines for maintained and not-maintained sites."""
    sign = signer(signing_key)
    latest_plugin, php_eol = latest_plugin_release(github_token), php_end_of_life()
    unique = unique_sites(sites)
    with ThreadPoolExecutor(workers) as pool:
        results = list(pool.map(lambda s: check_site(s, sign), unique))
    # The scanner's own IP is whatever most sites see; a site that sees something else misdetects visitors
    seen = collections.Counter(((r["report"] or {}).get("login_limit") or {}).get("visitor", {}).get("ip")
                               for r in results if r["report"])
    seen.pop(None, None)
    scanner_ip = seen.most_common(1)[0][0] if seen and seen.most_common(1)[0][1] >= 2 else None
    maintained, not_maintained = [], []
    for r in results:
        lines = list(r["problems"])
        if r["report"]:
            lines += health_problems(r["report"], latest_plugin, php_eol, scanner_ip)
        label = f"{r['site']['url']} ({r['site']['kind']}, {' / '.join(r['site']['projects'])})"
        (maintained if r["site"]["maintained"] else not_maintained).extend(f"{label}: {l}" for l in lines)
    if not callable(sign):
        maintained.insert(0, sign)
    checked = sum(not r["skip"] for r in results)
    print(f"Sites: {len(unique)} unique ({checked} checked, {len(unique) - checked} staging sites down and skipped), "
          f"{sum(1 for r in results if r['report'])} answered through CK Health")
    return maintained, not_maintained
