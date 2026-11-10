"""Check that the CK Health plugin release on our sites ships up-to-date, unvulnerable dependencies.

Sites install and update from the latest GitHub release, so that release's composer.lock is what
they run. It's compared with Packagist: every package must be on its latest stable version and
have no known security advisory. A lock on main that's newer than the release doesn't count until
it's released.
"""
import json, re, urllib.error, urllib.parse, urllib.request

REPO = "commonknowledge/security-scanner"
LOCK_PATH = "wp-plugin/ck-health/composer.lock"
STABLE = re.compile(r"^v?\d+(\.\d+)*$")
CONSTRAINT = re.compile(r"^(>=|<=|>|<|==|=|!=)?\s*v?(\d+(?:\.\d+)*)")


def _get(url, token=None):
    headers = {"Accept": "application/json", "User-Agent": "ck-security-scanner"}
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:
        return json.load(r)


def version_key(version):
    parts = [int(p) for p in re.findall(r"\d+", version.split("-")[0])]
    return tuple(parts + [0] * (4 - len(parts)))


def affects(version, constraints):
    """Whether a Composer constraint like ">=1.0,<1.2.3|>=2.0 <2.1" includes this version."""
    v = version_key(version)
    for alternative in re.split(r"\s*\|\|?\s*", constraints.strip()):
        alternative = re.sub(r"(>=|<=|==|!=|>|<|=)\s+", r"\1", alternative)  # ">= 1.0" -> ">=1.0"
        parts = [p for p in re.split(r"[,\s]+", alternative) if p]
        ok = bool(parts)
        for part in parts:
            m = CONSTRAINT.match(part)
            if not m:
                return True  # Can't read it: assume affected, so a person looks
            op, bound = m[1] or "=", version_key(m[2])
            ok = ok and {">=": v >= bound, "<=": v <= bound, ">": v > bound, "<": v < bound,
                         "=": v == bound, "==": v == bound, "!=": v != bound}[op]
        if ok:
            return True
    return False


def problems(github_token=None):
    try:
        release = _get(f"https://api.github.com/repos/{REPO}/releases/latest", github_token)
    except urllib.error.HTTPError as err:
        if err.code == 404:
            return ["CK HEALTH: no plugin release published yet, so sites can't install it"]
        return [f"CK HEALTH DEPENDENCIES NOT CHECKED: GitHub releases returned {err.code}"]
    tag = release["tag_name"]

    try:
        lock = _get(f"https://raw.githubusercontent.com/{REPO}/{urllib.parse.quote(tag)}/{LOCK_PATH}")
        packages = {p["name"]: p["version"] for p in lock.get("packages", []) + lock.get("packages-dev", [])}
        query = "&".join(f"packages[]={urllib.parse.quote(n)}" for n in packages)
        advisories = _get(f"https://packagist.org/api/security-advisories/?{query}")["advisories"] if packages else {}
        out = []
        for name, locked in sorted(packages.items()):
            meta = _get(f"https://repo.packagist.org/p2/{name}.json")["packages"][name]
            stable = [m["version"] for m in meta if STABLE.match(m["version"])]
            latest = max(stable, key=version_key) if stable else None
            if latest and version_key(locked) < version_key(latest):
                out.append(f"CK HEALTH DEPENDENCY OUT OF DATE: {name} is {locked} in release {tag}, latest is {latest}")
            for adv in advisories.get(name, []):
                if affects(locked, adv.get("affectedVersions", "")):
                    ref = adv.get("cve") or adv.get("link") or adv.get("advisoryId")
                    out.append(f"CK HEALTH DEPENDENCY VULNERABLE: {name} {locked} in release {tag}: {adv.get('title')} ({ref})")
        print(f"CK Health release {tag}: {len(packages)} dependencies checked")
        return out
    except (urllib.error.URLError, KeyError, ValueError) as err:
        return [f"CK HEALTH DEPENDENCIES NOT CHECKED (release {tag}): {err}"]
