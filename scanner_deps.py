"""Check that the scanner itself runs on up-to-date, unvulnerable dependencies.

The plugin's side is plugin_deps.py. This covers the rest of the scanner, as deployed from this
checkout:

- every package pinned in requirements.txt must be the latest stable release on PyPI and have no
  known vulnerability (PyPI publishes OSV advisories with each release);
- the Python running the scan must be the latest stable Python release;
- every GitHub Action used in .github/workflows must be on the action's latest major version.
"""
import json, os, platform, re, urllib.error, urllib.parse, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PIN = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*==\s*([^\s;#]+)")
USES = re.compile(r"^\s*-?\s*uses:\s*([\w.-]+/[\w.-]+)(?:/[^@\s]*)?@([^\s#]+)", re.M)


def _get(url, token=None):
    headers = {"Accept": "application/json", "User-Agent": "ck-security-scanner"}
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:
        return json.load(r)


def version_key(version):
    parts = [int(p) for p in re.findall(r"\d+", version.split("-")[0])]
    return tuple(parts + [0] * (4 - len(parts)))


def pinned(path=os.path.join(HERE, "requirements.txt")):
    """{package: version} for every `name==version` line."""
    out = {}
    for line in open(path):
        m = PIN.match(line)
        if m:
            out[m[1]] = m[2]
    return out


def actions(directory=os.path.join(HERE, ".github", "workflows")):
    """{owner/repo: {refs}} for every `uses:` in the workflows."""
    out = {}
    for name in sorted(os.listdir(directory)) if os.path.isdir(directory) else []:
        if name.endswith((".yml", ".yaml")):
            for repo, ref in USES.findall(open(os.path.join(directory, name)).read()):
                out.setdefault(repo, set()).add(ref)
    return out


def package_problems(packages, get=_get):
    out = []
    for name, version in sorted(packages.items()):
        latest = get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")["info"]["version"]
        if version_key(version) < version_key(latest):
            out.append(f"SCANNER DEPENDENCY OUT OF DATE: {name} is {version} in requirements.txt, latest is {latest}")
        release = get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json")
        for v in release.get("vulnerabilities") or []:
            if not v.get("withdrawn"):
                ids = ", ".join([v.get("id", "?")] + (v.get("aliases") or []))
                fixed = ", ".join(v.get("fixed_in") or []) or "no fix listed"
                out.append(f"SCANNER DEPENDENCY VULNERABLE: {name} {version}: {ids} (fixed in {fixed})")
    return out


def python_problems(running=None, get=_get):
    running = running or platform.python_version()
    cycles = get("https://endoflife.date/api/python.json")
    latest = max((c["latest"] for c in cycles), key=version_key)
    if version_key(running) < version_key(latest):
        return [f"SCANNER PYTHON OUT OF DATE: the scan runs on Python {running}, latest is {latest} "
                f"(set PYTHON_VERSION in render.yaml)"]
    return []


def action_problems(used, token=None, get=_get):
    out = []
    for repo, refs in sorted(used.items()):
        tag = get(f"https://api.github.com/repos/{repo}/releases/latest", token)["tag_name"]
        latest_major = version_key(tag)[0]
        for ref in sorted(refs):
            if re.fullmatch(r"[0-9a-f]{40}", ref):
                continue  # pinned to a commit: Dependabot keeps those current
            if version_key(ref)[0] < latest_major:
                out.append(f"SCANNER GITHUB ACTION OUT OF DATE: {repo}@{ref} in .github/workflows, latest is {tag}")
    return out


def problems(github_token=None):
    out = []
    for label, check in (("Python packages", lambda: package_problems(pinned())),
                         ("Python version", python_problems),
                         ("GitHub Actions", lambda: action_problems(actions(), github_token))):
        try:
            out += check()
        except (urllib.error.URLError, KeyError, ValueError, OSError) as err:
            out.append(f"SCANNER DEPENDENCIES NOT CHECKED ({label}): {err}")
    print(f"Scanner: Python {platform.python_version()}, {len(pinned())} pinned packages, "
          f"{sum(len(r) for r in actions().values())} GitHub Actions checked")
    return out
