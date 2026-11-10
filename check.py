#!/usr/bin/env python3
"""Fail (or fix) when any Render environment is unprotected, any service is loose, or PR previews break policy.
With WORDPRESS_CHECKS=on, also fails when the CK Health WordPress plugin's latest release has outdated or
vulnerable dependencies (see plugin_deps.py), or when a Linear project that should list its website
doesn't (see linear_sites.py).

Environment protection is checked in RENDER_OWNER_ID's workspace only; loose services in the
workspaces set by LOOSE_SCOPE; PR previews in every workspace the API key can see.

Env vars:
  RENDER_API_KEY        Render API key (required)
  RENDER_OWNER_ID       Workspace whose environments must be protected (required)
  LOOSE_SCOPE           "all" (default): loose services fail in every workspace; "owner": only RENDER_OWNER_ID's
  ALLOW_UNPROTECTED     Comma-separated environment ids that may stay unprotected
  MODE                  "alert" (default): exit 1 if any offenders; "protect": set them protected
  ALLOW_PREVIEWS        Comma-separated service ids whose PR previews may be automatic / long-lived
  PREVIEW_MAX_DAYS      Preview services older than this fail the run (default 7)
  GITHUB_TOKEN          Read-only GitHub token, to read Blueprints' render.yaml (required)
  WORDPRESS_CHECKS      "on": also run the WordPress checks; anything else (default): skip them
  LINEAR_API_KEY        Read-only Linear API key, to list the sites (required when WORDPRESS_CHECKS is on)

Automatic PR previews on a service are always switched to manual, whatever MODE is.
"""
import json, os, re, sys, urllib.error, urllib.request
import linear_sites, plugin_deps
from datetime import datetime, timedelta, timezone

API = "https://api.render.com/v1"
KEY = os.environ["RENDER_API_KEY"]
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
OWNER = os.environ["RENDER_OWNER_ID"]
LOOSE_SCOPE = os.environ.get("LOOSE_SCOPE", "all")
ALLOW = {e.strip() for e in os.environ.get("ALLOW_UNPROTECTED", "").split(",") if e.strip()}
MODE = os.environ.get("MODE", "alert")
ALLOW_PREVIEWS = {s.strip() for s in os.environ.get("ALLOW_PREVIEWS", "").split(",") if s.strip()}
PREVIEW_MAX_DAYS = int(os.environ.get("PREVIEW_MAX_DAYS", "7"))
# Off until every Linear project has its Live URL, so the scanner can find the sites
WORDPRESS_CHECKS = os.environ.get("WORDPRESS_CHECKS", "off") == "on"
LINEAR_API_KEY = os.environ.get("LINEAR_API_KEY", "")


def api(method, path, body=None):
    req = urllib.request.Request(API + path, method=method,
                                 data=json.dumps(body).encode() if body else None,
                                 headers={"Authorization": f"Bearer {KEY}", "Accept": "application/json",
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def github(path):
    req = urllib.request.Request("https://api.github.com" + path,
                                 headers={"Authorization": f"Bearer {GITHUB_TOKEN}",
                                          "Accept": "application/vnd.github.raw+json"})
    with urllib.request.urlopen(req) as r:
        return r.read().decode()


def paged(path):
    cursor, out = None, []
    while True:
        page = api("GET", path + ("&" if "?" in path else "?") + f"limit=100" + (f"&cursor={cursor}" if cursor else ""))
        if not page:
            return out
        out += page
        cursor = page[-1]["cursor"]


owners = {o["owner"]["id"]: o["owner"]["name"] for o in paged("/owners")}
services = {oid: [s["service"] for s in paged(f"/services?ownerId={oid}")] for oid in owners}
projects = [p["project"] for p in paged("/projects") if p["project"]["owner"]["id"] in owners]
envs = [api("GET", f"/environments/{e}") for p in projects for e in p["environmentIds"]]
pname = {p["id"]: f"{owners[p['owner']['id']]} / {p['name']}" for p in projects}

# Loose services (not in any environment) can't be protected at all. Preview services are
# created by Render outside any environment, so they're covered by the preview checks instead.
placed = {sid for e in envs for sid in e["serviceIds"] + e["databasesIds"] + e["redisIds"]}
loose = [f"{owners[oid]} / {s['name']}" for oid, ss in services.items() for s in ss
         if (LOOSE_SCOPE == "all" or oid == OWNER)
         and s["id"] not in placed and not (s.get("serviceDetails") or {}).get("parentServer")]

# Environments only need to be private in the owner's workspace
pown = {p["id"]: p["owner"]["id"] for p in projects}
offenders = [e for e in envs if pown[e["projectId"]] == OWNER
             and e["protectedStatus"] != "protected" and e["id"] not in ALLOW]
print(f"{len(owners)} workspaces, {len(projects)} projects, {len(envs)} environments, "
      f"{len(offenders)} unprotected in {owners[OWNER]} (excluding {len(ALLOW)} allowed), "
      f"{len(loose)} loose services ({'all workspaces' if LOOSE_SCOPE == 'all' else owners[OWNER]})")

for e in offenders:
    print(f"UNPROTECTED: {pname[e['projectId']]} / {e['name']} ({e['id']})")
    if MODE == "protect":
        api("PATCH", f"/environments/{e['id']}", {"protectedStatus": "protected"})
        print(f"  -> protected")
for name in loose:
    print(f"LOOSE SERVICE (not in any project): {name}")

# PR previews must be manual (company policy), and previews left running pile up unnoticed.
# Automatic previews are switched to manual on the spot, but still fail the run so someone hears about it.
cutoff = datetime.now(timezone.utc) - timedelta(days=PREVIEW_MAX_DAYS)
previews = []
for oid, ss in services.items():
    for s in ss:
        d = s.get("serviceDetails") or {}
        parent = (d.get("parentServer") or {}).get("id")
        if (parent or s["id"]) in ALLOW_PREVIEWS:
            continue
        if not parent and (d.get("previews") or {}).get("generation") == "automatic":
            api("PATCH", f"/services/{s['id']}", {"serviceDetails": {"previews": {"generation": "manual"}}})
            previews.append(f"AUTOMATIC PREVIEWS: {owners[oid]} / {s['name']} ({s['id']}) -> set to manual")
        elif parent and s["suspended"] == "not_suspended" and datetime.fromisoformat(s["createdAt"].replace("Z", "+00:00")) < cutoff:
            previews.append(f"STALE PREVIEW (> {PREVIEW_MAX_DAYS} days): {owners[oid]} / {s['name']} ({s['id']})")

# Blueprints can switch previews back on at their next sync, and Preview Environments
# (top-level previewsEnabled / previews) never show up as a service setting, so read every
# Blueprint's render.yaml too
AUTOMATIC_YAML = [re.compile(p, re.M) for p in (
    r"^previewsEnabled:\s*[\"']?(true|yes)\b",               # Preview Environments (legacy key)
    r"^[ \t]*generation:\s*[\"']?automatic\b",                # previews.generation, top-level or per service
    r"^[ \t]*pullRequestPreviewsEnabled:\s*[\"']?(true|yes)\b",  # legacy per-service key
)]
for oid in owners:
    for b in paged(f"/blueprints?ownerId={oid}"):
        b = b["blueprint"]
        label = f"{owners[oid]} / blueprint {b['name']} ({b['repo']}@{b['branch']}:{b['path']})"
        m = re.match(r"https://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$", b["repo"])
        if not m:
            previews.append(f"BLUEPRINT NOT CHECKED (not on GitHub): {label}")
            continue
        try:
            yaml = github(f"/repos/{m[1]}/contents/{b['path']}?ref={b['branch']}")
        except urllib.error.HTTPError as err:
            # A Blueprint whose branch is gone can't sync, so it can't turn previews on
            # (the branches API follows renames, so go by the contents API's message).
            # Only worth a note if auto-sync is on; with it off, the dead branch is deliberate.
            if err.code == 404 and "No commit found for the ref" in err.read().decode():
                if b.get("autoSync"):
                    print(f"note: blueprint can't sync, branch is gone: {label}")
                continue
            previews.append(f"BLUEPRINT NOT CHECKED (GitHub {err.code}): {label}")
            continue
        if any(p.search(yaml) for p in AUTOMATIC_YAML):
            previews.append(f"AUTOMATIC PREVIEWS IN BLUEPRINT: {label}")
print(f"{len(previews)} preview problems")
for line in previews:
    print(line)

# A security hole in the plugin we install on every WordPress site would be the worst kind
plugin = plugin_deps.problems(GITHUB_TOKEN) if WORDPRESS_CHECKS else []
# Sites come from Linear, so a project missing its Live URL is a site nobody scans.
# `sites` is for the per-site checks to come; `not-maintained` ones only go in the weekly digest.
sites, linear = linear_sites.load(LINEAR_API_KEY) if WORDPRESS_CHECKS else ([], [])
if WORDPRESS_CHECKS:
    print(f"{len(plugin)} CK Health plugin dependency problems")
    for line in plugin:
        print(line)
    print(f"{len(linear)} Linear site list problems")
    for line in linear:
        print(line)
else:
    print("WordPress checks skipped (WORDPRESS_CHECKS is not on)")

if MODE == "protect":
    sys.exit(1 if loose or previews or plugin or linear else 0)
sys.exit(1 if offenders or loose or previews or plugin or linear else 0)
