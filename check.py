#!/usr/bin/env python3
"""Fail (or fix) when any Render environment is unprotected, any service is loose, or PR previews break policy.

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
"""
import json, os, sys, urllib.request
from datetime import datetime, timedelta, timezone

API = "https://api.render.com/v1"
KEY = os.environ["RENDER_API_KEY"]
OWNER = os.environ["RENDER_OWNER_ID"]
LOOSE_SCOPE = os.environ.get("LOOSE_SCOPE", "all")
ALLOW = {e.strip() for e in os.environ.get("ALLOW_UNPROTECTED", "").split(",") if e.strip()}
MODE = os.environ.get("MODE", "alert")
ALLOW_PREVIEWS = {s.strip() for s in os.environ.get("ALLOW_PREVIEWS", "").split(",") if s.strip()}
PREVIEW_MAX_DAYS = int(os.environ.get("PREVIEW_MAX_DAYS", "7"))


def api(method, path, body=None):
    req = urllib.request.Request(API + path, method=method,
                                 data=json.dumps(body).encode() if body else None,
                                 headers={"Authorization": f"Bearer {KEY}", "Accept": "application/json",
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.load(r)


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

# PR previews must be manual (company policy), and previews left running pile up unnoticed
cutoff = datetime.now(timezone.utc) - timedelta(days=PREVIEW_MAX_DAYS)
previews = []
for oid, ss in services.items():
    for s in ss:
        d = s.get("serviceDetails") or {}
        parent = (d.get("parentServer") or {}).get("id")
        if (parent or s["id"]) in ALLOW_PREVIEWS:
            continue
        if not parent and (d.get("previews") or {}).get("generation") == "automatic":
            previews.append(f"AUTOMATIC PREVIEWS: {owners[oid]} / {s['name']} ({s['id']})")
        elif parent and s["suspended"] == "not_suspended" and datetime.fromisoformat(s["createdAt"].replace("Z", "+00:00")) < cutoff:
            previews.append(f"STALE PREVIEW (> {PREVIEW_MAX_DAYS} days): {owners[oid]} / {s['name']} ({s['id']})")
print(f"{len(previews)} preview problems")
for line in previews:
    print(line)

if MODE == "protect":
    sys.exit(1 if loose or previews else 0)
sys.exit(1 if offenders or loose or previews else 0)
