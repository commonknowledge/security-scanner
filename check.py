#!/usr/bin/env python3
"""Fail (or fix) when any Render environment in the workspace is unprotected.

Env vars:
  RENDER_API_KEY        Render API key (required)
  RENDER_OWNER_ID       Workspace owner id to check (required)
  ALLOW_UNPROTECTED     Comma-separated environment ids that may stay unprotected
  MODE                  "alert" (default): exit 1 if any offenders; "protect": set them protected
  ALLOW_PREVIEWS        Comma-separated service ids whose PR previews may be automatic / long-lived
  PREVIEW_MAX_DAYS      Paid preview services older than this fail the run (default 7)

The PR preview check covers every workspace the API key can see, not just RENDER_OWNER_ID.
"""
import json, os, sys, urllib.request
from datetime import datetime, timedelta, timezone

API = "https://api.render.com/v1"
KEY = os.environ["RENDER_API_KEY"]
OWNER = os.environ["RENDER_OWNER_ID"]
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


projects = [p["project"] for p in paged("/projects") if p["project"]["owner"]["id"] == OWNER]
envs = [api("GET", f"/environments/{e}") for p in projects for e in p["environmentIds"]]
pname = {p["id"]: p["name"] for p in projects}

# Loose services (not in any environment) can't be protected at all
placed = {sid for e in envs for sid in e["serviceIds"] + e["databasesIds"] + e["redisIds"]}
services = [s["service"] for s in paged(f"/services?ownerId={OWNER}")]
loose = [s["name"] for s in services if s["id"] not in placed]

offenders = [e for e in envs if e["protectedStatus"] != "protected" and e["id"] not in ALLOW]
print(f"{len(projects)} projects, {len(envs)} environments, {len(offenders)} unprotected (excluding {len(ALLOW)} allowed), {len(loose)} loose services")

for e in offenders:
    print(f"UNPROTECTED: {pname[e['projectId']]} / {e['name']} ({e['id']})")
    if MODE == "protect":
        api("PATCH", f"/environments/{e['id']}", {"protectedStatus": "protected"})
        print(f"  -> protected")
for name in loose:
    print(f"LOOSE SERVICE (not in any project): {name}")

# PR previews: automatic previews on a paid plan, or paid previews left running, run up the bill unnoticed
cutoff = datetime.now(timezone.utc) - timedelta(days=PREVIEW_MAX_DAYS)
previews = []
for o in paged("/owners"):
    for s in paged(f"/services?ownerId={o['owner']['id']}"):
        s = s["service"]
        d = s.get("serviceDetails") or {}
        parent = (d.get("parentServer") or {}).get("id")
        if d.get("plan") == "free" or (parent or s["id"]) in ALLOW_PREVIEWS:
            continue
        if not parent and (d.get("previews") or {}).get("generation") == "automatic":
            previews.append(f"AUTOMATIC PREVIEWS: {o['owner']['name']} / {s['name']} ({s['id']})")
        elif parent and s["suspended"] == "not_suspended" and datetime.fromisoformat(s["createdAt"].replace("Z", "+00:00")) < cutoff:
            previews.append(f"STALE PREVIEW (> {PREVIEW_MAX_DAYS} days): {o['owner']['name']} / {s['name']} ({s['id']})")
print(f"{len(previews)} preview problems")
for line in previews:
    print(line)

if MODE == "protect":
    sys.exit(1 if loose or previews else 0)
sys.exit(1 if offenders or loose or previews else 0)
