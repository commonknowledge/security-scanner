#!/usr/bin/env python3
"""Fail (or fix) when any Render environment in the workspace is unprotected.

Env vars:
  RENDER_API_KEY        Render API key (required)
  RENDER_OWNER_ID       Workspace owner id to check (required)
  ALLOW_UNPROTECTED     Comma-separated environment ids that may stay unprotected
  MODE                  "alert" (default): exit 1 if any offenders; "protect": set them protected
"""
import json, os, sys, urllib.request

API = "https://api.render.com/v1"
KEY = os.environ["RENDER_API_KEY"]
OWNER = os.environ["RENDER_OWNER_ID"]
ALLOW = {e.strip() for e in os.environ.get("ALLOW_UNPROTECTED", "").split(",") if e.strip()}
MODE = os.environ.get("MODE", "alert")


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

if MODE == "protect":
    sys.exit(1 if loose else 0)
sys.exit(1 if offenders or loose else 0)
