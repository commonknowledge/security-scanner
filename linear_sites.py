"""Build the list of CK websites from Linear, and flag projects that should have one listed but don't.

Every Linear project in an in-scope status (Design & Build, Wrap up, Active maintenance, Completed
or Paused: sites have been hacked within a day of going live, and a paused project's site is often
still up, so every stage counts) needs either:

- a project link named `Live URL` (and `Staging URL` if it has one), case-insensitive. In Design &
  Build, a `Staging URL` alone is enough, since the site may not be live yet; or
- the `no-website` label.

A Design & Build project with no links at all may simply not have a site yet, so it's only reported
on days its issues changed: work is happening, so maybe a staging site exists now. Quiet projects
don't nag.

A site we no longer maintain keeps its `Live URL` and gets the `not-maintained` label too. It is
still scanned, so each site carries `maintained`. Archived projects are included and count as
`not-maintained` without the label.
"""
import json, urllib.error, urllib.request
from datetime import datetime, timedelta, timezone

API = "https://api.linear.app/graphql"
IN_SCOPE = {"design & build", "wrap up", "active maintenance", "completed", "paused"}
STAGING_ENOUGH = {"design & build"}  # not live yet, so staging is all there is to scan
LINK_KINDS = {"live url": "live", "staging url": "staging"}
NO_WEBSITE = "no-website"
NOT_MAINTAINED = "not-maintained"
ACTIVITY_WINDOW = timedelta(hours=25)  # the scan runs daily; an hour's overlap so nothing falls between runs

PROJECTS = """
query Projects($after: String) {
  projects(first: 50, after: $after, includeArchived: true) {
    pageInfo { hasNextPage endCursor }
    nodes {
      name
      url
      archivedAt
      status { name }
      labels(first: 20) { nodes { name } }
      externalLinks(first: 50) { nodes { label url } }
    }
  }
}
"""

RECENT_ISSUES = """
query RecentIssues($after: String, $since: DateTimeOrDuration!) {
  issues(first: 100, after: $after, includeArchived: true, filter: { updatedAt: { gt: $since } }) {
    pageInfo { hasNextPage endCursor }
    nodes { project { url } }
  }
}
"""


def _query(api_key, query, variables):
    req = urllib.request.Request(API, data=json.dumps({"query": query, "variables": variables}).encode(),
                                 headers={"Authorization": api_key, "Content-Type": "application/json",
                                          "User-Agent": "ck-security-scanner"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = json.load(r)
    except urllib.error.HTTPError as err:  # Linear explains a 400 in the body, e.g. query too complex
        raise ValueError(f"Linear API {err.code}: {err.read().decode()[:300]}") from err
    if body.get("errors"):
        raise ValueError(body["errors"][0].get("message", body["errors"]))
    return body["data"]


def _paged(api_key, query, key, variables=None):
    after = None
    while True:
        page = _query(api_key, query, {**(variables or {}), "after": after})[key]
        yield from page["nodes"]
        if not page["pageInfo"]["hasNextPage"]:
            return
        after = page["pageInfo"]["endCursor"]


def _fetch(api_key):
    """Every project, archived too, as {name, url, status, archived, labels, links: [{label, url}]}."""
    return [{"name": p["name"], "url": p["url"], "status": (p.get("status") or {}).get("name", ""),
             "archived": bool(p.get("archivedAt")),
             "labels": [l["name"] for l in p["labels"]["nodes"]],
             "links": [{"label": l["label"], "url": l["url"]} for l in p["externalLinks"]["nodes"]]}
            for p in _paged(api_key, PROJECTS, "projects")]


def _active(api_key, now=None):
    """URLs of projects with an issue updated within ACTIVITY_WINDOW."""
    since = ((now or datetime.now(timezone.utc)) - ACTIVITY_WINDOW).isoformat()
    return {i["project"]["url"] for i in _paged(api_key, RECENT_ISSUES, "issues", {"since": since}) if i.get("project")}


def classify(projects, active=frozenset()):
    """(sites, problems) from projects shaped like _fetch's output.

    active: URLs of projects with recent issue activity (see _active).
    sites: [{project, project_url, kind ("live" | "staging"), url, maintained}]
    """
    sites, problems = [], []
    for p in projects:
        status = p["status"].strip().lower()
        if status not in IN_SCOPE:
            continue
        labels = {l.strip().lower() for l in p["labels"]}
        maintained = NOT_MAINTAINED not in labels and not p.get("archived")
        found = [(LINK_KINDS[l["label"].strip().lower()], l["url"].strip()) for l in p["links"]
                 if (l.get("label") or "").strip().lower() in LINK_KINDS]
        where = f"{p['name']} ({p['url']})"
        if NO_WEBSITE in labels:
            if found:
                problems.append(f"LINEAR: project has a site link but is labelled {NO_WEBSITE}: {where}")
            if NOT_MAINTAINED in labels:
                problems.append(f"LINEAR: project is labelled both {NO_WEBSITE} and {NOT_MAINTAINED}: {where}")
            continue
        if status in STAGING_ENOUGH and not found:
            if p["url"] in active:
                problems.append(f"LINEAR: issues changed in the last day, but there's no Staging URL or Live URL yet "
                                f"({p['status']}): {where}")
        elif not any(kind == "live" or status in STAGING_ENOUGH for kind, _ in found):
            problems.append(f"LINEAR: no Live URL link and no {NO_WEBSITE} label ({p['status']}): {where}")
        for kind, url in found:
            if not url.lower().startswith(("http://", "https://")):
                problems.append(f"LINEAR: {kind} URL isn't a web address ({url!r}): {where}")
                continue
            sites.append({"project": p["name"], "project_url": p["url"], "kind": kind, "url": url,
                          "maintained": maintained})
    return sites, problems


def load(api_key):
    """(sites, problems) from the live Linear workspace."""
    if not api_key:
        return [], ["LINEAR NOT CHECKED: LINEAR_API_KEY is not set"]
    try:
        projects = _fetch(api_key)
        active = _active(api_key)
    except (urllib.error.URLError, KeyError, ValueError) as err:
        return [], [f"LINEAR NOT CHECKED: {err}"]
    sites, problems = classify(projects, active)
    live = [s for s in sites if s["kind"] == "live"]
    print(f"Linear: {len(projects)} projects ({len(active)} with issue activity in the last day), "
          f"{len(live)} live sites ({sum(not s['maintained'] for s in live)} {NOT_MAINTAINED}), "
          f"{len(sites) - len(live)} staging sites")
    return sites, problems
