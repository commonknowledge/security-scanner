"""Build the list of CK websites from Linear, and flag projects that should have one listed but don't.

Every Linear project in an in-scope status (Design & Build, Wrap up, Active maintenance, Completed
or Paused: sites have been hacked within a day of going live, and a paused project's site is often
still up, so every stage counts) needs either:

- a project link named `Live URL` (and `Staging URL` if it has one), case-insensitive; or
- the `no-website` label.

A Design & Build project may not be live yet, so until it has a `Live URL` it's only reported on
days its issues changed: work is happening, so maybe a staging site or the live site exists now.
That keeps going after a `Staging URL` is added, because a site can launch before anyone moves the
project out of Design & Build. Quiet projects don't nag. Its `Staging URL` is scanned meanwhile.

A site we no longer maintain keeps its `Live URL` and gets the `no-maintained-website` label too.
It is still scanned, so each site carries `maintained`. Archived projects are included: archiving a
project doesn't mean its site stopped being ours, so only the label counts.
"""
import json, urllib.error, urllib.request
from datetime import datetime, timedelta, timezone

API = "https://api.linear.app/graphql"
IN_SCOPE = {"design & build", "wrap up", "active maintenance", "completed", "paused"}
NOT_LIVE_YET = {"design & build"}  # may not be live yet: only reported on days with issue activity
LINK_KINDS = {"live url": "live", "staging url": "staging"}
NO_WEBSITE = "no-website"
NOT_MAINTAINED = "no-maintained-website"
ACTIVITY_WINDOW = timedelta(hours=25)  # the scan runs daily; an hour's overlap so nothing falls between runs

PROJECTS = """
query Projects($after: String) {
  projects(first: 50, after: $after, includeArchived: true) {
    pageInfo { hasNextPage endCursor }
    nodes {
      name
      url
      archivedAt
      trashed
      status { name }
      labels(first: 20) { nodes { name } }
      externalLinks(first: 50, includeArchived: true) { nodes { label url archivedAt } }
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


def _when(timestamp):
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def current_links(project):
    """A project's links as they stand. Archiving a project archives its links with it, and Linear
    hides archived links, so on an archived project keep the links archived at the same moment.
    Any other archived link was deleted on its own."""
    archived = _when(project["archivedAt"]) if project.get("archivedAt") else None
    return [{"label": l["label"], "url": l["url"]} for l in project["externalLinks"]["nodes"]
            if not l.get("archivedAt") or (archived and abs((_when(l["archivedAt"]) - archived).total_seconds()) < 120)]


def _fetch(api_key):
    """Every project, archived too but not deleted (trashed), as {name, url, status, archived, labels, links: [{label, url}]}."""
    return [{"name": p["name"], "url": p["url"], "status": (p.get("status") or {}).get("name", ""),
             "archived": bool(p.get("archivedAt")),
             "labels": [l["name"] for l in p["labels"]["nodes"]],
             "links": current_links(p)}
            for p in _paged(api_key, PROJECTS, "projects") if not p.get("trashed")]


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
        maintained = NOT_MAINTAINED not in labels
        found = [(LINK_KINDS[l["label"].strip().lower()], l["url"].strip()) for l in p["links"]
                 if (l.get("label") or "").strip().lower() in LINK_KINDS]
        where = f"{p['name']} ({p['url']})"
        if NO_WEBSITE in labels:
            if found:
                problems.append(f"LINEAR: project has a site link but is labelled {NO_WEBSITE}: {where}")
            if NOT_MAINTAINED in labels:
                problems.append(f"LINEAR: project is labelled both {NO_WEBSITE} and {NOT_MAINTAINED}: {where}")
            continue
        has_live = any(kind == "live" for kind, _ in found)
        if status in NOT_LIVE_YET and not has_live:
            if p["url"] in active:
                missing = "Live URL" if any(kind == "staging" for kind, _ in found) else "Staging URL or Live URL"
                problems.append(f"LINEAR: issues changed in the last day, but there's no {missing} yet "
                                f"({p['status']}): {where}")
        elif not has_live:
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
