"""Build the list of CK websites from Linear, and flag projects that should have one listed but don't.

Every Linear project in an in-scope status (Design & Build, Wrap up, Active maintenance or
Completed: sites have been hacked within a day of going live, so every stage counts) needs either:

- a project link named `Live URL` (and `Staging URL` if it has one), case-insensitive; or
- the `no-website` label.

A site we no longer maintain keeps its `Live URL` and gets the `not-maintained` label too. It is
still scanned, but its problems belong in the weekly digest, not in immediate alerts, so each site
carries `maintained`.
"""
import json, urllib.error, urllib.request

API = "https://api.linear.app/graphql"
IN_SCOPE = {"design & build", "wrap up", "active maintenance", "completed"}
LINK_KINDS = {"live url": "live", "staging url": "staging"}
NO_WEBSITE = "no-website"
NOT_MAINTAINED = "not-maintained"

QUERY = """
query Projects($after: String) {
  projects(first: 100, after: $after) {
    pageInfo { hasNextPage endCursor }
    nodes {
      name
      url
      status { name }
      labels { nodes { name } }
      externalLinks { nodes { label url } }
    }
  }
}
"""


def _fetch(api_key):
    """Every non-archived project, as {name, url, status, labels, links: [{label, url}]}."""
    out, after = [], None
    while True:
        req = urllib.request.Request(API, data=json.dumps({"query": QUERY, "variables": {"after": after}}).encode(),
                                     headers={"Authorization": api_key, "Content-Type": "application/json",
                                              "User-Agent": "ck-security-scanner"})
        with urllib.request.urlopen(req, timeout=30) as r:
            body = json.load(r)
        if body.get("errors"):
            raise ValueError(body["errors"][0].get("message", body["errors"]))
        page = body["data"]["projects"]
        for p in page["nodes"]:
            out.append({"name": p["name"], "url": p["url"], "status": (p.get("status") or {}).get("name", ""),
                        "labels": [l["name"] for l in p["labels"]["nodes"]],
                        "links": [{"label": l["label"], "url": l["url"]} for l in p["externalLinks"]["nodes"]]})
        if not page["pageInfo"]["hasNextPage"]:
            return out
        after = page["pageInfo"]["endCursor"]


def classify(projects):
    """(sites, problems) from projects shaped like _fetch's output.

    sites: [{project, project_url, kind ("live" | "staging"), url, maintained}]
    """
    sites, problems = [], []
    for p in projects:
        if p["status"].strip().lower() not in IN_SCOPE:
            continue
        labels = {l.strip().lower() for l in p["labels"]}
        maintained = NOT_MAINTAINED not in labels
        found = [(LINK_KINDS[l["label"].strip().lower()], l["url"].strip()) for l in p["links"]
                 if (l.get("label") or "").strip().lower() in LINK_KINDS]
        where = f"{p['name']} ({p['url']})"
        if NO_WEBSITE in labels:
            if found:
                problems.append(f"LINEAR: project has a site link but is labelled {NO_WEBSITE}: {where}")
            if not maintained:
                problems.append(f"LINEAR: project is labelled both {NO_WEBSITE} and {NOT_MAINTAINED}: {where}")
            continue
        if not any(kind == "live" for kind, _ in found):
            problems.append(f"LINEAR: no Live URL link and no {NO_WEBSITE} label: {where}")
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
    except (urllib.error.URLError, KeyError, ValueError) as err:
        return [], [f"LINEAR NOT CHECKED: {err}"]
    sites, problems = classify(projects)
    live = [s for s in sites if s["kind"] == "live"]
    print(f"Linear: {len(projects)} projects, {len(live)} live sites "
          f"({sum(not s['maintained'] for s in live)} {NOT_MAINTAINED}), "
          f"{len(sites) - len(live)} staging sites")
    return sites, problems
