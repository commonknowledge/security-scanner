# security-scanner

Daily Render cron job that checks:

- every environment in the Common Knowledge workspace (`RENDER_OWNER_ID`) is **protected**, so
  non-Admin members can't read secrets or open shells. Other workspaces don't need protecting;
- no service sits outside a project, in every workspace (`LOOSE_SCOPE=all`) or only the
  Common Knowledge one (`LOOSE_SCOPE=owner`);
- PR previews follow company policy, in **every workspace the API key can see**;
- with `WORDPRESS_CHECKS=on` (off by default, until every Linear project has its Live URL): the
  latest release of the CK Health WordPress plugin (`wp-plugin/`) ships no outdated or
  vulnerable dependencies (`plugin_deps.py`). See `wp-plugin/README.md`. It also builds the list
  of sites from Linear (`linear_sites.py`, needs `LINEAR_API_KEY`), described below.

## Daily digest

Everything the scanner finds goes into **one email a day** to tech@commonknowledge.coop
(`digest.py`), sent through SMTP2GO (`SMTP2GO_API_KEY`). Nothing is emailed on a day with no
issues. Without `SMTP2GO_API_KEY` the digest is only printed in the cron log.

Security issues never fail the run. **A failed run means the scanner itself broke** (a code error,
or the digest failing to send), and Render's failure notification is the alert for that.

## Site list (Linear)

Every Linear project in Design & Build, Wrap up, Active maintenance, Completed or Paused needs either:

- a project link named `Live URL` (and `Staging URL` if there is one; names are case-insensitive).
  In Design & Build, a `Staging URL` alone is enough, since the site may not be live yet; or
- the `no-website` label.

Otherwise it's in the digest. A Design & Build project with no links at all may not have a site
yet, so it's only in the digest on days its issues changed in Linear: work is happening, so maybe a
staging site exists now. Quiet projects don't nag.

Sites we no longer maintain keep their `Live URL` and also get the `not-maintained` label: they're
still scanned. Archived projects are included, and count as `not-maintained` without needing the
label.

## PR previews

PR previews must be **manual**. The digest lists:

- any service, on any plan, with automatic previews. These are **switched to manual
  automatically** (whatever `MODE` is), and still reported so someone hears about it.
  This catches previews switched on in the dashboard, which bypasses `render.yaml` (Resist Rent
  Rises ran 19 Standard previews for months);
- any Blueprint whose `render.yaml` turns previews on: top-level `previewsEnabled: true` (Preview
  Environments, which never show up as a service setting), or `generation: automatic` /
  `pullRequestPreviewsEnabled: true`, which would switch them back on at the next sync. This
  reads the file from GitHub, so it needs `GITHUB_TOKEN`; a Blueprint it can't read is reported too;
- any preview service running for more than `PREVIEW_MAX_DAYS` (default 7).

## Settings

- `MODE=alert` (default): unprotected environments and loose services are reported.
- `MODE=protect`: unprotected environments are also set to protected automatically; loose
  services still have to be placed by hand.
- `ALLOW_UNPROTECTED`: comma-separated environment ids that are intentionally open
  (e.g. a contractor's project).
- `ALLOW_PREVIEWS`: comma-separated service ids (the main service) whose previews may be
  automatic or long-lived.
- `DIGEST_TO` / `DIGEST_FROM`: override the digest's recipient and sender.

Run locally: `RENDER_API_KEY=... RENDER_OWNER_ID=tea-... GITHUB_TOKEN=$(gh auth token) python3 check.py`
(without `SMTP2GO_API_KEY` it only prints the digest).
