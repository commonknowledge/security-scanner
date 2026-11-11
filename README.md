# security-scanner

Daily Render cron job that checks:

- every environment in the Common Knowledge workspace (`RENDER_OWNER_ID`) is **protected**, so
  non-Admin members can't read secrets or open shells. Other workspaces don't need protecting;
- no service sits outside a project, in every workspace (`LOOSE_SCOPE=all`) or only the
  Common Knowledge one (`LOOSE_SCOPE=owner`);
- PR previews follow company policy, in **every workspace the API key can see**;
- the scanner itself runs on up-to-date dependencies (`scanner_deps.py`): every package pinned in
  `requirements.txt` is the latest stable release with no known vulnerability, the Python running it
  is the latest release (`PYTHON_VERSION` in `render.yaml`), and the GitHub Actions in
  `.github/workflows` are on their latest major version. Dependabot opens PRs for all of these;
- with `WORDPRESS_CHECKS=on` (off by default, until every Linear project has its Live URL): the
  latest release of the CK Health WordPress plugin (`wp-plugin/`) ships no outdated or
  vulnerable dependencies (`plugin_deps.py`), and every website listed in Linear passes the site
  checks below (`linear_sites.py` builds the list, `sites.py` checks it).

## Daily digest

Everything the scanner finds goes into **one email a day** to tech@commonknowledge.coop
(`digest.py`), sent through SMTP2GO (`SMTP2GO_API_KEY`). Nothing is emailed on a day with no
issues. Without `SMTP2GO_API_KEY` the digest is only printed in the cron log.

Security issues never fail the run. **A failed run means the scanner itself broke** (a code error,
or the digest failing to send), and Render's failure notification is the alert for that.

## Site list (Linear)

Every Linear project in Design & Build, Wrap up, Active maintenance, Completed or Paused needs either:

- a project link named `Live URL` (and `Staging URL` if there is one; names are case-insensitive), or
- the `no-website` label.

Otherwise it's in the digest. A Design & Build project may not be live yet, so until it has a
`Live URL` it's only in the digest on days its issues changed in Linear: work is happening, so maybe
a staging site or the live site exists now. That carries on after a `Staging URL` is added, because
a site can launch before anyone moves the project out of Design & Build. Quiet projects don't nag.

Sites we no longer maintain keep their `Live URL` and also get the `not-maintained` label: they're
still scanned. Archived projects are included, and count as `not-maintained` without needing the
label.

## Site checks

Every site listed in Linear (`sites.py`). A site listed on several projects is checked once.

- **Up and on HTTPS**, with a valid certificate that doesn't expire within 14 days. A staging site
  that's down is skipped silently (staging is often switched off); a live one is reported. A site
  behind a login (401) can't be checked further, which is fine.
- **Nothing exposed** that should be private: a `.git` directory or `.env` file, and on WordPress a
  public `wp-content/debug.log` or a browsable `wp-content/uploads/`. WordPress's public user list
  (`/wp-json/wp/v2/users`) isn't reported: WordPress doesn't treat usernames as secret, the password
  audit and login limiting are what protect accounts, and CK Health closes the list anyway.
- **CK Health** (maintained WordPress sites only), through a request signed with
  `CK_HEALTH_SIGNING_KEY` (see `wp-plugin/README.md`): the plugin answers and is the latest release;
  WordPress, plugins and themes have no updates waiting; PHP is still supported; no account has an
  easily guessed password; login rate limiting is on and sees the scanner's real IP (compared with
  what most sites see); and WordPress is still checking for updates. A WordPress site whose plugin
  doesn't answer also gets an open XML-RPC endpoint reported, since nothing rate-limits it.
- **Bot protection**: a hosting firewall or Cloudflare challenge page instead of the site is
  reported, since nothing behind it could be checked. Allowlist the scanner on that site.

Sites not maintained by us (labelled `not-maintained`, or on an archived project) get only the
first two, in their own section of the digest.

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
