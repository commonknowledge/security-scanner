# CK Health (WordPress plugin)

Installed on every Common Knowledge WordPress site so the daily scanner can check it. No configuration.

## Install

1. Download `ck-health.zip` from the [latest release](https://github.com/commonknowledge/security-scanner/releases/latest).
2. In the site's admin, go to Plugins → Add New → Upload Plugin, upload the zip and activate it.
3. Optionally, turn on auto-updates for it on the Plugins screen.

From then on, new releases show up as normal plugin updates. They come from this repo's GitHub releases
(via [Plugin Update Checker](https://github.com/YahnisElsts/plugin-update-checker)), never from WordPress.org.
The `Update URI` header stops WordPress.org from offering an unrelated plugin with the same slug.

If a client admin deactivates the plugin, the site stops answering the scanner and gets reported.

## What it does

- **Status endpoint** `GET /?rest_route=/ck-health/v1/status` (or `/wp-json/ck-health/v1/status`).
  Only requests signed with the scanner's Ed25519 private key get an answer. Anyone else gets
  the same 404 as a site without the plugin. The response gives the WordPress and PHP versions,
  plugin and theme versions with available updates, the password audit result and the login
  limit status.
- **Password audit.** Every account that can edit content (contributors and above) is tested
  against easily guessed passwords: variations of its username, name, email and the site's name
  and domain, plus a list of common passwords. The test runs against the stored hash inside the
  site; no logins are attempted. It runs in short batches (hourly via WP-Cron, and 5 seconds per
  status request) and starts again when a password changes. Only usernames are reported, never
  passwords.
- **Login rate limiting.** After 10 failed logins from one visitor IP within 15 minutes, that IP
  is refused until the 15 minutes are up. This covers wp-login.php, XML-RPC and anything else
  that goes through `wp_authenticate`. The visitor IP is worked out without configuration (see
  `resolve_visitor_ip()`). Forwarding headers are only trusted when the connection comes from
  Cloudflare or a private-network load balancer. If the visitor can't be identified safely, rate
  limiting is skipped rather than risk locking everyone out. The status response shows what was
  detected, so the scanner can check it against its own IP.

The checks need PHP 7.2 and updates need PHP 7.4. The main file uses only old PHP syntax, so it
can't crash a site on an older PHP version; it just stays off, and the scanner reports the site.

## Releasing

1. Bump `Version:` in `ck-health/ck-health.php`, merge to `main`.
2. Tag `main` as `v<version>` and push the tag (`git tag v0.2.1 && git push origin v0.2.1`).
3. The `Release CK Health plugin` workflow checks the version matches, runs the tests, installs the
   locked dependencies, refuses to release if `composer audit` finds a vulnerability, then publishes
   `ck-health.zip` as a GitHub release.

## Dependencies

The only dependency is Plugin Update Checker, locked in `ck-health/composer.lock`.

- Dependabot opens a PR when it has an update.
- The daily scanner (`plugin_deps.py`) fails if the **latest release** ships any dependency that
  isn't on its latest stable version or has a known security advisory. Merging Dependabot's PR
  isn't enough: the failure clears once a new release is tagged.

## Signing

Signed message: `"ck-health-v1\n" + <unix timestamp>`, sent as headers
`X-CK-Health-Timestamp` and `X-CK-Health-Signature` (base64). Timestamps more than 5 minutes
from the site's clock are rejected.

The public key is in `health.php`. The private key is in `.secrets/ck-health-signing-key`
(git-ignored) and goes in the scanner's Render environment. If it's lost or leaked, generate a
new pair, update the public key and release a new version.

## Tests

```
php wp-plugin/tests/ip_test.php
```
