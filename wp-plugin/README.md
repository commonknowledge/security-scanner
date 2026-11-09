# CK Health (WordPress must-use plugin)

Installed on every Common Knowledge WordPress site so the daily scanner can check it. No configuration.

## Install

Copy everything in `mu-plugins/` into the site's `wp-content/mu-plugins/`:

```
wp-content/mu-plugins/ck-health.php
wp-content/mu-plugins/ck-health/health.php
```

Must-use plugins can't be deactivated from the admin screen. The loader does nothing on PHP older than 7.2, so it can't crash an old site. The scanner then gets no answer and reports the site.

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

## Signing

Signed message: `"ck-health-v1\n" + <unix timestamp>`, sent as headers
`X-CK-Health-Timestamp` and `X-CK-Health-Signature` (base64). Timestamps more than 5 minutes
from the site's clock are rejected.

The public key is in `health.php`. The private key is in `.secrets/ck-health-signing-key`
(git-ignored) and goes in the scanner's Render environment. If it's lost or leaked, generate a
new pair, update the public key and redeploy the plugin everywhere.

## Tests

```
php wp-plugin/tests/ip_test.php
```
