# render-env-guard

Daily Render cron job that checks, in **every workspace the API key can see**, that every
environment is **protected** (so non-Admin members can't read secrets or open shells), that no
service sits outside a project, and that PR previews follow company policy.

PR previews must be **manual**: the run fails if any service, on any plan, has automatic
previews, or a preview service has been running for more than `PREVIEW_MAX_DAYS` (default 7).
This catches previews switched on in the dashboard, which bypasses `render.yaml` (Resist Rent
Rises ran 19 Standard previews for months).

- `MODE=alert` (default): the run fails if any environment is unprotected or any service is
  loose. Render's failure notification is the alert.
- `MODE=protect`: unprotected environments are set to protected automatically; loose
  services still fail the run (they have to be placed by hand).
- `ALLOW_UNPROTECTED`: comma-separated environment ids that are intentionally open
  (e.g. a contractor's project).
- `ALLOW_PREVIEWS`: comma-separated service ids (the main service) whose previews may be
  automatic or long-lived.

Run locally: `RENDER_API_KEY=... python3 check.py`
