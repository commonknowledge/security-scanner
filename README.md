# render-env-guard

Daily Render cron job that checks every environment in the Common Knowledge workspace is
**protected** (so non-Admin members can't read secrets or open shells), and that no service
sits outside a project.

It also checks PR previews in **every workspace the API key can see**: the run fails if a
service on a paid plan has automatic previews, or a paid preview service has been running for
more than `PREVIEW_MAX_DAYS` (default 7). This catches previews switched on in the dashboard,
which bypasses `render.yaml` (Resist Rent Rises ran 19 Standard previews for months).

- `MODE=alert` (default): the run fails if any environment is unprotected or any service is
  loose. Render's failure notification is the alert.
- `MODE=protect`: unprotected environments are set to protected automatically; loose
  services still fail the run (they have to be placed by hand).
- `ALLOW_UNPROTECTED`: comma-separated environment ids that are intentionally open
  (e.g. a contractor's project).
- `ALLOW_PREVIEWS`: comma-separated service ids (the main service) whose previews may be
  automatic or long-lived.

Run locally: `RENDER_API_KEY=... RENDER_OWNER_ID=tea-... python3 check.py`
