# security-scanner

Daily Render cron job that checks every environment in the Common Knowledge workspace is
**protected** (so non-Admin members can't read secrets or open shells), and that no service
sits outside a project.

- `MODE=alert` (default): the run fails if any environment is unprotected or any service is
  loose. Render's failure notification is the alert.
- `MODE=protect`: unprotected environments are set to protected automatically; loose
  services still fail the run (they have to be placed by hand).
- `ALLOW_UNPROTECTED`: comma-separated environment ids that are intentionally open
  (e.g. a contractor's project).

Run locally: `RENDER_API_KEY=... RENDER_OWNER_ID=tea-... python3 check.py`
