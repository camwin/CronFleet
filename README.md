# CronFleet

Centralized multi-node cron management, discovery/adoption, guardrails, AAA security, and execution telemetry.

## Security & AAA Architecture
- First-Run Security Setup Wizard: Locks control-plane APIs on initial boot until claimed with the one-time setup code printed in `docker compose logs cronfleet`.
- Extensible Authentication: Supports Local Admin (`scrypt` password hashing), Active Directory / LDAP (`ldapts` with security-group mapping), and OIDC Single Sign-On (PKCE + JWKS signature verification for Entra ID, Okta, Keycloak, or Google), plus a mandatory Break-Glass Local Admin for IdP outages.
- Role-Based Access Control (RBAC): Enforces Admin (root + non-root jobs, hosts, security settings), Operator (non-root jobs only), and Viewer (read-only).
- Append-Only Audit Trail: Records all logins, role denials, and job/host mutations to `data/audit.jsonl` and sends real-time webhook alerts on `root` job changes.

## Quick Start (Control Plane)
1. Copy `.env.example` to `.env` and set `PUBLIC_URL`, `PUID`, and `PGID`:
       cp .env.example .env
2. Prepare persistent storage matching `PUID:PGID`:
       mkdir -p data/ssh && sudo chown -R 1000:1000 data
3. Build and launch:
       docker compose up -d --build
4. Read the one-time setup code and complete the browser setup wizard:
       docker compose logs cronfleet

## Onboarding a Managed Linux Node
1. Sign in as an Admin and click '+ Add Server' to generate a unique host token.
2. Select the server in the top dropdown and run its Node Bootstrap Command as root on the target Linux host:
       curl -fsSL "http://<CONTROL_PLANE>:4000/onboard.sh?token=<HOST_TOKEN>" | sudo bash
3. Click 'Scan Host (Discover)' or 'Scan All Hosts (Discover)' to import existing crontabs into `/etc/cron.d/cronfleet`.

## Recovery / Resetting Authentication
If you are locked out of the UI, set `RESET_AUTH=true` in `.env` and run `docker compose up -d` to re-open the Setup Wizard without losing your hosts, jobs, or telemetry history.
