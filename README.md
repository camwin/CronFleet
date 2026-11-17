# CronFleet

Centralized multi-node cron management, discovery/adoption, guardrails, and execution telemetry.

## Architecture
- Control Plane (server.js, public/): Express + Tailwind UI providing a Fleet View across all managed nodes, SSH crontab discovery/adoption, cron linting, webhook alerts, and missed-run watchdog monitoring.
- Managed Nodes (templates/onboard.sh.tpl): Execute scheduled jobs via /usr/local/bin/cronfleet-exec, capturing exit codes, duration, and stdout/stderr tails back to /api/v1/telemetry (with offline spooling support).

## Quick Start (Control Plane)
1. Prepare the persistent data directory matching the container UID (1002:1002):
   mkdir -p data/ssh && sudo chown -R 1002:1002 data
2. Configure PUBLIC_URL in docker-compose.yml and ensure ./data:/app/data:Z is mapped.
3. Build and start the container:
   docker compose up -d --build

## Onboarding a Managed Linux Node
1. Click "+ Add Server" in the CronFleet UI to generate a host token.
2. Select the server in the top dropdown and run its Node Bootstrap Command as root on the target host:
   curl -fsSL "http://<CONTROL_PLANE>:4000/onboard.sh?token=<HOST_TOKEN>" | sudo bash
3. Click "Scan Host (Discover)" to import existing crontabs into /etc/cron.d/cronfleet.

## Security Notes
- Never commit data/—it stores the generated Ed25519 SSH private key (data/ssh/cronfleet_ed25519), host tokens, and webhook URLs (data/db.json).
- Restrict port 4000 to your management VLAN/VPN or place it behind an authenticated reverse proxy.
