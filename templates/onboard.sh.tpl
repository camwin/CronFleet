#!/usr/bin/env bash
set -euo pipefail

CONTROL_PLANE_URL="__CONTROL_PLANE_URL__"
HOST_TOKEN="__HOST_TOKEN__"
SSH_PUB_KEY='__SSH_PUB_KEY__'

[[ "$SSH_PUB_KEY" == ssh-* ]] || { echo "ERROR: Control plane public key missing" >&2; exit 1; }
id -u cronfleet &>/dev/null || useradd -m -s /bin/bash cronfleet
usermod -p '*' cronfleet
mkdir -p /home/cronfleet/.ssh && chmod 700 /home/cronfleet/.ssh
grep -qxF "$SSH_PUB_KEY" /home/cronfleet/.ssh/authorized_keys 2>/dev/null || echo "$SSH_PUB_KEY" >> /home/cronfleet/.ssh/authorized_keys
chmod 600 /home/cronfleet/.ssh/authorized_keys
chown -R cronfleet:cronfleet /home/cronfleet/.ssh
restorecon -Rv /home/cronfleet/.ssh 2>/dev/null || true

mkdir -p /etc/cronfleet
cat <<ENV > /etc/cronfleet/agent.env
CONTROL_PLANE_URL="$CONTROL_PLANE_URL"
HOST_TOKEN="$HOST_TOKEN"
HOSTNAME="$(hostname -f)"
ENV
chmod 644 /etc/cronfleet/agent.env

cat <<'SCAN' > /usr/local/bin/cronfleet-scan
#!/usr/bin/env bash
set -euo pipefail
echo "===FILE:/etc/crontab==="
cat /etc/crontab 2>/dev/null || true
for f in /etc/cron.d/*; do
  [[ -f "$f" && "$f" != "/etc/cron.d/cronfleet" ]] || continue
  echo "===FILE:$f==="
  cat "$f" 2>/dev/null || true
done
for dir in /var/spool/cron/crontabs /var/spool/cron; do
  [[ -d "$dir" ]] || continue
  for f in "$dir"/*; do
    [[ -f "$f" ]] || continue
    echo "===USER_SPOOL:$(basename "$f")==="
    cat "$f" 2>/dev/null || true
  done
done
SCAN
chmod 755 /usr/local/bin/cronfleet-scan

cat <<'ADOPT' > /usr/local/bin/cronfleet-adopt-comment
#!/usr/bin/env bash
set -euo pipefail
SOURCE_TYPE="$1"; SOURCE_TARGET="$2"; JOB_ID="$3"; B64_LINE="$4"
if [[ "$SOURCE_TYPE" == "user_spool" ]]; then
  [[ -f "/var/spool/cron/$SOURCE_TARGET" ]] && TARGET_FILE="/var/spool/cron/$SOURCE_TARGET" || TARGET_FILE="/var/spool/cron/crontabs/$SOURCE_TARGET"
elif [[ "$SOURCE_TYPE" == "system_file" && ( "$SOURCE_TARGET" == "/etc/crontab" || "$SOURCE_TARGET" == /etc/cron.d/* ) ]]; then
  TARGET_FILE="$SOURCE_TARGET"
else
  echo "Invalid source target" >&2; exit 1
fi
python3 - "$TARGET_FILE" "$JOB_ID" "$B64_LINE" <<'PY'
import base64, datetime, sys
path, job_id, b64_line = sys.argv[1], sys.argv[2], sys.argv[3]
target_line = base64.b64decode(b64_line).decode("utf-8")
today = datetime.date.today().isoformat()
with open(path, "r") as f: lines = f.read().splitlines()
replaced, out = False, []
for line in lines:
    if not replaced and line.strip() == target_line.strip():
        out.append(f"# [Adopted by CronFleet job_id={job_id} on {today}]")
        out.append(f"# {line}")
        replaced = True
    else:
        out.append(line)
if not replaced: sys.exit(1)
with open(path, "w") as f: f.write("\n".join(out) + "\n")
PY
ADOPT
chmod 755 /usr/local/bin/cronfleet-adopt-comment

cat <<'EXEC' > /usr/local/bin/cronfleet-exec
#!/usr/bin/env bash
set -uo pipefail
source /etc/cronfleet/agent.env
JOB_ID=""; TIMEOUT_SEC=3600; USE_FLOCK=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --job-id=*) JOB_ID="${1#*=}"; shift ;;
    --timeout=*) TIMEOUT_SEC="${1#*=}"; shift ;;
    --no-flock) USE_FLOCK=0; shift ;;
    --) shift; break ;;
    *) shift ;;
  esac
done
TMP_OUT=$(mktemp "/tmp/cronfleet-${JOB_ID}-XXXXXX.log")
START_MS=$(date +%s%3N)
if [[ "$USE_FLOCK" -eq 1 ]]; then
  flock -n "/tmp/cronfleet-job-${JOB_ID}.lock" bash -c 'timeout --kill-after=10s "$1" "${@:2}"' _ "$TIMEOUT_SEC" "$@" >"$TMP_OUT" 2>&1
  EXIT_CODE=$?
else
  timeout --kill-after=10s "$TIMEOUT_SEC" "$@" >"$TMP_OUT" 2>&1
  EXIT_CODE=$?
fi
END_MS=$(date +%s%3N)
DURATION_MS=$((END_MS - START_MS))
PAYLOAD=$(python3 -c 'import json, sys; output=open(sys.argv[5],"r",errors="replace").read()[-16384:]; print(json.dumps({"job_id":sys.argv[1],"hostname":sys.argv[2],"exit_code":int(sys.argv[3]),"duration_ms":int(sys.argv[4]),"output_tail":output}))' "$JOB_ID" "$HOSTNAME" "$EXIT_CODE" "$DURATION_MS" "$TMP_OUT")
rm -f "$TMP_OUT"
SPOOL_DIR="/tmp/cronfleet-spool-$(id -un)"; mkdir -p "$SPOOL_DIR"
if curl -fsS -m 10 -X POST "$CONTROL_PLANE_URL/api/v1/telemetry" -H "Content-Type: application/json" -H "Authorization: Bearer $HOST_TOKEN" -d "$PAYLOAD" >/dev/null 2>&1; then
  for spooled in "$SPOOL_DIR"/*.json; do
    [[ -f "$spooled" ]] || continue
    curl -fsS -m 5 -X POST "$CONTROL_PLANE_URL/api/v1/telemetry" -H "Content-Type: application/json" -H "Authorization: Bearer $HOST_TOKEN" --data-binary @"$spooled" >/dev/null 2>&1 && rm -f "$spooled"
  done
else
  echo "$PAYLOAD" > "$SPOOL_DIR/${END_MS}-${JOB_ID}.json"
fi
exit "$EXIT_CODE"
EXEC
chmod 755 /usr/local/bin/cronfleet-exec

cat <<'SUDO' > /etc/sudoers.d/cronfleet
Defaults:cronfleet !requiretty
cronfleet ALL=(root) NOPASSWD: /usr/bin/install -o root -g root -m 0644 /tmp/cronfleet.staging /etc/cron.d/cronfleet
cronfleet ALL=(root) NOPASSWD: /usr/local/bin/cronfleet-scan
cronfleet ALL=(root) NOPASSWD: /usr/local/bin/cronfleet-adopt-comment *
SUDO
chmod 440 /etc/sudoers.d/cronfleet
visudo -cf /etc/sudoers.d/cronfleet
echo "CronFleet node onboarded successfully."
