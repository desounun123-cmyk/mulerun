#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# renew-certs.sh — Automated Let's Encrypt certificate renewal
#                  for OIL Benchmarks
#
# Runs certbot to renew the TLS certificate, copies the fresh files
# into the server's certs/ directory, and signals the running Node
# process (SIGHUP) so it hot-reloads without downtime.
#
# Prerequisites:
#   1. certbot is installed         (apt install certbot)
#   2. Initial cert already issued  (see "First-time setup" below)
#   3. Node server handles SIGHUP   (see index.js TLS reload handler)
#
# First-time setup (run once manually):
#   sudo certbot certonly --standalone -d your-domain.com \
#     --agree-tos -m admin@your-domain.com --non-interactive
#
#   Or with webroot (if server is already running on port 80):
#   sudo certbot certonly --webroot -w /path/to/public \
#     -d your-domain.com --agree-tos -m admin@your-domain.com
#
# Install into crontab (runs twice daily as recommended by Let's Encrypt):
#   sudo crontab -e
#   # Twice daily at 2:30 AM and 2:30 PM (certbot skips if not near expiry):
#   30 2,14 * * * /absolute/path/to/server/scripts/renew-certs.sh >> /absolute/path/to/server/logs/cert-renewal.log 2>&1
#
# Environment variables (optional — sensible defaults provided):
#   CERTBOT_DOMAIN      — domain name on the certificate
#   CERTBOT_LIVE_DIR    — certbot's live directory (default: /etc/letsencrypt/live/$CERTBOT_DOMAIN)
#   CERT_DEST_DIR       — where the server reads certs from (default: ../certs relative to this script)
#   NODE_PID_FILE       — PID file for the Node process (default: auto-detect via pgrep)
#   CERTBOT_BIN         — path to certbot binary (default: auto-detect)
#   CERTBOT_METHOD      — "standalone" or "webroot" (default: standalone)
#   CERTBOT_WEBROOT     — webroot path if CERTBOT_METHOD=webroot
#   CERTBOT_EMAIL       — email for Let's Encrypt account
#   DRY_RUN             — set to "true" to test without actually renewing
# ─────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Resolve paths ─────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_PREFIX="[cert-renew $(date -u '+%Y-%m-%dT%H:%M:%SZ')]"

# Load .env if present (same pattern as cron-backup.sh)
if [ -f "$SERVER_DIR/.env" ]; then
  while IFS='=' read -r key value; do
    [ -z "$key" ] && continue
    if [ -z "${!key+x}" ]; then
      export "$key=$value"
    fi
  done < <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=[^<>]*$' "$SERVER_DIR/.env" | sed 's/#.*//')
fi

# ── Configuration ─────────────────────────────────────────────────
CERTBOT_DOMAIN="${CERTBOT_DOMAIN:-}"
CERTBOT_EMAIL="${CERTBOT_EMAIL:-}"
CERTBOT_METHOD="${CERTBOT_METHOD:-standalone}"
CERTBOT_WEBROOT="${CERTBOT_WEBROOT:-$SERVER_DIR/..}"
CERT_DEST_DIR="${CERT_DEST_DIR:-$SERVER_DIR/certs}"
DRY_RUN="${DRY_RUN:-false}"

# Validate required config
if [ -z "$CERTBOT_DOMAIN" ]; then
  echo "$LOG_PREFIX ERROR: CERTBOT_DOMAIN is not set. Add it to .env or export it." >&2
  echo "$LOG_PREFIX   Example: CERTBOT_DOMAIN=oil-benchmarks.com" >&2
  exit 1
fi

CERTBOT_LIVE_DIR="${CERTBOT_LIVE_DIR:-/etc/letsencrypt/live/$CERTBOT_DOMAIN}"

# Find certbot
CERTBOT_BIN="${CERTBOT_BIN:-$(command -v certbot 2>/dev/null || true)}"
if [ -z "$CERTBOT_BIN" ] || [ ! -x "$CERTBOT_BIN" ]; then
  echo "$LOG_PREFIX ERROR: certbot not found. Install with: sudo apt install certbot" >&2
  exit 1
fi

echo "$LOG_PREFIX Starting certificate renewal for $CERTBOT_DOMAIN"
echo "$LOG_PREFIX   Method:    $CERTBOT_METHOD"
echo "$LOG_PREFIX   Live dir:  $CERTBOT_LIVE_DIR"
echo "$LOG_PREFIX   Dest dir:  $CERT_DEST_DIR"

# ── Check current certificate expiry ─────────────────────────────
CERT_FILE="$CERT_DEST_DIR/fullchain.pem"
if [ -f "$CERT_FILE" ]; then
  EXPIRY=$(openssl x509 -enddate -noout -in "$CERT_FILE" 2>/dev/null | cut -d= -f2)
  EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || echo "0")
  NOW_EPOCH=$(date +%s)
  DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
  echo "$LOG_PREFIX   Current cert expires: $EXPIRY ($DAYS_LEFT days remaining)"

  # Certbot's own threshold is 30 days; log a warning if we're close
  if [ "$DAYS_LEFT" -gt 30 ]; then
    echo "$LOG_PREFIX   Certificate still valid for >30 days — certbot will likely skip renewal"
  elif [ "$DAYS_LEFT" -le 7 ]; then
    echo "$LOG_PREFIX   WARNING: Certificate expires in $DAYS_LEFT days — renewal is critical"
  fi
else
  echo "$LOG_PREFIX   No existing certificate found at $CERT_FILE — expecting fresh issuance"
fi

# ── Run certbot renew ────────────────────────────────────────────
CERTBOT_ARGS=("renew" "--cert-name" "$CERTBOT_DOMAIN" "--non-interactive" "--no-random-sleep-on-renew")

if [ "$DRY_RUN" = "true" ]; then
  CERTBOT_ARGS+=("--dry-run")
  echo "$LOG_PREFIX   DRY RUN mode — no actual changes will be made"
fi

# Certbot hooks: stop/start standalone server only if using standalone method
if [ "$CERTBOT_METHOD" = "standalone" ]; then
  # Standalone needs port 80 free; the Node HTTP redirect server may be using it.
  # Use pre/post hooks to temporarily free port 80 if needed.
  CERTBOT_ARGS+=(
    "--preferred-challenges" "http"
    "--pre-hook"  "kill -STOP \$(pgrep -f 'node.*index.js' | head -1) 2>/dev/null || true"
    "--post-hook" "kill -CONT \$(pgrep -f 'node.*index.js' | head -1) 2>/dev/null || true"
  )
elif [ "$CERTBOT_METHOD" = "webroot" ]; then
  CERTBOT_ARGS+=("--webroot" "-w" "$CERTBOT_WEBROOT")
fi

echo "$LOG_PREFIX   Running: certbot ${CERTBOT_ARGS[*]}"
RENEW_OUTPUT=$("$CERTBOT_BIN" "${CERTBOT_ARGS[@]}" 2>&1) || {
  echo "$LOG_PREFIX ERROR: certbot renewal failed:" >&2
  echo "$RENEW_OUTPUT" >&2
  exit 1
}

echo "$LOG_PREFIX   certbot output: $RENEW_OUTPUT"

# Check if certbot actually renewed (look for "no renewals" message)
if echo "$RENEW_OUTPUT" | grep -qi "no renewals were attempted\|cert not yet due for renewal"; then
  echo "$LOG_PREFIX Certificate not yet due for renewal — no action needed"
  exit 0
fi

if [ "$DRY_RUN" = "true" ]; then
  echo "$LOG_PREFIX DRY RUN complete — exiting without copying or reloading"
  exit 0
fi

# ── Copy renewed certificates to server's certs/ directory ────────
# Let's Encrypt stores renewed certs in /etc/letsencrypt/live/<domain>/
# We copy them so the Node server doesn't need root access to /etc/letsencrypt.
echo "$LOG_PREFIX   Copying renewed certificates to $CERT_DEST_DIR"

mkdir -p "$CERT_DEST_DIR"

if [ ! -f "$CERTBOT_LIVE_DIR/fullchain.pem" ] || [ ! -f "$CERTBOT_LIVE_DIR/privkey.pem" ]; then
  echo "$LOG_PREFIX ERROR: Expected cert files not found in $CERTBOT_LIVE_DIR" >&2
  ls -la "$CERTBOT_LIVE_DIR" 2>/dev/null >&2 || true
  exit 1
fi

# Atomic copy: write to temp file first, then move (prevents serving partial files)
cp "$CERTBOT_LIVE_DIR/fullchain.pem" "$CERT_DEST_DIR/fullchain.pem.tmp"
cp "$CERTBOT_LIVE_DIR/privkey.pem"   "$CERT_DEST_DIR/privkey.pem.tmp"

# Copy chain.pem if it exists (optional CA chain)
if [ -f "$CERTBOT_LIVE_DIR/chain.pem" ]; then
  cp "$CERTBOT_LIVE_DIR/chain.pem" "$CERT_DEST_DIR/chain.pem.tmp"
  mv "$CERT_DEST_DIR/chain.pem.tmp" "$CERT_DEST_DIR/chain.pem"
fi

mv "$CERT_DEST_DIR/fullchain.pem.tmp" "$CERT_DEST_DIR/fullchain.pem"
mv "$CERT_DEST_DIR/privkey.pem.tmp"   "$CERT_DEST_DIR/privkey.pem"

# Restrict permissions (key should only be readable by the server user)
chmod 644 "$CERT_DEST_DIR/fullchain.pem"
chmod 600 "$CERT_DEST_DIR/privkey.pem"
[ -f "$CERT_DEST_DIR/chain.pem" ] && chmod 644 "$CERT_DEST_DIR/chain.pem"

echo "$LOG_PREFIX   Certificates copied successfully"

# Verify the new certificate
NEW_EXPIRY=$(openssl x509 -enddate -noout -in "$CERT_DEST_DIR/fullchain.pem" 2>/dev/null | cut -d= -f2)
NEW_SUBJECT=$(openssl x509 -subject -noout -in "$CERT_DEST_DIR/fullchain.pem" 2>/dev/null | sed 's/subject=//')
echo "$LOG_PREFIX   New cert: $NEW_SUBJECT"
echo "$LOG_PREFIX   Expires:  $NEW_EXPIRY"

# ── Signal Node server to hot-reload TLS certificates ─────────────
# The Node server listens for SIGHUP and calls server.setSecureContext()
# to reload certs without dropping existing connections.
NODE_PID=""
if [ -n "${NODE_PID_FILE:-}" ] && [ -f "$NODE_PID_FILE" ]; then
  NODE_PID=$(cat "$NODE_PID_FILE" 2>/dev/null)
elif command -v pgrep >/dev/null 2>&1; then
  NODE_PID=$(pgrep -f "node.*index\.js" | head -1 || true)
fi

if [ -n "$NODE_PID" ] && kill -0 "$NODE_PID" 2>/dev/null; then
  echo "$LOG_PREFIX   Sending SIGHUP to Node process (PID $NODE_PID) for zero-downtime TLS reload"
  kill -HUP "$NODE_PID"
  echo "$LOG_PREFIX   SIGHUP sent — server will reload certificates"
else
  echo "$LOG_PREFIX   WARNING: Could not find running Node process — you may need to restart manually"
  echo "$LOG_PREFIX   If using systemd:  sudo systemctl restart oil-benchmarks"
  echo "$LOG_PREFIX   If using pm2:      pm2 restart oil-benchmarks"
fi

echo "$LOG_PREFIX Done. Certificate renewal complete for $CERTBOT_DOMAIN"
