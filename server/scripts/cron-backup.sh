#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# cron-backup.sh — Automated SQLite database backup for OIL Benchmarks
#
# Designed to be called by cron independently of the Node.js server.
# Uses better-sqlite3's backup API via the existing backup.js module
# for a safe, online backup that doesn't block the running app.
#
# Install into crontab:
#   crontab -e
#   # Every 6 hours:
#   0 */6 * * * /absolute/path/to/server/cron-backup.sh >> /absolute/path/to/server/backups/cron.log 2>&1
#   # Daily at 3:00 AM:
#   0 3 * * * /absolute/path/to/server/cron-backup.sh >> /absolute/path/to/server/backups/cron.log 2>&1
#
# Environment variables (optional — defaults match .env / backup.js):
#   BACKUP_DIR          — where to store backups   (default: ./backups)
#   BACKUP_RETAIN_COUNT — how many to keep          (default: 10)
#   DB_PATH             — path to data.db           (default: ./data.db)
#   NODE_PATH            — path to node binary      (auto-detected)
# ─────────────────────────────────────────────────────────────────

set -euo pipefail

# Resolve script directory so it works from any cwd
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load .env if present (so cron inherits the same config as the server)
# Uses grep to extract only simple KEY=VALUE lines (skips comments, empty lines,
# and lines with shell-unsafe characters like < > that break source).
if [ -f "$SCRIPT_DIR/.env" ]; then
  while IFS='=' read -r key value; do
    # Skip empty keys or values containing shell metacharacters
    [ -z "$key" ] && continue
    # Only export if not already set in environment (don't override explicit vars)
    if [ -z "${!key+x}" ]; then
      export "$key=$value"
    fi
  done < <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=[^<>]*$' "$SCRIPT_DIR/.env" | sed 's/#.*//')
fi

# Defaults
BACKUP_DIR="${BACKUP_DIR:-$SCRIPT_DIR/backups}"
BACKUP_RETAIN_COUNT="${BACKUP_RETAIN_COUNT:-10}"
DB_PATH="${DB_PATH:-$SCRIPT_DIR/data.db}"
LOG_PREFIX="[cron-backup $(date -u '+%Y-%m-%dT%H:%M:%SZ')]"

# Find node binary
NODE_BIN="${NODE_PATH:-$(command -v node 2>/dev/null || true)}"
if [ -z "$NODE_BIN" ] || [ ! -x "$NODE_BIN" ]; then
  echo "$LOG_PREFIX ERROR: node binary not found. Set NODE_PATH or ensure node is in PATH." >&2
  exit 1
fi

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

# Verify the database file exists
if [ ! -f "$DB_PATH" ]; then
  echo "$LOG_PREFIX ERROR: Database not found at $DB_PATH" >&2
  exit 1
fi

# Run the backup via backup.js (reuses the same safe backup logic)
echo "$LOG_PREFIX Starting backup of $DB_PATH ..."

RESULT=$("$NODE_BIN" "$SCRIPT_DIR/backup.js" --prune 2>&1) || {
  echo "$LOG_PREFIX ERROR: Backup failed:" >&2
  echo "$RESULT" >&2
  exit 1
}

echo "$LOG_PREFIX $RESULT"

# Log current backup inventory
BACKUP_COUNT=$(find "$BACKUP_DIR" -maxdepth 1 -name 'data-backup-*.db' -type f | wc -l)
BACKUP_SIZE=$(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1)
echo "$LOG_PREFIX Done. $BACKUP_COUNT backups on disk ($BACKUP_SIZE total)."
