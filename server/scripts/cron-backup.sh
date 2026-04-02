#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# cron-backup.sh — Automated SQLite database backup for OIL Benchmarks
#
# Designed to be called by cron independently of the Node.js server.
# Uses better-sqlite3's backup API via the existing backup.js module
# for a safe, online backup that doesn't block the running app.
#
# After each backup, a restore-verification test is run against the
# newest backup file to prove it is actually restorable. The test
# opens the backup as a SQLite database (read-only), runs PRAGMA
# integrity_check, validates the schema, reads every core table, and
# checks foreign-key consistency — all without touching the live DB.
# If the verification fails the script exits non-zero so cron alerts
# can fire.
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
#   SKIP_VERIFY         — set to "true" to skip the restore-verification step
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
SKIP_VERIFY="${SKIP_VERIFY:-false}"
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

# ── Step 1: Create the backup ────────────────────────────────────
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

# ── Step 2: Restore-verification test ────────────────────────────
# Proves the newest backup is actually restorable by running a
# multi-layer integrity check (read-only, never touches the live DB).
#
# Checks performed by backup.js --verify:
#   1. File exists and is >= 512 bytes
#   2. Opens successfully as a SQLite database
#   3. PRAGMA integrity_check passes (page-level verification)
#   4. All expected core tables are present in the schema
#   5. SELECT COUNT(*) succeeds on every expected table
#   6. PRAGMA foreign_key_check passes (referential integrity)

if [ "$SKIP_VERIFY" = "true" ]; then
  echo "$LOG_PREFIX Restore-verification skipped (SKIP_VERIFY=true)."
  exit 0
fi

# Find the newest backup file
LATEST_BACKUP=$(find "$BACKUP_DIR" -maxdepth 1 -name 'data-backup-*.db' -type f \
  -printf '%T@ %f\n' 2>/dev/null \
  | sort -rn | head -1 | cut -d' ' -f2-)

if [ -z "$LATEST_BACKUP" ]; then
  echo "$LOG_PREFIX WARNING: No backup files found to verify." >&2
  exit 0
fi

echo "$LOG_PREFIX Verifying backup is restorable: $LATEST_BACKUP ..."

VERIFY_OUTPUT=$("$NODE_BIN" "$SCRIPT_DIR/backup.js" --verify "$LATEST_BACKUP" 2>&1)
VERIFY_EXIT=$?

echo "$VERIFY_OUTPUT" | while IFS= read -r line; do
  echo "$LOG_PREFIX   $line"
done

if [ $VERIFY_EXIT -ne 0 ]; then
  echo "$LOG_PREFIX CRITICAL: Restore-verification FAILED for $LATEST_BACKUP" >&2
  echo "$LOG_PREFIX Untested backups are not backups. Investigate immediately." >&2
  exit 1
fi

echo "$LOG_PREFIX Restore-verification PASSED. Backup is confirmed restorable."
