/**
 * SQLite database backup utility with hourly/daily scheduling and
 * point-in-time recovery (PITR).
 *
 * Uses better-sqlite3's `.backup()` API for safe, online backups that
 * don't block reads/writes on the live database.
 *
 * Supports two independent backup tiers:
 *   - Hourly: lightweight rolling backups (default: every 1h, keep 24)
 *   - Daily:  full daily backups at a configurable hour (default: 02:00 UTC)
 *             with GFS retention policy: keep 7 daily, 4 weekly, 12 monthly
 *
 * GFS (Grandfather-Father-Son) retention:
 *   When BACKUP_GFS_ENABLED=true (default), daily backups are pruned using
 *   a tiered policy instead of a flat count:
 *     - Daily:   keep the last 7 days of backups (every backup)
 *     - Weekly:  keep 1 backup per week for the previous 4 weeks
 *     - Monthly: keep 1 backup per month for the previous 12 months
 *   This provides long-term coverage (~1 year) without consuming excessive
 *   disk space. The newest backup in each weekly/monthly bucket is preserved.
 *
 * Both tiers run independently and auto-prune old files based on their own
 * retention setting.
 *
 * Point-in-time recovery (PITR):
 *   A change-log table (`_pitr_changelog`) records every mutating SQL
 *   statement with its timestamp. To recover to a specific point in time,
 *   the system restores the nearest base backup taken *before* the target
 *   timestamp, then replays all logged changes up to (and including) that
 *   exact moment. This gives sub-second recovery granularity bounded only
 *   by backup availability.
 *
 * CLI usage:
 *   node backup.js                         # one-off backup
 *   node backup.js --prune                 # backup + delete old files
 *   node backup.js --restore <file>        # restore from a backup file
 *   node backup.js --pitr <ISO-timestamp>  # point-in-time recovery
 *   node backup.js --pitr-range            # show recoverable time window
 *   node backup.js --gfs-prune [tier]      # run GFS retention prune (default: daily)
 *
 * Environment variables:
 *   BACKUP_DIR                — directory for backup files      (default: ./backups)
 *   BACKUP_RETAIN_COUNT       — legacy: how many to keep        (default: 10)
 *
 *   BACKUP_HOURLY_ENABLED     — enable hourly backups           (default: true)
 *   BACKUP_HOURLY_INTERVAL_MIN— minutes between hourly backups  (default: 60)
 *   BACKUP_HOURLY_RETAIN      — how many hourly backups to keep (default: 24)
 *
 *   BACKUP_DAILY_ENABLED      — enable daily backups            (default: true)
 *   BACKUP_DAILY_HOUR_UTC     — UTC hour for daily backup 0-23  (default: 2)
 *   BACKUP_DAILY_RETAIN       — flat daily backup count (if GFS off) (default: 30)
 *
 *   BACKUP_GFS_ENABLED        — enable GFS retention policy           (default: true)
 *   BACKUP_GFS_DAILY_RETAIN   — days of daily backups to keep         (default: 7)
 *   BACKUP_GFS_WEEKLY_RETAIN  — weeks of weekly backups to keep       (default: 4)
 *   BACKUP_GFS_MONTHLY_RETAIN — months of monthly backups to keep     (default: 12)
 *
 *   PITR_ENABLED              — enable PITR change logging      (default: true)
 *   PITR_RETAIN_HOURS         — how long to keep changelog rows (default: 168 = 7 days)
 */
const path = require('path');
const fs = require('fs');
const log = require('./logger').child({ module: 'backup' });
const { createMonitor } = require('./job-monitor');

const BACKUP_DIR = process.env.BACKUP_DIR
  ? path.resolve(process.env.BACKUP_DIR)
  : path.join(__dirname, '..', 'backups');

/**
 * Resolve a backup filename to an absolute path within BACKUP_DIR.
 * Throws if the result escapes the backup directory (path traversal).
 */
function safePath(filename) {
  if (!filename || typeof filename !== 'string') {
    throw new Error('Invalid backup filename.');
  }
  // Strip any directory components — only the bare filename is allowed.
  const base = path.basename(filename);
  if (base !== filename) {
    throw new Error('Path traversal detected in backup filename.');
  }
  const resolved = path.resolve(BACKUP_DIR, base);
  if (!resolved.startsWith(BACKUP_DIR + path.sep) && resolved !== BACKUP_DIR) {
    throw new Error('Path traversal detected in backup filename.');
  }
  return resolved;
}

const RETAIN_COUNT = parseInt(process.env.BACKUP_RETAIN_COUNT, 10) || 10;

const DB_PATH = process.env.DB_PATH
  ? path.resolve(process.env.DB_PATH)
  : path.join(__dirname, '..', 'data.db');

// ── Tier configuration ──────────────────────────────────────────
const HOURLY_ENABLED      = process.env.BACKUP_HOURLY_ENABLED !== 'false';
const HOURLY_INTERVAL_MIN = parseInt(process.env.BACKUP_HOURLY_INTERVAL_MIN, 10) || 60;
const HOURLY_RETAIN       = parseInt(process.env.BACKUP_HOURLY_RETAIN, 10) || 24;

const DAILY_ENABLED       = process.env.BACKUP_DAILY_ENABLED !== 'false';
const DAILY_HOUR_UTC      = parseInt(process.env.BACKUP_DAILY_HOUR_UTC, 10) || 2;
const DAILY_RETAIN        = parseInt(process.env.BACKUP_DAILY_RETAIN, 10) || 30;

// ── GFS retention policy (Grandfather-Father-Son) ────────────
// Applies to daily-tier backups. When enabled, replaces flat count-based
// pruning with tiered retention: keep N daily, M weekly, P monthly.
const GFS_ENABLED         = process.env.BACKUP_GFS_ENABLED !== 'false';
const GFS_DAILY_RETAIN    = parseInt(process.env.BACKUP_GFS_DAILY_RETAIN, 10) || 7;
const GFS_WEEKLY_RETAIN   = parseInt(process.env.BACKUP_GFS_WEEKLY_RETAIN, 10) || 4;
const GFS_MONTHLY_RETAIN  = parseInt(process.env.BACKUP_GFS_MONTHLY_RETAIN, 10) || 12;

// ── PITR configuration ─────────────────────────────────────────
const PITR_ENABLED        = process.env.PITR_ENABLED !== 'false';
const PITR_RETAIN_HOURS   = parseInt(process.env.PITR_RETAIN_HOURS, 10) || 168; // 7 days
const PITR_MAX_ROWS       = parseInt(process.env.PITR_MAX_ROWS, 10) || 500000;  // hard row cap

/**
 * Create a timestamped backup of the database.
 * @param {string} [tier] — optional label: 'hourly', 'daily', or omitted for manual/legacy.
 * Returns { path, filename, size, timestamp, tier }.
 */
async function createBackup(tier) {
  if (!fs.existsSync(BACKUP_DIR)) {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const prefix = tier ? `data-backup-${tier}-` : 'data-backup-';
  const filename = `${prefix}${timestamp}.db`;
  const dest = path.join(BACKUP_DIR, filename);

  // Use better-sqlite3's backup API — safe with concurrent readers/writers.
  // Falls back to file copy if backup() fails (e.g. WAL-mode edge cases).
  const Database = require('better-sqlite3');
  try {
    const source = new Database(DB_PATH, { readonly: true });
    try {
      await source.backup(dest);
    } finally {
      source.close();
    }
  } catch (_) {
    // Fallback: checkpoint WAL then copy the file
    try {
      const tmp = new Database(DB_PATH);
      tmp.pragma('wal_checkpoint(TRUNCATE)');
      tmp.close();
    } catch (__) { /* ignore — may already be closed or readonly */ }
    fs.copyFileSync(DB_PATH, dest);
  }

  const stats = fs.statSync(dest);
  return {
    path: dest,
    filename,
    size: stats.size,
    timestamp: new Date().toISOString(),
    tier: tier || 'manual',
  };
}

/**
 * List existing backups sorted by date (newest first).
 * @param {string} [tier] — if provided, only list backups for that tier.
 *                          If omitted, list all backups.
 */
function listBackups(tier) {
  if (!fs.existsSync(BACKUP_DIR)) return [];

  const prefix = tier ? `data-backup-${tier}-` : 'data-backup-';

  return fs.readdirSync(BACKUP_DIR)
    .filter(f => f.startsWith(prefix) && f.endsWith('.db'))
    .map(f => {
      const stats = fs.statSync(path.join(BACKUP_DIR, f));
      return { filename: f, size: stats.size, created: stats.mtime };
    })
    .sort((a, b) => b.created - a.created);
}

/**
 * Delete old backups, keeping only the most recent `count`.
 * @param {number} [count] — how many to keep (defaults to RETAIN_COUNT)
 * @param {string} [tier]  — if provided, only prune that tier's backups
 * Returns the list of deleted filenames.
 */
function pruneBackups(count, tier) {
  const keep = count !== undefined ? count : RETAIN_COUNT;
  const backups = listBackups(tier);
  const deleted = [];

  if (backups.length <= keep) return deleted;

  const toDelete = backups.slice(keep);
  for (const b of toDelete) {
    fs.unlinkSync(path.join(BACKUP_DIR, b.filename));
    deleted.push(b.filename);
  }

  return deleted;
}

/**
 * GFS (Grandfather-Father-Son) retention policy for daily backups.
 *
 * Instead of keeping a flat count, this function classifies each backup
 * into one of three tiers based on its age:
 *
 *   Daily   — backups from the last `dailyKeep` days (default: 7)
 *   Weekly  — one backup per calendar week for the last `weeklyKeep` weeks (default: 4)
 *   Monthly — one backup per calendar month for the last `monthlyKeep` months (default: 12)
 *
 * For weekly and monthly buckets the *newest* backup in each bucket is kept
 * (the most recent backup from that week/month). Everything else is deleted.
 *
 * @param {object}  [opts]
 * @param {number}  [opts.dailyKeep]   — days of daily backups to retain  (default: GFS_DAILY_RETAIN)
 * @param {number}  [opts.weeklyKeep]  — weeks of weekly backups to retain (default: GFS_WEEKLY_RETAIN)
 * @param {number}  [opts.monthlyKeep] — months of monthly backups to retain (default: GFS_MONTHLY_RETAIN)
 * @param {string}  [opts.tier]        — backup tier to apply GFS to (default: 'daily')
 * @returns {{ kept: string[], deleted: string[], policy: object }}
 */
function pruneGFS(opts = {}) {
  const dailyKeep   = opts.dailyKeep   ?? GFS_DAILY_RETAIN;
  const weeklyKeep  = opts.weeklyKeep  ?? GFS_WEEKLY_RETAIN;
  const monthlyKeep = opts.monthlyKeep ?? GFS_MONTHLY_RETAIN;
  const tier        = opts.tier        ?? 'daily';

  const backups = listBackups(tier); // newest-first
  if (backups.length === 0) return { kept: [], deleted: [], policy: { dailyKeep, weeklyKeep, monthlyKeep } };

  const now = new Date();
  const dailyCutoff   = new Date(now - dailyKeep * 86400000);
  const weeklyCutoff  = new Date(now - (dailyKeep * 86400000 + weeklyKeep * 7 * 86400000));
  const monthlyCutoff = new Date(now);
  monthlyCutoff.setUTCMonth(monthlyCutoff.getUTCMonth() - monthlyKeep);
  monthlyCutoff.setUTCDate(1);
  monthlyCutoff.setUTCHours(0, 0, 0, 0);

  // Helper: ISO week key "YYYY-WNN"
  function weekKey(date) {
    const d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
    d.setUTCDate(d.getUTCDate() + 4 - (d.getUTCDay() || 7));
    const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
    const weekNum = Math.ceil(((d - yearStart) / 86400000 + 1) / 7);
    return `${d.getUTCFullYear()}-W${String(weekNum).padStart(2, '0')}`;
  }

  // Helper: month key "YYYY-MM"
  function monthKey(date) {
    return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}`;
  }

  const keepSet = new Set();
  const weeklyBuckets = {};   // weekKey → newest backup filename
  const monthlyBuckets = {};  // monthKey → newest backup filename

  for (const b of backups) {
    const created = new Date(b.created);

    // Tier 1: Daily — keep all backups within the daily window
    if (created >= dailyCutoff) {
      keepSet.add(b.filename);
      continue;
    }

    // Tier 2: Weekly — keep newest per ISO week within the weekly window
    if (created >= weeklyCutoff) {
      const wk = weekKey(created);
      if (!weeklyBuckets[wk]) {
        weeklyBuckets[wk] = b; // backups are newest-first, so first seen is newest in that week
      }
      continue;
    }

    // Tier 3: Monthly — keep newest per calendar month within monthly window
    if (created >= monthlyCutoff) {
      const mk = monthKey(created);
      if (!monthlyBuckets[mk]) {
        monthlyBuckets[mk] = b;
      }
      continue;
    }

    // Older than all retention windows — will be deleted
  }

  // Add weekly and monthly keepers
  for (const b of Object.values(weeklyBuckets)) keepSet.add(b.filename);
  for (const b of Object.values(monthlyBuckets)) keepSet.add(b.filename);

  // Delete everything not in keepSet
  const kept = [];
  const deleted = [];
  for (const b of backups) {
    if (keepSet.has(b.filename)) {
      kept.push(b.filename);
    } else {
      try {
        fs.unlinkSync(path.join(BACKUP_DIR, b.filename));
        deleted.push(b.filename);
      } catch (err) {
        log.warn({ err, filename: b.filename }, 'Failed to delete backup during GFS prune');
      }
    }
  }

  if (deleted.length > 0) {
    log.info({
      tier, dailyKeep, weeklyKeep, monthlyKeep,
      kept: kept.length, deleted: deleted.length,
      weeklyBuckets: Object.keys(weeklyBuckets).length,
      monthlyBuckets: Object.keys(monthlyBuckets).length,
    }, 'GFS retention prune complete');
  }

  return {
    kept,
    deleted,
    policy: { dailyKeep, weeklyKeep, monthlyKeep },
  };
}

/**
 * Restore the live database from a backup file.
 * DANGER: This overwrites the current data.db.
 */
async function restoreBackup(backupFilePath) {
  const resolved = path.resolve(backupFilePath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Backup file not found: ${resolved}`);
  }

  // Verify the backup is a valid SQLite database
  const Database = require('better-sqlite3');
  const check = new Database(resolved, { readonly: true });
  try {
    check.pragma('integrity_check');
  } finally {
    check.close();
  }

  // Copy backup over live database
  fs.copyFileSync(resolved, DB_PATH);

  // Remove WAL/SHM files so the restored DB starts clean
  for (const suffix of ['-wal', '-shm']) {
    const f = DB_PATH + suffix;
    if (fs.existsSync(f)) fs.unlinkSync(f);
  }

  return { restored: resolved, target: DB_PATH };
}

// ══════════════════════════════════════════════════════════════════
// ── Backup Integrity Verification (Restore Test) ─────────────────
// ══════════════════════════════════════════════════════════════════

// Expected tables that a valid backup must contain (core schema)
const EXPECTED_TABLES = [
  'users', 'user_settings', 'email_verification_tokens',
  'password_reset_tokens', 'price_alert_rules', 'notifications',
  'page_views', 'analytics_events',
];

/**
 * Verify a single backup file is intact and restorable.
 *
 * Performs a multi-layer verification without touching the live database:
 *   1. File existence and minimum size check
 *   2. Opens the file as a SQLite DB (proves it's a valid SQLite file)
 *   3. PRAGMA integrity_check (full page-level verification)
 *   4. Schema validation: all expected tables are present
 *   5. Read test: SELECT COUNT(*) on each expected table (proves data is readable)
 *   6. Foreign key check: PRAGMA foreign_key_check (referential integrity)
 *
 * @param {string} filename — backup filename (relative to BACKUP_DIR)
 * @returns {{ ok: boolean, filename: string, checks: object, durationMs: number, error?: string }}
 */
function verifyBackup(filename) {
  const start = Date.now();
  const filePath = safePath(filename);
  const checks = {
    fileExists: false,
    fileSize: 0,
    sqliteOpen: false,
    integrityCheck: false,
    integrityErrors: [],
    schemaTables: [],
    missingTables: [],
    schemaValid: false,
    readTest: {},
    readTestPassed: false,
    foreignKeyCheck: false,
    foreignKeyErrors: [],
  };

  try {
    // 1. File existence + size
    if (!fs.existsSync(filePath)) {
      return { ok: false, filename, checks, durationMs: Date.now() - start, error: 'File not found' };
    }
    checks.fileExists = true;
    const stats = fs.statSync(filePath);
    checks.fileSize = stats.size;

    if (stats.size < 512) {
      return { ok: false, filename, checks, durationMs: Date.now() - start, error: 'File too small to be a valid SQLite database' };
    }

    // 2. Open as SQLite (readonly — never modifies the backup)
    const Database = require('better-sqlite3');
    let testDb;
    try {
      testDb = new Database(filePath, { readonly: true });
    } catch (openErr) {
      return { ok: false, filename, checks, durationMs: Date.now() - start, error: 'Failed to open as SQLite: ' + openErr.message };
    }
    checks.sqliteOpen = true;

    try {
      // 3. Integrity check
      const intResult = testDb.pragma('integrity_check');
      if (intResult.length === 1 && intResult[0].integrity_check === 'ok') {
        checks.integrityCheck = true;
      } else {
        checks.integrityErrors = intResult.map(r => r.integrity_check).slice(0, 20);
      }

      // 4. Schema validation — get all tables and verify expected ones exist
      const tables = testDb.prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
      ).all().map(r => r.name);
      checks.schemaTables = tables;
      checks.missingTables = EXPECTED_TABLES.filter(t => !tables.includes(t));
      checks.schemaValid = checks.missingTables.length === 0;

      // 5. Read test — try to count rows in each expected table
      let allReadsOk = true;
      for (const tbl of EXPECTED_TABLES) {
        if (!tables.includes(tbl)) {
          checks.readTest[tbl] = { ok: false, error: 'table missing' };
          allReadsOk = false;
          continue;
        }
        try {
          const row = testDb.prepare(`SELECT COUNT(*) AS cnt FROM "${tbl}"`).get();
          checks.readTest[tbl] = { ok: true, rows: row.cnt };
        } catch (readErr) {
          checks.readTest[tbl] = { ok: false, error: readErr.message };
          allReadsOk = false;
        }
      }
      checks.readTestPassed = allReadsOk;

      // 6. Foreign key check
      const fkErrors = testDb.pragma('foreign_key_check');
      if (fkErrors.length === 0) {
        checks.foreignKeyCheck = true;
      } else {
        checks.foreignKeyErrors = fkErrors.slice(0, 20).map(e => ({
          table: e.table,
          rowid: e.rowid,
          parent: e.parent,
          fkid: e.fkid,
        }));
      }
    } finally {
      testDb.close();
    }

    const ok = checks.integrityCheck && checks.schemaValid && checks.readTestPassed && checks.foreignKeyCheck;

    return { ok, filename, checks, durationMs: Date.now() - start };
  } catch (err) {
    return { ok: false, filename, checks, durationMs: Date.now() - start, error: err.message };
  }
}

/**
 * Verify all backup files (or a filtered tier).
 *
 * @param {string} [tier] — optional tier filter ('hourly', 'daily', etc.)
 * @returns {{ total: number, passed: number, failed: number, results: object[] }}
 */
function verifyAllBackups(tier) {
  const backups = listBackups(tier);
  const results = [];
  let passed = 0;
  let failed = 0;

  for (const b of backups) {
    const result = verifyBackup(b.filename);
    results.push(result);
    if (result.ok) {
      passed++;
    } else {
      failed++;
      log.warn({ filename: b.filename, error: result.error, checks: result.checks },
        'Backup verification FAILED');
    }
  }

  return { total: backups.length, passed, failed, results };
}

/**
 * Initialise the PITR change-log table and install SQLite triggers on
 * every user-facing table so that INSERT / UPDATE / DELETE statements
 * are automatically captured with their timestamp and parameters.
 *
 * Must be called once at server startup (after DB migrations).
 * Safe to call multiple times — uses IF NOT EXISTS throughout.
 *
 * @param {import('better-sqlite3').Database} db — the live database handle
 */
function initPitrChangeLog(db) {
  if (!PITR_ENABLED) return;

  // The changelog table itself
  db.exec(`
    CREATE TABLE IF NOT EXISTS _pitr_changelog (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      ts        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
      tbl       TEXT    NOT NULL,
      op        TEXT    NOT NULL CHECK(op IN ('INSERT','UPDATE','DELETE')),
      row_id    INTEGER NOT NULL,
      old_data  TEXT,
      new_data  TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_pitr_ts ON _pitr_changelog(ts);
  `);

  // Discover all user tables (skip sqlite internals, session store, and the
  // changelog itself).
  const SKIP_TABLES = new Set([
    '_pitr_changelog', 'sqlite_sequence', 'sessions', 'config',
  ]);

  const tables = db.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
  ).all().map(r => r.name).filter(t => !SKIP_TABLES.has(t));

  for (const tbl of tables) {
    // Gather column names for JSON serialisation
    const cols = db.prepare(`PRAGMA table_info("${tbl}")`).all().map(c => c.name);
    const jsonOld = cols.map(c => `'${c}', OLD."${c}"`).join(', ');
    const jsonNew = cols.map(c => `'${c}', NEW."${c}"`).join(', ');

    // INSERT trigger — captures the new row
    db.exec(`
      CREATE TRIGGER IF NOT EXISTS _pitr_after_insert_${tbl}
      AFTER INSERT ON "${tbl}"
      BEGIN
        INSERT INTO _pitr_changelog (tbl, op, row_id, new_data)
        VALUES ('${tbl}', 'INSERT', NEW.rowid, json_object(${jsonNew}));
      END;
    `);

    // UPDATE trigger — captures both old and new state
    db.exec(`
      CREATE TRIGGER IF NOT EXISTS _pitr_after_update_${tbl}
      AFTER UPDATE ON "${tbl}"
      BEGIN
        INSERT INTO _pitr_changelog (tbl, op, row_id, old_data, new_data)
        VALUES ('${tbl}', 'UPDATE', NEW.rowid, json_object(${jsonOld}), json_object(${jsonNew}));
      END;
    `);

    // DELETE trigger — captures the deleted row
    db.exec(`
      CREATE TRIGGER IF NOT EXISTS _pitr_after_delete_${tbl}
      AFTER DELETE ON "${tbl}"
      BEGIN
        INSERT INTO _pitr_changelog (tbl, op, row_id, old_data)
        VALUES ('${tbl}', 'DELETE', OLD.rowid, json_object(${jsonOld}));
      END;
    `);
  }

  log.info({ tables: tables.length, pitrRetainHours: PITR_RETAIN_HOURS },
    'PITR change-log triggers installed');
}

/**
 * Prune changelog entries older than PITR_RETAIN_HOURS **and** enforce
 * PITR_MAX_ROWS hard cap.  The time-based prune runs first; if the table
 * still exceeds PITR_MAX_ROWS afterwards, the oldest excess rows are
 * deleted regardless of age.  This prevents unbounded growth under heavy
 * write load where rows accumulate faster than the time window expires.
 *
 * Called automatically during scheduled backups and the background cleanup job.
 *
 * @param {import('better-sqlite3').Database} db
 * @returns {{ deleted: number, deletedByCap: number }}
 */
function pruneChangelog(db) {
  if (!PITR_ENABLED) return { deleted: 0, deletedByCap: 0 };

  // 1. Time-based prune (existing behaviour)
  const cutoff = new Date(Date.now() - PITR_RETAIN_HOURS * 3600000).toISOString();
  const timeResult = db.prepare('DELETE FROM _pitr_changelog WHERE ts < ?').run(cutoff);

  // 2. Row-cap enforcement — delete oldest rows exceeding the hard limit
  let deletedByCap = 0;
  if (PITR_MAX_ROWS > 0) {
    const count = db.prepare('SELECT COUNT(*) AS cnt FROM _pitr_changelog').get().cnt;
    if (count > PITR_MAX_ROWS) {
      const excess = count - PITR_MAX_ROWS;
      const capResult = db.prepare(
        'DELETE FROM _pitr_changelog WHERE id IN (SELECT id FROM _pitr_changelog ORDER BY id ASC LIMIT ?)'
      ).run(excess);
      deletedByCap = capResult.changes;
    }
  }

  return { deleted: timeResult.changes, deletedByCap };
}

/**
 * Return the recoverable time window: the range of timestamps for which
 * PITR is possible (oldest backup → most recent changelog entry).
 *
 * @param {import('better-sqlite3').Database} [db] — optional; used to read changelog bounds
 * @returns {{ earliest: string|null, latest: string|null, backups: number, changelogEntries: number }}
 */
function getPitrRange(db) {
  // Find the oldest available backup (any tier)
  const allBackups = listBackups();
  const earliest = allBackups.length > 0
    ? allBackups[allBackups.length - 1].created.toISOString()
    : null;

  let latest = null;
  let changelogEntries = 0;

  if (db && PITR_ENABLED) {
    try {
      const row = db.prepare(
        'SELECT MAX(ts) AS latest, COUNT(*) AS cnt FROM _pitr_changelog'
      ).get();
      latest = row.latest || null;
      changelogEntries = row.cnt || 0;
    } catch (_) { /* table may not exist yet */ }
  }

  // If no changelog entries, latest recoverable point is newest backup
  if (!latest && allBackups.length > 0) {
    latest = allBackups[0].created.toISOString();
  }

  return {
    earliest,
    latest,
    backups: allBackups.length,
    changelogEntries,
  };
}

/**
 * Perform point-in-time recovery: restore to the state at `targetISO`.
 *
 * Algorithm:
 *   1. Find the newest backup whose timestamp is ≤ targetISO.
 *   2. Restore that backup (overwrite the live DB file).
 *   3. Open the restored DB and replay all changelog entries from the
 *      *live* changelog that fall between the backup's timestamp and
 *      targetISO, in chronological order.
 *   4. Return a summary of what was replayed.
 *
 * IMPORTANT: The server should be stopped (or this should be the only
 * writer) during PITR. The caller is responsible for restarting after.
 *
 * @param {string} targetISO — ISO 8601 timestamp to recover to
 * @param {import('better-sqlite3').Database} [liveDb] — current live DB
 *        (used to read the changelog before overwriting). If omitted the
 *        function opens the DB_PATH itself.
 * @returns {Promise<{ baseBackup: string, target: string, replayed: number }>}
 */
async function restoreToPointInTime(targetISO, liveDb) {
  const Database = require('better-sqlite3');
  const target = new Date(targetISO);
  if (isNaN(target.getTime())) {
    throw new Error('Invalid timestamp: ' + targetISO);
  }
  const targetStr = target.toISOString();

  // 1. Find the best base backup (newest one created ≤ target)
  const allBackups = listBackups();
  const candidates = allBackups.filter(b => new Date(b.created) <= target);
  if (candidates.length === 0) {
    throw new Error(
      'No backup available at or before ' + targetStr + '. ' +
      'Oldest backup: ' + (allBackups.length > 0
        ? allBackups[allBackups.length - 1].created.toISOString()
        : 'none')
    );
  }
  // candidates are sorted newest-first, so [0] is the closest before target
  const baseBackup = candidates[0];
  const baseTimestamp = new Date(baseBackup.created).toISOString();

  log.info({
    baseBackup: baseBackup.filename,
    baseTimestamp,
    target: targetStr,
  }, 'PITR: selected base backup');

  // 2. Read changelog entries from the LIVE database before overwriting it.
  //    We need all entries between the base backup time and the target time.
  let changelogRows = [];
  const sourceDb = liveDb || new Database(DB_PATH, { readonly: true });
  try {
    // Check if changelog table exists
    const hasTable = sourceDb.prepare(
      "SELECT 1 FROM sqlite_master WHERE type='table' AND name='_pitr_changelog'"
    ).get();

    if (hasTable) {
      changelogRows = sourceDb.prepare(
        'SELECT * FROM _pitr_changelog WHERE ts > ? AND ts <= ? ORDER BY id ASC'
      ).all(baseTimestamp, targetStr);
    }
  } finally {
    if (!liveDb) sourceDb.close();
  }

  log.info({ changelogRows: changelogRows.length }, 'PITR: changelog entries to replay');

  // 3. Restore the base backup (overwrites the live DB file)
  await restoreBackup(path.join(BACKUP_DIR, baseBackup.filename));

  // 4. Replay changelog entries on the restored database
  if (changelogRows.length > 0) {
    const restored = new Database(DB_PATH);
    restored.pragma('journal_mode = WAL');
    restored.pragma('busy_timeout = 5000');

    const replay = restored.transaction((rows) => {
      for (const row of rows) {
        _replayChangelogEntry(restored, row);
      }
    });

    try {
      replay(changelogRows);
    } finally {
      restored.close();
    }
  }

  log.info({
    baseBackup: baseBackup.filename,
    target: targetStr,
    replayed: changelogRows.length,
  }, 'PITR: recovery complete');

  return {
    baseBackup: baseBackup.filename,
    baseTimestamp,
    target: targetStr,
    replayed: changelogRows.length,
  };
}

/**
 * Replay a single changelog entry on a database handle.
 * @param {import('better-sqlite3').Database} db
 * @param {object} entry — row from _pitr_changelog
 */
function _replayChangelogEntry(db, entry) {
  const tbl = entry.tbl;

  if (entry.op === 'INSERT') {
    const data = JSON.parse(entry.new_data);
    const cols = Object.keys(data);
    const placeholders = cols.map(() => '?').join(', ');
    const quotedCols = cols.map(c => `"${c}"`).join(', ');
    db.prepare(
      `INSERT OR REPLACE INTO "${tbl}" (${quotedCols}) VALUES (${placeholders})`
    ).run(...cols.map(c => data[c]));

  } else if (entry.op === 'UPDATE') {
    const data = JSON.parse(entry.new_data);
    const cols = Object.keys(data);
    // Use rowid to target the exact row
    const setClauses = cols.map(c => `"${c}" = ?`).join(', ');
    db.prepare(
      `UPDATE "${tbl}" SET ${setClauses} WHERE rowid = ?`
    ).run(...cols.map(c => data[c]), entry.row_id);

  } else if (entry.op === 'DELETE') {
    db.prepare(
      `DELETE FROM "${tbl}" WHERE rowid = ?`
    ).run(entry.row_id);
  }
}

// ── Backup scheduler ────────────────────────────────────────────

/**
 * Calculate milliseconds until the next occurrence of `hourUTC` (0-23).
 * If the target hour already passed today, returns the time until that
 * hour tomorrow.
 */
function msUntilNextHourUTC(hourUTC) {
  const now = new Date();
  const target = new Date(now);
  target.setUTCHours(hourUTC, 0, 0, 0);
  if (target <= now) {
    target.setUTCDate(target.getUTCDate() + 1);
  }
  return target - now;
}

let _hourlyTimer = null;
let _dailyTimer = null;
let _dailyAlignTimer = null;

let _liveDb = null; // set by startSchedule() for changelog pruning

const _hourlyMonitor = createMonitor({
  name: 'backup-hourly',
  fn: () => _runHourlyBackupInner(),
  alertThreshold: 3,
  cooldownMs: 60 * 60 * 1000,
});

const _dailyMonitor = createMonitor({
  name: 'backup-daily',
  fn: () => _runDailyBackupInner(),
  alertThreshold: 2,             // daily jobs are less frequent — alert sooner
  cooldownMs: 12 * 60 * 60 * 1000,
});

/**
 * Run a single scheduled hourly backup cycle (backup + prune + changelog prune).
 */
async function _runHourlyBackupInner() {
  const result = await createBackup('hourly');
  const pruned = pruneBackups(HOURLY_RETAIN, 'hourly');

  // Prune old changelog entries alongside the hourly backup
  let changelogPruned = 0;
  let changelogCapped = 0;
  if (_liveDb && PITR_ENABLED) {
    try {
      const cl = pruneChangelog(_liveDb);
      changelogPruned = cl.deleted;
      changelogCapped = cl.deletedByCap;
    } catch (clErr) {
      log.warn({ err: clErr }, 'Changelog prune failed (non-fatal)');
    }
  }

  log.info({
    tier: 'hourly',
    filename: result.filename,
    sizeKB: +(result.size / 1024).toFixed(1),
    pruned: pruned.length,
    changelogPruned,
    changelogCapped,
  }, 'Hourly backup complete');

  return result;
}

async function _runHourlyBackup() {
  return _hourlyMonitor.run();
}

/**
 * Run a single scheduled daily backup cycle (backup + prune + verify).
 */
async function _runDailyBackupInner() {
  const result = await createBackup('daily');

  // Prune using GFS retention policy (7 daily / 4 weekly / 12 monthly)
  // or fall back to flat count if GFS is disabled.
  let pruneResult;
  if (GFS_ENABLED) {
    pruneResult = pruneGFS({ tier: 'daily' });
  } else {
    const pruned = pruneBackups(DAILY_RETAIN, 'daily');
    pruneResult = { deleted: pruned, kept: [], policy: { flat: DAILY_RETAIN } };
  }

  // Verify the backup we just created
  let verified = null;
  try {
    verified = verifyBackup(result.filename);
    if (!verified.ok) {
      log.error({
        tier: 'daily',
        filename: result.filename,
        checks: verified.checks,
        error: verified.error,
      }, 'DAILY BACKUP VERIFICATION FAILED — backup may be corrupt');
    }
  } catch (verifyErr) {
    log.warn({ err: verifyErr }, 'Daily backup verification threw an error (non-fatal)');
  }

  log.info({
    tier: 'daily',
    filename: result.filename,
    sizeKB: +(result.size / 1024).toFixed(1),
    pruned: pruneResult.deleted.length,
    retentionPolicy: pruneResult.policy,
    verified: verified ? verified.ok : null,
    verifyMs: verified ? verified.durationMs : null,
  }, 'Daily backup complete');

  return result;
}

async function _runDailyBackup() {
  return _dailyMonitor.run();
}

/**
 * Start the automated backup schedule.
 *
 * - Hourly: runs immediately on start, then every BACKUP_HOURLY_INTERVAL_MIN
 *   minutes. Keeps the most recent BACKUP_HOURLY_RETAIN files.
 *   Also prunes old PITR changelog entries.
 *
 * - Daily: aligns to BACKUP_DAILY_HOUR_UTC, then repeats every 24 h.
 *   Keeps the most recent BACKUP_DAILY_RETAIN files.
 *
 * @param {import('better-sqlite3').Database} [db] — live DB handle (for changelog pruning)
 * Returns a handle with `.stop()` to cancel all timers.
 */
function startSchedule(db) {
  _liveDb = db || null;
  // ── Hourly tier ──────────────────────────────────────────────
  if (HOURLY_ENABLED) {
    _runHourlyBackup();   // immediate first backup
    const intervalMs = HOURLY_INTERVAL_MIN * 60 * 1000;
    _hourlyTimer = setInterval(_runHourlyBackup, intervalMs);
    _hourlyTimer.unref();
    log.info({
      tier: 'hourly',
      intervalMin: HOURLY_INTERVAL_MIN,
      retain: HOURLY_RETAIN,
    }, 'Hourly backup schedule started');
  }

  // ── Daily tier ───────────────────────────────────────────────
  if (DAILY_ENABLED) {
    const delayMs = msUntilNextHourUTC(DAILY_HOUR_UTC);
    const delayH = +(delayMs / 3600000).toFixed(1);

    log.info({
      tier: 'daily',
      hourUTC: DAILY_HOUR_UTC,
      gfsEnabled: GFS_ENABLED,
      retention: GFS_ENABLED
        ? { daily: GFS_DAILY_RETAIN, weekly: GFS_WEEKLY_RETAIN, monthly: GFS_MONTHLY_RETAIN }
        : { flat: DAILY_RETAIN },
      nextInHours: delayH,
    }, 'Daily backup schedule started (waiting for aligned hour)');

    // Wait until the target hour, then run daily + repeat every 24 h
    _dailyAlignTimer = setTimeout(() => {
      _dailyAlignTimer = null;
      _runDailyBackup();
      const DAY_MS = 24 * 60 * 60 * 1000;
      _dailyTimer = setInterval(_runDailyBackup, DAY_MS);
      _dailyTimer.unref();
    }, delayMs);
    _dailyAlignTimer.unref();
  }

  return {
    stop: stopSchedule,
  };
}

/**
 * Stop all scheduled backup timers. Safe to call multiple times.
 */
function stopSchedule() {
  if (_hourlyTimer) { clearInterval(_hourlyTimer); _hourlyTimer = null; }
  if (_dailyTimer) { clearInterval(_dailyTimer); _dailyTimer = null; }
  if (_dailyAlignTimer) { clearTimeout(_dailyAlignTimer); _dailyAlignTimer = null; }
  log.info('Backup schedule stopped');
}

// ─── CLI mode ───────────────────────────────────────────────────
if (require.main === module) {
  const args = process.argv.slice(2);

  if (args.includes('--restore')) {
    const idx = args.indexOf('--restore');
    const file = args[idx + 1];
    if (!file) {
      console.error('Usage: node backup.js --restore <backup-file>');
      process.exit(1);
    }
    restoreBackup(file)
      .then(r => console.log(`Restored ${r.restored} → ${r.target}`))
      .catch(e => { console.error('Restore failed:', e.message); process.exit(1); });

  } else if (args.includes('--pitr')) {
    const idx = args.indexOf('--pitr');
    const timestamp = args[idx + 1];
    if (!timestamp) {
      console.error('Usage: node backup.js --pitr <ISO-8601-timestamp>');
      console.error('Example: node backup.js --pitr 2026-03-28T14:30:00.000Z');
      process.exit(1);
    }
    restoreToPointInTime(timestamp)
      .then(r => {
        console.log(`PITR recovery complete:`);
        console.log(`  Base backup : ${r.baseBackup} (${r.baseTimestamp})`);
        console.log(`  Target time : ${r.target}`);
        console.log(`  Replayed    : ${r.replayed} changelog entries`);
        console.log(`\nRestart the server to load the recovered database.`);
      })
      .catch(e => { console.error('PITR failed:', e.message); process.exit(1); });

  } else if (args.includes('--pitr-range')) {
    const range = getPitrRange();
    console.log('Recoverable time window:');
    console.log(`  Earliest : ${range.earliest || '(no backups)'}`);
    console.log(`  Latest   : ${range.latest || '(no data)'}`);
    console.log(`  Backups  : ${range.backups}`);
    console.log(`  Changelog: ${range.changelogEntries} entries`);

  } else if (args.includes('--verify')) {
    const idx = args.indexOf('--verify');
    const file = args[idx + 1];
    if (!file) {
      console.error('Usage: node backup.js --verify <backup-filename>');
      process.exit(1);
    }
    const result = verifyBackup(file);
    console.log(`Verification: ${result.ok ? 'PASSED' : 'FAILED'}  (${result.durationMs}ms)`);
    console.log(`  File        : ${result.filename}`);
    console.log(`  Size        : ${(result.checks.fileSize / 1024).toFixed(1)} KB`);
    console.log(`  Integrity   : ${result.checks.integrityCheck ? 'ok' : 'FAIL — ' + result.checks.integrityErrors.join('; ')}`);
    console.log(`  Schema      : ${result.checks.schemaValid ? 'ok' : 'MISSING: ' + result.checks.missingTables.join(', ')}`);
    console.log(`  Read test   : ${result.checks.readTestPassed ? 'ok' : 'FAIL'}`);
    if (result.checks.readTestPassed) {
      for (const [tbl, info] of Object.entries(result.checks.readTest)) {
        console.log(`    ${tbl}: ${info.rows} rows`);
      }
    }
    console.log(`  Foreign keys: ${result.checks.foreignKeyCheck ? 'ok' : 'FAIL — ' + result.checks.foreignKeyErrors.length + ' violations'}`);
    if (result.error) console.log(`  Error       : ${result.error}`);
    process.exit(result.ok ? 0 : 1);

  } else if (args.includes('--verify-all')) {
    const tier = args[args.indexOf('--verify-all') + 1] || undefined;
    const summary = verifyAllBackups(tier);
    console.log(`Verified ${summary.total} backup(s): ${summary.passed} passed, ${summary.failed} failed`);
    for (const r of summary.results) {
      const status = r.ok ? 'PASS' : 'FAIL';
      const sizeKB = (r.checks.fileSize / 1024).toFixed(1);
      console.log(`  [${status}] ${r.filename}  (${sizeKB} KB, ${r.durationMs}ms)${r.error ? ' — ' + r.error : ''}`);
    }
    process.exit(summary.failed > 0 ? 1 : 0);

  } else if (args.includes('--gfs-prune')) {
    const tier = args[args.indexOf('--gfs-prune') + 1] || 'daily';
    const result = pruneGFS({ tier });
    console.log(`GFS retention policy: keep ${result.policy.dailyKeep} daily, ${result.policy.weeklyKeep} weekly, ${result.policy.monthlyKeep} monthly`);
    console.log(`Kept: ${result.kept.length} backup(s)`);
    if (result.deleted.length > 0) {
      console.log(`Deleted: ${result.deleted.length} backup(s):`);
      for (const f of result.deleted) console.log(`  - ${f}`);
    } else {
      console.log('No backups to delete.');
    }

  } else {
    createBackup()
      .then(result => {
        console.log(`Backup created: ${result.filename} (${(result.size / 1024).toFixed(1)} KB)`);
        if (args.includes('--prune')) {
          const deleted = pruneBackups();
          if (deleted.length > 0) {
            console.log(`Pruned ${deleted.length} old backup(s): ${deleted.join(', ')}`);
          } else {
            console.log(`No old backups to prune (keeping ${RETAIN_COUNT}).`);
          }
        }
      })
      .catch(e => { console.error('Backup failed:', e.message); process.exit(1); });
  }
}

module.exports = {
  createBackup, listBackups, pruneBackups, pruneGFS, restoreBackup,
  verifyBackup, verifyAllBackups, safePath,
  startSchedule, stopSchedule,
  initPitrChangeLog, pruneChangelog, getPitrRange, restoreToPointInTime,
  BACKUP_DIR, PITR_ENABLED, GFS_ENABLED,
  getStatus() {
    return {
      hourly: _hourlyMonitor.getStatus(),
      daily: _dailyMonitor.getStatus(),
    };
  },
};
