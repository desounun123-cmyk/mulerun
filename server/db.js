const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = process.env.DB_PATH
  ? require('path').resolve(process.env.DB_PATH)
  : path.join(__dirname, 'data.db');

const db = new Database(DB_PATH);

// Enable WAL mode and busy timeout
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'Free',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS user_settings (
    user_id INTEGER PRIMARY KEY,
    price_alerts INTEGER NOT NULL DEFAULT 1,
    weekly_newsletter INTEGER NOT NULL DEFAULT 0,
    dark_mode INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Add avatar column if missing (migration)
const cols = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
if (!cols.includes('avatar')) {
  db.exec("ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT NULL");
}
if (!cols.includes('avatar_bg')) {
  db.exec("ALTER TABLE users ADD COLUMN avatar_bg TEXT DEFAULT NULL");
}

// User activity tracking columns (migration)
if (!cols.includes('last_login')) {
  db.exec("ALTER TABLE users ADD COLUMN last_login TEXT DEFAULT NULL");
}
if (!cols.includes('login_count')) {
  db.exec("ALTER TABLE users ADD COLUMN login_count INTEGER NOT NULL DEFAULT 0");
}
if (!cols.includes('last_settings_change')) {
  db.exec("ALTER TABLE users ADD COLUMN last_settings_change TEXT DEFAULT NULL");
}

// OAuth columns (migration)
if (!cols.includes('oauth_provider')) {
  db.exec("ALTER TABLE users ADD COLUMN oauth_provider TEXT DEFAULT NULL");
}
if (!cols.includes('oauth_id')) {
  db.exec("ALTER TABLE users ADD COLUMN oauth_id TEXT DEFAULT NULL");
}

// Account lockout columns (migration)
if (!cols.includes('failed_login_attempts')) {
  db.exec("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0");
}
if (!cols.includes('locked_until')) {
  db.exec("ALTER TABLE users ADD COLUMN locked_until TEXT DEFAULT NULL");
}

// TOTP two-factor authentication columns (migration)
if (!cols.includes('totp_secret')) {
  db.exec("ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT NULL");
}
if (!cols.includes('totp_enabled')) {
  db.exec("ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0");
}

// Email notification preference column (migration)
const settingCols = db.prepare("PRAGMA table_info(user_settings)").all().map(c => c.name);
if (!settingCols.includes('notify_email')) {
  db.exec("ALTER TABLE user_settings ADD COLUMN notify_email INTEGER NOT NULL DEFAULT 0");
}
if (!settingCols.includes('notify_inapp')) {
  db.exec("ALTER TABLE user_settings ADD COLUMN notify_inapp INTEGER NOT NULL DEFAULT 1");
}
if (!settingCols.includes('notify_push')) {
  db.exec("ALTER TABLE user_settings ADD COLUMN notify_push INTEGER NOT NULL DEFAULT 1");
}

// Email verification column (migration)
if (!cols.includes('email_verified')) {
  db.exec("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0");
  // Mark all existing users as verified (they registered before this feature)
  db.exec("UPDATE users SET email_verified = 1");
}

// Email verification tokens table
db.exec(`
  CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Price alert rules table
db.exec(`
  CREATE TABLE IF NOT EXISTS price_alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    product TEXT NOT NULL,
    direction TEXT NOT NULL CHECK(direction IN ('above','below')),
    threshold REAL NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    triggered INTEGER NOT NULL DEFAULT 0,
    last_triggered_at TEXT DEFAULT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_par_user ON price_alert_rules(user_id, active);
`);

// Password reset tokens table
db.exec(`
  CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Privacy-respecting analytics — page views
db.exec(`
  CREATE TABLE IF NOT EXISTS page_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    page TEXT NOT NULL DEFAULT '/',
    referrer TEXT DEFAULT NULL,
    screen_w INTEGER DEFAULT NULL,
    screen_h INTEGER DEFAULT NULL,
    lang TEXT DEFAULT NULL,
    ua_browser TEXT DEFAULT NULL,
    ua_os TEXT DEFAULT NULL,
    ua_device TEXT DEFAULT 'desktop',
    session_hash TEXT DEFAULT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// Analytics events (feature usage, button clicks, etc.)
db.exec(`
  CREATE TABLE IF NOT EXISTS analytics_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,
    meta TEXT DEFAULT NULL,
    session_hash TEXT DEFAULT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// In-app notifications
db.exec(`
  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL DEFAULT 'info',
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, read, created_at);
`);

// Seed demo user if not present
const existingDemo = db.prepare('SELECT id FROM users WHERE email = ?').get('demo@oil.com');
if (!existingDemo) {
  const hash = bcrypt.hashSync('oil2026oil2026', 10);
  const result = db.prepare(
    'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)'
  ).run('Demo', 'demo@oil.com', hash);

  db.prepare(
    'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode) VALUES (?, 1, 0, 1)'
  ).run(result.lastInsertRowid);
}

// Seed test user if not present
const existingTest = db.prepare('SELECT id FROM users WHERE email = ?').get('test@oil.com');
if (!existingTest) {
  const testHash = bcrypt.hashSync('2026oil2026oil', 10);
  const testResult = db.prepare(
    'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)'
  ).run('Test', 'test@oil.com', testHash);

  db.prepare(
    'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode) VALUES (?, 1, 0, 1)'
  ).run(testResult.lastInsertRowid);
}

// Seed admin user if not present
const existingAdmin = db.prepare('SELECT id FROM users WHERE email = ?').get('siteadmin@oil.com');
if (!existingAdmin) {
  const adminHash = bcrypt.hashSync('nimdaetis123&', 10);
  const adminResult = db.prepare(
    'INSERT INTO users (name, email, password_hash, plan) VALUES (?, ?, ?, ?)'
  ).run('Admin', 'siteadmin@oil.com', adminHash, 'Admin');

  db.prepare(
    'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode) VALUES (?, 1, 1, 1)'
  ).run(adminResult.lastInsertRowid);
} else {
  db.prepare("UPDATE users SET plan = 'Admin', name = 'Admin' WHERE email = 'siteadmin@oil.com'").run();
}

module.exports = db;

// ── Database Health: WAL Checkpoint & Integrity Checks ──────────

/**
 * Run a WAL checkpoint (PASSIVE by default — does not block writers).
 * Returns { busy, log, checkpointed } counts from SQLite.
 * Use mode = 'TRUNCATE' for a full checkpoint that resets the WAL file.
 */
function checkpointWAL(mode) {
  const m = (mode || 'PASSIVE').toUpperCase();
  if (!['PASSIVE', 'FULL', 'RESTART', 'TRUNCATE'].includes(m)) {
    throw new Error('Invalid WAL checkpoint mode: ' + m);
  }
  const row = db.pragma('wal_checkpoint(' + m + ')')[0] || {};
  return { busy: row.busy, log: row.log, checkpointed: row.checkpointed };
}

/**
 * Run `PRAGMA integrity_check` on the database.
 * Returns { ok: true } if the database is healthy, or
 * { ok: false, errors: [...] } with the list of problems.
 */
function runIntegrityCheck() {
  const rows = db.pragma('integrity_check');
  if (rows.length === 1 && rows[0].integrity_check === 'ok') {
    return { ok: true, errors: [] };
  }
  return { ok: false, errors: rows.map(r => r.integrity_check) };
}

/**
 * Attempt automatic recovery from the most recent backup.
 * Returns { recovered: true, backup: filename } on success,
 * or { recovered: false, reason: string } on failure.
 */
async function attemptRecovery(log, backupModule) {
  if (!backupModule) return { recovered: false, reason: 'No backup module available' };

  const backups = backupModule.listBackups();
  if (backups.length === 0) return { recovered: false, reason: 'No backups found' };

  // Try backups newest-first until one passes integrity check
  const Database = require('better-sqlite3');
  const path = require('path');

  for (const b of backups) {
    const filePath = path.join(backupModule.BACKUP_DIR, b.filename);
    try {
      const testDb = new Database(filePath, { readonly: true });
      const result = testDb.pragma('integrity_check');
      testDb.close();
      if (result.length === 1 && result[0].integrity_check === 'ok') {
        log.warn({ backup: b.filename }, 'Found valid backup — initiating restore');
        await backupModule.restoreBackup(filePath);
        log.info({ backup: b.filename }, 'Database restored from backup');
        return { recovered: true, backup: b.filename };
      } else {
        log.warn({ backup: b.filename }, 'Backup also corrupt — trying next');
      }
    } catch (err) {
      log.warn({ backup: b.filename, err: err.message }, 'Backup unreadable — trying next');
    }
  }
  return { recovered: false, reason: 'All backups corrupt or unreadable' };
}

/**
 * Start a background health monitor that:
 *   1. Runs WAL PASSIVE checkpoint every `checkpointMinutes` (default 5)
 *   2. Runs integrity_check every `integrityMinutes` (default 60)
 *   3. On integrity failure: logs a critical error, takes a pre-recovery
 *      backup, and attempts automatic restore from the newest valid backup.
 *
 * Returns a handle with `.stop()` to cancel the timers.
 */
function startHealthMonitor(log, backupModule, options) {
  const opts = Object.assign({
    checkpointMinutes: parseInt(process.env.DB_CHECKPOINT_INTERVAL_MIN, 10) || 5,
    integrityMinutes: parseInt(process.env.DB_INTEGRITY_INTERVAL_MIN, 10) || 60,
  }, options);

  let recovering = false;

  // ── Periodic WAL checkpoint ──────────────────────────────────
  const walJob = () => {
    try {
      const result = checkpointWAL('PASSIVE');
      if (result.log > 0) {
        log.debug({ walPages: result.log, checkpointed: result.checkpointed }, 'WAL checkpoint');
      }
    } catch (err) {
      log.error({ err }, 'WAL checkpoint failed');
    }
  };

  // ── Periodic integrity check ─────────────────────────────────
  const integrityJob = async () => {
    if (recovering) return;
    try {
      const result = runIntegrityCheck();
      if (result.ok) {
        log.info('Database integrity check passed');
        return;
      }

      // ── Corruption detected ────────────────────────────────
      log.fatal({ errors: result.errors.slice(0, 20) },
        'DATABASE CORRUPTION DETECTED — attempting automatic recovery');

      recovering = true;

      // Take a pre-recovery snapshot (best effort — the DB is already damaged)
      try {
        if (backupModule) {
          const snap = await backupModule.createBackup();
          log.warn({ filename: snap.filename }, 'Pre-recovery snapshot saved (may be corrupt)');
        }
      } catch (_) { /* ignore */ }

      const recovery = await attemptRecovery(log, backupModule);

      if (recovery.recovered) {
        log.info({ backup: recovery.backup },
          'Automatic recovery succeeded — the server should be restarted to reload the database');
      } else {
        log.fatal({ reason: recovery.reason },
          'AUTOMATIC RECOVERY FAILED — manual intervention required');
      }

      recovering = false;
    } catch (err) {
      recovering = false;
      log.error({ err }, 'Integrity check job error');
    }
  };

  // Run WAL checkpoint immediately, integrity check after a short delay
  walJob();
  setTimeout(integrityJob, 5000);

  const walTimer = setInterval(walJob, opts.checkpointMinutes * 60 * 1000);
  const integrityTimer = setInterval(integrityJob, opts.integrityMinutes * 60 * 1000);
  walTimer.unref();
  integrityTimer.unref();

  log.info({
    checkpointIntervalMin: opts.checkpointMinutes,
    integrityIntervalMin: opts.integrityMinutes,
  }, 'Database health monitor started (WAL checkpoint + integrity check)');

  return {
    stop() {
      clearInterval(walTimer);
      clearInterval(integrityTimer);
    },
    checkpointWAL,
    runIntegrityCheck,
  };
}

module.exports.checkpointWAL = checkpointWAL;
module.exports.runIntegrityCheck = runIntegrityCheck;
module.exports.startHealthMonitor = startHealthMonitor;
