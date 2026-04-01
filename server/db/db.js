// ── Database Backend Selection ───────────────────────────────────
// When DATABASE_URL is set, use PostgreSQL. Otherwise use SQLite.
// The PostgreSQL adapter (db-postgres.js) exposes the same API as
// better-sqlite3 so no changes are needed in route handlers.
//
// To switch to PostgreSQL:
//   1. Set DATABASE_URL=postgres://user:pass@host:5432/oilbench
//   2. Run: node scripts/migrate-to-postgres.js
//   3. Import the generated SQL: psql -d oilbench -f pg-export/migration.sql
//   4. Restart the server
//
if (process.env.DATABASE_URL) {
  const pgDb = require('./db-postgres');
  module.exports = pgDb;

  // Run versioned migrations
  const { runMigrations } = require('./migrate');
  runMigrations(pgDb, { engine: 'postgresql' });

  // Seed demo users
  const bcrypt = require('bcryptjs');

  // Seed demo users (same as SQLite path)
  const existingDemo = pgDb.prepare('SELECT id FROM users WHERE email = $1').get('demo@oil.com');
  if (!existingDemo) {
    const hash = bcrypt.hashSync('oil2026oil2026', 10);
    const result = pgDb.prepare(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id'
    ).get('Demo', 'demo@oil.com', hash);
    if (result) {
      pgDb.prepare(
        'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode) VALUES ($1, TRUE, FALSE, TRUE)'
      ).run(result.id);
    }
  }

  const existingTest = pgDb.prepare('SELECT id FROM users WHERE email = $1').get('test@oil.com');
  if (!existingTest) {
    const testHash = bcrypt.hashSync('2026oil2026oil', 10);
    const testResult = pgDb.prepare(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id'
    ).get('Test', 'test@oil.com', testHash);
    if (testResult) {
      pgDb.prepare(
        'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode) VALUES ($1, TRUE, FALSE, TRUE)'
      ).run(testResult.id);
    }
  }

  const existingAdmin = pgDb.prepare('SELECT id FROM users WHERE email = $1').get('siteadmin@oil.com');
  if (!existingAdmin) {
    const adminHash = bcrypt.hashSync('nimdaetis123&', 10);
    const adminResult = pgDb.prepare(
      'INSERT INTO users (name, email, password_hash, plan) VALUES ($1, $2, $3, $4) RETURNING id'
    ).get('Admin', 'siteadmin@oil.com', adminHash, 'Admin');
    if (adminResult) {
      pgDb.prepare(
        'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode) VALUES ($1, TRUE, TRUE, TRUE)'
      ).run(adminResult.id);
    }
  } else {
    pgDb.prepare("UPDATE users SET plan = 'Admin', name = 'Admin' WHERE email = $1").run('siteadmin@oil.com');
  }

  // Export health stubs (PostgreSQL handles its own WAL/vacuum)
  module.exports.checkpointWAL = function() { return { busy: 0, log: 0, checkpointed: 0 }; };
  module.exports.runIntegrityCheck = function() { return { ok: true, errors: [] }; };
  module.exports.getWALStatus = function() {
    return {
      journalMode: 'wal', walFileSize: 0, walFileSizeKB: 0, shmFileSize: 0,
      dbFileSize: 0, dbFileSizeKB: 0, autoCheckpoint: 0, pageSize: 8192,
      pageCount: 0, freelistCount: 0, cacheSize: 0, busyTimeout: 0,
      engine: 'postgresql',
    };
  };
  module.exports.startHealthMonitor = function(log) {
    if (log) log.info('PostgreSQL mode — SQLite health monitor disabled (PG manages its own WAL)');
    return { stop() {}, checkpointWAL() { return { busy: 0, log: 0, checkpointed: 0 }; }, runIntegrityCheck() { return { ok: true, errors: [] }; } };
  };

  return; // Skip the rest of the file (SQLite setup)
}

// ══════════════════════════════════════════════════════════════════════════
// ── SQLite Backend (default) ─────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = process.env.DB_PATH
  ? require('path').resolve(process.env.DB_PATH)
  : path.join(__dirname, '..', 'data.db');

const db = new Database(DB_PATH);

// Enable WAL mode and busy timeout
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');

// Configurable WAL auto-checkpoint threshold (pages). Default: 1000 (~4 MB).
// Set to 0 to disable auto-checkpoint (manual/scheduled only).
const WAL_AUTOCHECKPOINT = parseInt(process.env.WAL_AUTOCHECKPOINT, 10);
if (!isNaN(WAL_AUTOCHECKPOINT)) {
  db.pragma('wal_autocheckpoint = ' + WAL_AUTOCHECKPOINT);
}

// ── Serialized Write Queue ──────────────────────────────────────
// SQLite WAL mode allows concurrent reads but only one writer at a time.
// Under heavy write load, busy_timeout alone leads to SQLITE_BUSY errors
// because multiple requests contend for the write lock simultaneously.
//
// This write queue serializes all write operations (INSERT, UPDATE, DELETE,
// CREATE, ALTER, DROP) through a FIFO queue so they execute one at a time,
// while reads bypass the queue entirely and run concurrently.
//
// Reads:  caller → db.prepare(sql).get/all()  → direct execution (no queue)
// Writes: caller → writeQueue → sequential execution → result/error

const _writeQueue = [];
let _writeBusy = false;

// Detect SQL that modifies the database (writes).
// better-sqlite3 .run() is typically used for writes, but .get()/.all() can
// also contain writes (e.g., INSERT...RETURNING).  We classify by SQL verb.
const _WRITE_RE = /^\s*(INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER|DROP|UPSERT|PRAGMA\s+\w+\s*=)/i;

function _isWriteSQL(sql) {
  return _WRITE_RE.test(sql);
}

function _drainWriteQueue() {
  if (_writeBusy || _writeQueue.length === 0) return;
  _writeBusy = true;

  const { fn, resolve, reject } = _writeQueue.shift();
  try {
    const result = fn();
    _writeBusy = false;
    resolve(result);
  } catch (err) {
    _writeBusy = false;
    reject(err);
  }

  // Drain next synchronously (we're already in a synchronous context)
  _drainWriteQueue();
}

/**
 * Execute a write operation through the serialized queue.
 * Because better-sqlite3 is synchronous, the queue processes items
 * back-to-back without yielding to the event loop (no async overhead).
 * The queue prevents overlapping write attempts from concurrent requests
 * that arrive in the same tick or during busy_timeout waits.
 */
function _enqueueWrite(fn) {
  // Optimization: if queue is empty and not busy, run directly.
  // This avoids any overhead for the common case (no contention).
  if (_writeQueue.length === 0 && !_writeBusy) {
    _writeBusy = true;
    try {
      const result = fn();
      _writeBusy = false;
      return result;
    } catch (err) {
      _writeBusy = false;
      throw err;
    }
  }

  // Contention: queue the write and drain synchronously.
  // Because better-sqlite3 is blocking, we can resolve synchronously.
  let result, error;
  _writeQueue.push({
    fn,
    resolve: (r) => { result = r; },
    reject: (e) => { error = e; },
  });
  _drainWriteQueue();
  if (error) throw error;
  return result;
}

// ── Wrap db.prepare to route writes through the queue ────────────
const _origPrepare = db.prepare.bind(db);

db.prepare = function(sql) {
  const stmt = _origPrepare(sql);
  const isWrite = _isWriteSQL(sql);

  if (!isWrite) {
    // Read statement — return as-is, no queue overhead
    return stmt;
  }

  // Write statement — wrap .run(), .get(), .all() through the write queue
  const origRun = stmt.run.bind(stmt);
  const origGet = stmt.get.bind(stmt);
  const origAll = stmt.all.bind(stmt);

  stmt.run = function(...params) {
    return _enqueueWrite(() => origRun(...params));
  };
  stmt.get = function(...params) {
    return _enqueueWrite(() => origGet(...params));
  };
  stmt.all = function(...params) {
    return _enqueueWrite(() => origAll(...params));
  };

  return stmt;
};

// ── Wrap db.exec for DDL and multi-statement writes ──────────────
const _origExec = db.exec.bind(db);

db.exec = function(sql) {
  if (_isWriteSQL(sql)) {
    return _enqueueWrite(() => _origExec(sql));
  }
  return _origExec(sql);
};

// ── Wrap db.transaction to serialize the entire transaction ──────
const _origTransaction = db.transaction.bind(db);

db.transaction = function(fn) {
  const txFn = _origTransaction(fn);
  return function(...args) {
    return _enqueueWrite(() => txFn(...args));
  };
};

// ── Run versioned migrations ─────────────────────────────────────
const { runMigrations } = require('./migrate');
runMigrations(db, { engine: 'sqlite' });

// Seed demo user if not present
const existingDemo = db.prepare('SELECT id FROM users WHERE email = ?').get('demo@oil.com');
if (!existingDemo) {
  const hash = bcrypt.hashSync('oil2026oil2026', 10);
  const result = db.prepare(
    'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)'
  ).run('Demo', 'demo@oil.com', hash);

  db.prepare(
    'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode) VALUES (?, TRUE, FALSE, TRUE)'
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
    'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode) VALUES (?, TRUE, FALSE, TRUE)'
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
    'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode) VALUES (?, TRUE, TRUE, TRUE)'
  ).run(adminResult.lastInsertRowid);
} else {
  db.prepare("UPDATE users SET plan = 'Admin', name = 'Admin' WHERE email = 'siteadmin@oil.com'").run();
}

db._engine = 'sqlite';

/**
 * Returns database stats for monitoring.
 * SQLite has no connection pool, so returns static values.
 */
db.poolStats = function() {
  return {
    engine: 'sqlite',
    totalCount: 1,
    idleCount: 1,
    waitingCount: _writeQueue.length,
    activeCount: _writeBusy ? 1 : 0,
    maxConnections: 1,
  };
};

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
 * Get detailed WAL status and database metrics.
 *
 * Returns:
 *   journalMode      — current journal mode (should be 'wal')
 *   walFileSize       — WAL file size in bytes (0 if no WAL file)
 *   walFileSizeKB     — WAL file size in KB (rounded)
 *   dbFileSize        — main database file size in bytes
 *   dbFileSizeKB      — main database file size in KB (rounded)
 *   autoCheckpoint    — current wal_autocheckpoint threshold (pages)
 *   pageSize          — database page size in bytes
 *   pageCount         — total pages in the database
 *   freelistCount     — unused pages (fragmentation indicator)
 *   cacheSize         — cache_size pragma value
 *   busyTimeout       — current busy_timeout in ms
 */
function getWALStatus() {
  const fs = require('fs');
  const walPath = DB_PATH + '-wal';
  const shmPath = DB_PATH + '-shm';

  let walFileSize = 0;
  let shmFileSize = 0;
  try { walFileSize = fs.existsSync(walPath) ? fs.statSync(walPath).size : 0; } catch (_) {}
  try { shmFileSize = fs.existsSync(shmPath) ? fs.statSync(shmPath).size : 0; } catch (_) {}

  let dbFileSize = 0;
  try { dbFileSize = fs.statSync(DB_PATH).size; } catch (_) {}

  const journalMode = (db.pragma('journal_mode')[0] || {}).journal_mode || 'unknown';
  const autoCheckpoint = (db.pragma('wal_autocheckpoint')[0] || {}).wal_autocheckpoint;
  const pageSize = (db.pragma('page_size')[0] || {}).page_size || 4096;
  const pageCount = (db.pragma('page_count')[0] || {}).page_count || 0;
  const freelistCount = (db.pragma('freelist_count')[0] || {}).freelist_count || 0;
  const cacheSize = (db.pragma('cache_size')[0] || {}).cache_size || -2000;
  const busyTimeout = (db.pragma('busy_timeout')[0] || {}).timeout || 5000;

  return {
    journalMode,
    walFileSize,
    walFileSizeKB: +(walFileSize / 1024).toFixed(1),
    shmFileSize,
    dbFileSize,
    dbFileSizeKB: +(dbFileSize / 1024).toFixed(1),
    autoCheckpoint: autoCheckpoint != null ? autoCheckpoint : 1000,
    pageSize,
    pageCount,
    freelistCount,
    cacheSize,
    busyTimeout,
  };
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
module.exports.getWALStatus = getWALStatus;
module.exports.startHealthMonitor = startHealthMonitor;
