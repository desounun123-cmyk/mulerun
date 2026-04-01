'use strict';

/**
 * Database migration runner with version tracking.
 *
 * Manages schema changes through numbered migration files in the
 * `migrations/` directory.  Each migration exports:
 *
 *   module.exports = {
 *     version:     1,                  // unique integer, run in ascending order
 *     name:        'initial_schema',   // human-readable label (logged)
 *     up(db, engine) { ... },          // apply the migration
 *     down(db, engine) { ... },        // revert the migration (best-effort)
 *   };
 *
 * The `engine` parameter is 'sqlite' or 'postgresql' so migrations can
 * use dialect-specific SQL when needed.
 *
 * On each server start, `runMigrations(db)` will:
 *   1. Create the `schema_migrations` table if it doesn't exist
 *   2. Load all migration files from `migrations/`
 *   3. Skip any that have already been applied (tracked by version number)
 *   4. Run unapplied migrations in ascending version order inside transactions
 *   5. Record each successful migration with a timestamp
 *
 * Rollbacks are manual: call `rollback(db, targetVersion)` to revert
 * down to (but not including) the target version.
 */

const fs = require('fs');
const path = require('path');

const MIGRATIONS_DIR = path.join(__dirname, 'migrations');
const TABLE = 'schema_migrations';

let _log = null;

function getLog() {
  if (!_log) {
    try {
      _log = require('../utils/logger').child({ module: 'migrate' });
    } catch (_) {
      // Fallback for standalone usage (e.g., CLI scripts)
      _log = {
        info: console.log,
        warn: console.warn,
        error: console.error,
      };
    }
  }
  return _log;
}

/**
 * Ensure the schema_migrations tracking table exists.
 */
function ensureTable(db, engine) {
  if (engine === 'postgresql') {
    db.exec(`
      CREATE TABLE IF NOT EXISTS ${TABLE} (
        version   INTEGER PRIMARY KEY,
        name      TEXT NOT NULL,
        applied_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
    `);
  } else {
    db.exec(`
      CREATE TABLE IF NOT EXISTS ${TABLE} (
        version    INTEGER PRIMARY KEY,
        name       TEXT NOT NULL,
        applied_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);
  }
}

/**
 * Return a Set of version numbers that have already been applied.
 */
function getAppliedVersions(db) {
  const rows = db.prepare(`SELECT version FROM ${TABLE} ORDER BY version`).all();
  return new Set(rows.map(r => r.version));
}

/**
 * Load and sort migration files from the migrations directory.
 * Files must match the pattern NNN_name.js (e.g., 001_initial_schema.js).
 */
function loadMigrations() {
  if (!fs.existsSync(MIGRATIONS_DIR)) {
    return [];
  }

  const files = fs.readdirSync(MIGRATIONS_DIR)
    .filter(f => /^\d{3}_.*\.js$/.test(f))
    .sort(); // lexicographic sort works because of zero-padded numbers

  return files.map(f => {
    const mod = require(path.join(MIGRATIONS_DIR, f));
    if (!mod.version || !mod.name || !mod.up) {
      throw new Error(`Invalid migration file ${f}: must export { version, name, up }`);
    }
    return { ...mod, file: f };
  });
}

/**
 * Run all pending migrations in ascending version order.
 *
 * @param {object} db      Database instance (better-sqlite3 or pg adapter)
 * @param {object} [opts]
 * @param {string} [opts.engine]  'sqlite' or 'postgresql' (auto-detected from db._engine)
 * @returns {{ applied: number[], current: number }}
 */
function runMigrations(db, opts) {
  const log = getLog();
  const engine = (opts && opts.engine) || db._engine || 'sqlite';

  ensureTable(db, engine);

  const applied = getAppliedVersions(db);
  const migrations = loadMigrations();
  const newlyApplied = [];

  for (const m of migrations) {
    if (applied.has(m.version)) continue;

    log.info({ version: m.version, name: m.name, file: m.file }, 'Applying migration');

    // Run inside a transaction for atomicity
    const applyMigration = db.transaction(() => {
      m.up(db, engine);
      db.prepare(
        `INSERT INTO ${TABLE} (version, name) VALUES (?, ?)`
      ).run(m.version, m.name);
    });

    try {
      applyMigration();
      newlyApplied.push(m.version);
      log.info({ version: m.version, name: m.name }, 'Migration applied successfully');
    } catch (err) {
      log.error({ err, version: m.version, name: m.name }, 'Migration failed — aborting');
      throw err; // Stop on first failure — don't skip broken migrations
    }
  }

  const allApplied = [...applied, ...newlyApplied].sort((a, b) => a - b);
  const current = allApplied.length > 0 ? allApplied[allApplied.length - 1] : 0;

  if (newlyApplied.length > 0) {
    log.info({ applied: newlyApplied, current }, 'Migrations complete');
  } else {
    log.info({ current }, 'Schema up to date — no migrations to apply');
  }

  return { applied: newlyApplied, current };
}

/**
 * Rollback migrations down to (but not including) the target version.
 * Runs `down()` in descending order for each migration above targetVersion.
 *
 * @param {object} db
 * @param {number} targetVersion  Roll back to this version (0 = roll back everything)
 * @param {object} [opts]
 * @returns {{ reverted: number[] }}
 */
function rollback(db, targetVersion, opts) {
  const log = getLog();
  const engine = (opts && opts.engine) || db._engine || 'sqlite';

  ensureTable(db, engine);

  const applied = getAppliedVersions(db);
  const migrations = loadMigrations().reverse(); // descending order
  const reverted = [];

  for (const m of migrations) {
    if (m.version <= targetVersion) continue;
    if (!applied.has(m.version)) continue;

    if (!m.down) {
      log.error({ version: m.version, name: m.name }, 'Migration has no down() — cannot rollback');
      throw new Error(`Migration ${m.version} (${m.name}) has no down() function`);
    }

    log.info({ version: m.version, name: m.name }, 'Reverting migration');

    const revertMigration = db.transaction(() => {
      m.down(db, engine);
      db.prepare(`DELETE FROM ${TABLE} WHERE version = ?`).run(m.version);
    });

    try {
      revertMigration();
      reverted.push(m.version);
      log.info({ version: m.version, name: m.name }, 'Migration reverted successfully');
    } catch (err) {
      log.error({ err, version: m.version, name: m.name }, 'Rollback failed — aborting');
      throw err;
    }
  }

  log.info({ reverted, targetVersion }, 'Rollback complete');
  return { reverted };
}

/**
 * Get the current migration status.
 *
 * @param {object} db
 * @returns {{ current: number, applied: object[], pending: object[] }}
 */
function status(db) {
  const engine = db._engine || 'sqlite';
  ensureTable(db, engine);

  const appliedRows = db.prepare(
    `SELECT version, name, applied_at FROM ${TABLE} ORDER BY version`
  ).all();
  const appliedSet = new Set(appliedRows.map(r => r.version));
  const migrations = loadMigrations();

  const pending = migrations.filter(m => !appliedSet.has(m.version))
    .map(m => ({ version: m.version, name: m.name, file: m.file }));

  const current = appliedRows.length > 0
    ? appliedRows[appliedRows.length - 1].version
    : 0;

  return { current, applied: appliedRows, pending };
}

module.exports = { runMigrations, rollback, status };
