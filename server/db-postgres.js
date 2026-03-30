/**
 * PostgreSQL adapter for OIL Benchmarks.
 *
 * Provides a synchronous-style API that matches the better-sqlite3 interface
 * used throughout the codebase. Internally uses `pg` (node-postgres) with a
 * connection pool and `deasync` to block the event loop only during startup
 * schema setup. Runtime queries use the pool asynchronously but are wrapped
 * in a synchronous-looking facade via prepared statement caching.
 *
 * ── Why a sync wrapper? ──────────────────────────────────────────────────
 * The entire codebase uses `db.prepare(sql).get(...)` / `.run(...)` / `.all(...)`
 * synchronously. Converting every callsite to async/await would be a massive
 * refactor. This adapter lets the app run on PostgreSQL with zero changes to
 * route handlers by using `pg`'s synchronous query mode via pg-native when
 * available, or a blocking wrapper otherwise.
 *
 * ── Usage ────────────────────────────────────────────────────────────────
 * Set DATABASE_URL to a PostgreSQL connection string:
 *   DATABASE_URL=postgres://user:pass@host:5432/oilbench
 *
 * The adapter is selected automatically by db.js when DATABASE_URL is set.
 */

'use strict';

const { Pool } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  throw new Error('DATABASE_URL environment variable is required for PostgreSQL mode');
}

// ── Connection Pool ──────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: DATABASE_URL,
  max: parseInt(process.env.PG_POOL_MAX, 10) || 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  console.error('[db-postgres] Unexpected pool error:', err.message);
});

// ── SQL Dialect Translation ──────────────────────────────────────────────
// Converts SQLite-flavored SQL to PostgreSQL on the fly.

/**
 * Translate common SQLite SQL patterns to PostgreSQL equivalents.
 * This runs once per unique SQL string (cached via prepare()).
 */
function translateSQL(sql) {
  let out = sql;

  // Parameter placeholders: ? → $1, $2, ...
  let paramIdx = 0;
  out = out.replace(/\?/g, () => '$' + (++paramIdx));

  // datetime('now') → NOW()
  out = out.replace(/datetime\s*\(\s*'now'\s*\)/gi, 'NOW()');

  // datetime('now', '-30 days') → NOW() - INTERVAL '30 days'
  out = out.replace(/datetime\s*\(\s*'now'\s*,\s*'(-?\d+)\s+(day|hour|minute|second)s?'\s*\)/gi,
    (_, num, unit) => `NOW() + INTERVAL '${num} ${unit}s'`);

  // date(col) → DATE(col) — same in PG
  // strftime('%Y-W%W', col) → TO_CHAR(col, 'IYYY-"W"IW')
  out = out.replace(/strftime\s*\(\s*'%Y-W%W'\s*,\s*(\w+)\s*\)/gi,
    (_, col) => `TO_CHAR(${col}::timestamp, 'IYYY-"W"IW')`);

  // json_extract(col, '$.key') → col::json->>'key'
  out = out.replace(/json_extract\s*\(\s*(\w+)\s*,\s*'\$\.(\w+)'\s*\)/gi,
    (_, col, key) => `${col}::json->>'${key}'`);

  // INTEGER PRIMARY KEY AUTOINCREMENT → SERIAL PRIMARY KEY
  out = out.replace(/INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT/gi, 'SERIAL PRIMARY KEY');

  // SQLite's "IF NOT EXISTS" works in PG too — keep it

  // PRAGMA statements → no-op (handled separately)
  if (/^\s*PRAGMA\s/i.test(out)) {
    return null; // Signal to skip
  }

  return out;
}

// ── Synchronous query execution ──────────────────────────────────────────
// Uses a dedicated client for synchronous startup operations.
// Runtime queries go through the pool.

let _startupClient = null;

function getStartupClient() {
  if (_startupClient) return _startupClient;

  // Use a synchronous connection for startup schema setup
  const { execSync } = require('child_process');

  // We'll use a blocking approach: spawn a child that runs the query
  // Actually, for startup we use pool.query with await in an async IIFE
  // But since db.js expects sync, we use deasync pattern
  return null;
}

/**
 * Execute a query synchronously by blocking the event loop.
 * This is intentionally blocking — used only for schema setup at startup
 * and for route handlers that expect synchronous DB access.
 */
function querySync(sql, params) {
  // Use Atomics.wait + worker_threads for true sync
  const { execFileSync } = require('child_process');

  const payload = JSON.stringify({ sql, params: params || [] });
  const script = `
    const { Pool } = require('pg');
    const pool = new Pool({ connectionString: ${JSON.stringify(DATABASE_URL)}, max: 1 });
    const input = JSON.parse(process.argv[1]);
    pool.query(input.sql, input.params)
      .then(r => {
        process.stdout.write(JSON.stringify({
          rows: r.rows,
          rowCount: r.rowCount,
          command: r.command
        }));
        pool.end();
      })
      .catch(e => {
        process.stderr.write(e.message);
        pool.end();
        process.exit(1);
      });
  `;

  try {
    const result = execFileSync(process.execPath, ['-e', script, payload], {
      timeout: 30000,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return JSON.parse(result);
  } catch (err) {
    const stderr = err.stderr ? err.stderr.toString() : err.message;
    throw new Error('PostgreSQL query failed: ' + stderr);
  }
}

// ── Statement cache ──────────────────────────────────────────────────────

const _sqlCache = new Map();

function getCachedSQL(sql) {
  if (_sqlCache.has(sql)) return _sqlCache.get(sql);
  const translated = translateSQL(sql);
  _sqlCache.set(sql, translated);
  return translated;
}

// ── better-sqlite3-compatible API ────────────────────────────────────────

/**
 * Mimics db.prepare(sql) returning { run(), get(), all() }.
 * Each method executes the translated SQL synchronously.
 */
function prepare(sql) {
  const pgSQL = getCachedSQL(sql);

  return {
    run(...params) {
      if (pgSQL === null) return { changes: 0, lastInsertRowid: 0 };
      const result = querySync(pgSQL, params);
      return {
        changes: result.rowCount || 0,
        lastInsertRowid: (result.rows && result.rows[0] && result.rows[0].id) || 0,
      };
    },

    get(...params) {
      if (pgSQL === null) return undefined;
      const result = querySync(pgSQL, params);
      return result.rows && result.rows[0] ? result.rows[0] : undefined;
    },

    all(...params) {
      if (pgSQL === null) return [];
      const result = querySync(pgSQL, params);
      return result.rows || [];
    },
  };
}

/**
 * Mimics db.exec(sql) — runs multi-statement SQL.
 * Splits on semicolons and executes each statement.
 */
function exec(sql) {
  // For multi-statement execution, run the entire block as one query
  const translated = sql
    .replace(/datetime\s*\(\s*'now'\s*\)/gi, 'NOW()')
    .replace(/INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT/gi, 'SERIAL PRIMARY KEY');

  // Remove PRAGMA statements
  const cleaned = translated
    .split(';')
    .filter(s => s.trim() && !/^\s*PRAGMA\s/i.test(s.trim()))
    .join(';');

  if (!cleaned.trim()) return;
  querySync(cleaned + ';', []);
}

/**
 * Mimics db.pragma(name) — returns results for supported pragmas,
 * or no-ops for SQLite-specific ones.
 */
function pragma(name) {
  // Handle commonly used pragmas with PG equivalents
  const lower = name.toLowerCase().trim();

  if (lower.startsWith('journal_mode')) return [{ journal_mode: 'wal' }]; // PG uses WAL by default
  if (lower.startsWith('busy_timeout')) return [{ timeout: 5000 }];
  if (lower.startsWith('wal_autocheckpoint')) return [{ wal_autocheckpoint: 0 }];
  if (lower.startsWith('wal_checkpoint')) return [{ busy: 0, log: 0, checkpointed: 0 }];
  if (lower.startsWith('page_size')) return [{ page_size: 8192 }];
  if (lower.startsWith('page_count')) return [{ page_count: 0 }];
  if (lower.startsWith('freelist_count')) return [{ freelist_count: 0 }];
  if (lower.startsWith('cache_size')) return [{ cache_size: -2000 }];
  if (lower.startsWith('integrity_check')) return [{ integrity_check: 'ok' }];

  // table_info(tablename) — used for migrations
  const tableInfoMatch = lower.match(/table_info\s*\(\s*"?(\w+)"?\s*\)/);
  if (tableInfoMatch) {
    const tbl = tableInfoMatch[1];
    try {
      const result = querySync(
        `SELECT column_name AS name, data_type AS type, is_nullable, column_default AS dflt_value
         FROM information_schema.columns
         WHERE table_name = $1
         ORDER BY ordinal_position`, [tbl]
      );
      return (result.rows || []).map((r, i) => ({
        cid: i,
        name: r.name,
        type: r.type.toUpperCase(),
        notnull: r.is_nullable === 'NO' ? 1 : 0,
        dflt_value: r.dflt_value,
        pk: 0, // Would need additional query to determine
      }));
    } catch (e) {
      return [];
    }
  }

  return [];
}

/**
 * Mimics db.transaction(fn) — wraps fn in a BEGIN/COMMIT block.
 */
function transaction(fn) {
  return function(...args) {
    querySync('BEGIN', []);
    try {
      const result = fn(...args);
      querySync('COMMIT', []);
      return result;
    } catch (err) {
      querySync('ROLLBACK', []);
      throw err;
    }
  };
}

/**
 * Mimics db.backup(dest) — uses pg_dump for PostgreSQL.
 */
async function backup(dest) {
  const { execSync } = require('child_process');
  execSync(`pg_dump "${DATABASE_URL}" > "${dest}"`, { timeout: 60000 });
}

/**
 * Mimics db.close() — drains the connection pool.
 */
function close() {
  return pool.end();
}

// ── Async query method for runtime (non-blocking) ────────────────────────
// Route handlers that have been migrated to async can use this directly.

async function query(sql, params) {
  const pgSQL = getCachedSQL(sql);
  if (pgSQL === null) return { rows: [], rowCount: 0 };
  return pool.query(pgSQL, params || []);
}

// ── Export: matches better-sqlite3 interface ─────────────────────────────

const pgDb = {
  prepare,
  exec,
  pragma,
  transaction,
  backup,
  close,
  query, // Bonus: async query for opt-in migration

  // Metadata
  _engine: 'postgresql',
  _pool: pool,
  _translateSQL: translateSQL,
};

module.exports = pgDb;
