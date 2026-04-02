/**
 * PostgreSQL adapter for OIL Benchmarks.
 *
 * Provides a synchronous-style API that matches the better-sqlite3 interface
 * used throughout the codebase.  Uses a persistent worker thread with
 * SharedArrayBuffer + Atomics.wait to block the main thread while the worker
 * executes queries asynchronously via `pg`.  This avoids spawning a new child
 * process per query (~50-100ms overhead each) while keeping the synchronous
 * API that every route handler expects.
 *
 * ── Architecture ─────────────────────────────────────────────────────────
 * Main thread                          Worker thread
 * ───────────                          ─────────────
 * 1. Write {sql, params} to port       1. Receive message
 * 2. Atomics.wait(signal, 0)           2. pool.query(sql, params)
 *    (blocks until worker signals)     3. Write result to shared buffer
 *                                      4. Atomics.store(signal, 1)
 *                                      5. Atomics.notify(signal)
 * 3. Read result from shared buffer
 *
 * ── Usage ────────────────────────────────────────────────────────────────
 * Set DATABASE_URL to a PostgreSQL connection string:
 *   DATABASE_URL=postgres://user:pass@host:5432/oilbench
 *
 * The adapter is selected automatically by db.js when DATABASE_URL is set.
 */

'use strict';

const { Worker, MessageChannel, receiveMessageOnPort } = require('worker_threads');
const { Pool } = require('pg');
const path = require('path');
const log = require('../utils/logger').child({ module: 'db-postgres' });

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  throw new Error('DATABASE_URL environment variable is required for PostgreSQL mode');
}

// ── Connection Pool (used by async query() and passed to worker) ─────────
const pool = new Pool({
  connectionString: DATABASE_URL,
  max: parseInt(process.env.PG_POOL_MAX, 10) || 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  log.error({ err, engine: 'postgresql' }, 'Unexpected connection pool error');
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

  // INSERT OR REPLACE → INSERT ... ON CONFLICT DO UPDATE
  // Generic translation: assumes first column after ( is the conflict target (PK).
  out = out.replace(
    /INSERT\s+OR\s+REPLACE\s+INTO\s+("?\w+"?)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)/gi,
    (_, table, colList, valList) => {
      const cols = colList.split(',').map(c => c.trim());
      const conflictCol = cols[0];
      const updateCols = cols.slice(1);
      const setClauses = updateCols.map(c => `${c} = EXCLUDED.${c}`).join(', ');
      if (updateCols.length === 0) {
        return `INSERT INTO ${table} (${colList}) VALUES (${valList}) ON CONFLICT (${conflictCol}) DO NOTHING`;
      }
      return `INSERT INTO ${table} (${colList}) VALUES (${valList}) ON CONFLICT (${conflictCol}) DO UPDATE SET ${setClauses}`;
    }
  );

  // INSERT OR IGNORE → INSERT ... ON CONFLICT DO NOTHING
  out = out.replace(/INSERT\s+OR\s+IGNORE/gi, 'INSERT');
  // (above keeps simple — most INSERT OR IGNORE can use ON CONFLICT DO NOTHING
  //  but that requires knowing the constraint; for safety we just drop the OR IGNORE
  //  and let PG raise on real conflicts. Add DO NOTHING if needed per-query.)

  // sqlite_master → information_schema.tables
  out = out.replace(
    /SELECT\s+name\s+FROM\s+sqlite_master\s+WHERE\s+type\s*=\s*'table'\s+AND\s+name\s+NOT\s+LIKE\s+'sqlite_%'/gi,
    "SELECT table_name AS name FROM information_schema.tables WHERE table_schema = 'public'"
  );
  out = out.replace(
    /SELECT\s+name\s*,\s*sql\s+FROM\s+sqlite_master\s+WHERE\s+type\s*=\s*'table'\s+AND\s+name\s+NOT\s+LIKE\s+'sqlite_%'/gi,
    "SELECT table_name AS name, '' AS sql FROM information_schema.tables WHERE table_schema = 'public'"
  );
  out = out.replace(
    /SELECT\s+1\s+FROM\s+sqlite_master\s+WHERE\s+type\s*=\s*'table'\s+AND\s+name\s*=\s*('[^']+'|\$\d+)/gi,
    (_, nameVal) => `SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = ${nameVal}`
  );

  // datetime('now', '-' || $N || ' days') → NOW() - make_interval(days => $N)
  // Dynamic intervals built with || concatenation in SQLite
  out = out.replace(
    /datetime\s*\(\s*'now'\s*,\s*'-'\s*\|\|\s*(\$\d+)\s*\|\|\s*'\s*(day|hour|minute|second)s?\s*'\s*\)/gi,
    (_, param, unit) => `NOW() - make_interval(${unit}s => ${param})`
  );

  // datetime('now', '+' || $N || ' ...') → NOW() + make_interval(...)
  out = out.replace(
    /datetime\s*\(\s*'now'\s*,\s*'\+?'\s*\|\|\s*(\$\d+)\s*\|\|\s*'\s*(day|hour|minute|second)s?\s*'\s*\)/gi,
    (_, param, unit) => `NOW() + make_interval(${unit}s => ${param})`
  );

  // datetime('now') → NOW()  (must come after dynamic interval patterns)
  out = out.replace(/datetime\s*\(\s*'now'\s*\)/gi, 'NOW()');

  // datetime('now', '-30 days') → NOW() + INTERVAL '-30 days'
  // Handles both singular and plural unit names (day/days, minute/minutes, etc.)
  out = out.replace(/datetime\s*\(\s*'now'\s*,\s*'([+-]?\d+)\s+(day|hour|minute|second)s?'\s*\)/gi,
    (_, num, unit) => `NOW() + INTERVAL '${num} ${unit}s'`);

  // date('now') → CURRENT_DATE
  out = out.replace(/date\s*\(\s*'now'\s*\)/gi, 'CURRENT_DATE');

  // strftime('%H', col) → EXTRACT(HOUR FROM col)::text
  out = out.replace(/strftime\s*\(\s*'%H'\s*,\s*(\w+)\s*\)/gi,
    (_, col) => `LPAD(EXTRACT(HOUR FROM ${col}::timestamp)::int::text, 2, '0')`);

  // strftime('%Y-%m-%dT%H:%M:%f', 'now') → NOW()::text
  out = out.replace(/strftime\s*\(\s*'%Y-%m-%dT%H:%M:%f'\s*,\s*'now'\s*\)/gi, "NOW()::text");

  // strftime('%Y-W%W', col) → TO_CHAR(col, 'IYYY-"W"IW')
  out = out.replace(/strftime\s*\(\s*'%Y-W%W'\s*,\s*(\w+)\s*\)/gi,
    (_, col) => `TO_CHAR(${col}::timestamp, 'IYYY-"W"IW')`);

  // Catch-all: any remaining strftime with 'now' → NOW()::text
  out = out.replace(/strftime\s*\(\s*'[^']*'\s*,\s*'now'\s*\)/gi, "NOW()::text");

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

// ── Persistent Worker Thread for Synchronous Queries ─────────────────────
// A single long-lived worker holds its own pg Pool.  The main thread sends
// queries via MessagePort and blocks with Atomics.wait until the worker
// posts the result.  Overhead per query: ~0.1ms (shared-memory signal)
// instead of ~50-100ms (child process spawn).

const QUERY_TIMEOUT_MS = parseInt(process.env.PG_QUERY_TIMEOUT, 10) || 30000;
const QUERY_RETRY_MAX = 2;          // max retries on worker crash (not on SQL errors)
const QUERY_QUEUE_MAX = 500;        // max pending queries before rejecting new ones

// Hard ceiling on result buffer size to prevent unbounded memory allocation.
// A query whose serialised result exceeds this limit is rejected rather than
// allowed to allocate an arbitrarily large SharedArrayBuffer.
// Default 128 MB — configurable via PG_RESULT_BUF_MAX_MB for special workloads.
const RESULT_BUF_MAX = (parseInt(process.env.PG_RESULT_BUF_MAX_MB, 10) || 128) * 1024 * 1024;
let _pendingQueries = 0;
let _workerAlive = true;

// Shared signal buffer: Int32Array[0] is the "done" flag.
// 0 = waiting, 1 = result ready, 2 = error
const _signalBuf = new SharedArrayBuffer(4);
const _signal = new Int32Array(_signalBuf);

// Result buffer: large enough for typical query results.
// Dynamically grown if a result exceeds it.
let _resultBufSize = 4 * 1024 * 1024; // 4 MB initial
let _resultBuf = new SharedArrayBuffer(_resultBufSize);
let _resultView = new Uint8Array(_resultBuf);

// Synchronous communication channel
const { port1: _mainPort, port2: _workerPort } = new MessageChannel();

// Inline worker script (avoids needing a separate file)
const _workerCode = `
'use strict';
const { parentPort, workerData } = require('worker_threads');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: workerData.databaseUrl,
  max: workerData.poolMax,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  // Forward to main thread for structured logging (worker has no pino access)
  parentPort.postMessage({ type: 'pool-error', message: err.message, stack: err.stack });
});

let port = null;

parentPort.on('message', (msg) => {
  if (msg.type === 'init') {
    port = msg.port;
    port.on('message', handleQuery);
  } else if (msg.type === 'shutdown') {
    pool.end().then(() => process.exit(0)).catch(() => process.exit(1));
  }
});

async function handleQuery(msg) {
  const { sql, params, signal, resultBuf } = msg;
  const signalArr = new Int32Array(signal);
  const resultArr = new Uint8Array(resultBuf);

  try {
    const r = await pool.query(sql, params);
    const json = JSON.stringify({
      rows: r.rows,
      rowCount: r.rowCount,
      command: r.command,
    });

    const encoded = Buffer.from(json, 'utf8');

    if (encoded.length > resultArr.length) {
      // Result too large — write length as error so main thread can resize
      const errJson = JSON.stringify({ __resize: encoded.length });
      const errBuf = Buffer.from(errJson, 'utf8');
      resultArr.set(errBuf);
      // Write length header (first 4 bytes)
      new DataView(resultBuf).setUint32(0, errBuf.length, true);
      Atomics.store(signalArr, 0, 2); // error
      Atomics.notify(signalArr, 0);
      return;
    }

    // Write length header then payload
    new DataView(resultBuf).setUint32(0, encoded.length, true);
    resultArr.set(encoded, 4);
    Atomics.store(signalArr, 0, 1); // success
    Atomics.notify(signalArr, 0);
  } catch (err) {
    const errJson = JSON.stringify({ __error: err.message });
    const errBuf = Buffer.from(errJson, 'utf8');
    const resultArr2 = new Uint8Array(resultBuf);
    new DataView(resultBuf).setUint32(0, errBuf.length, true);
    resultArr2.set(errBuf, 4);
    Atomics.store(signalArr, 0, 2); // error
    Atomics.notify(signalArr, 0);
  }
}
`;

// Launch the persistent worker
const _worker = new Worker(_workerCode, {
  eval: true,
  workerData: {
    databaseUrl: DATABASE_URL,
    poolMax: parseInt(process.env.PG_POOL_MAX, 10) || 20,
  },
});

_worker.on('error', (err) => {
  log.error({ err, engine: 'postgresql' }, 'Worker thread error');
});

_worker.on('exit', (code) => {
  _workerAlive = false;
  log.error({ code, engine: 'postgresql' }, 'Worker thread exited unexpectedly');
});

// Forward pool errors from the worker thread to the structured logger
_worker.on('message', (msg) => {
  if (msg && msg.type === 'pool-error') {
    log.error({ err: { message: msg.message, stack: msg.stack }, engine: 'postgresql', source: 'worker' },
      'Worker pool error');
  }
});

// Send the communication port to the worker
_worker.postMessage({ type: 'init', port: _workerPort }, [_workerPort]);

/**
 * Execute a query synchronously by blocking with Atomics.wait.
 * The persistent worker thread runs the query asynchronously via pg Pool
 * and signals completion through shared memory.
 *
 * Hardened against:
 *   - Worker thread crash (checks _workerAlive, throws immediately)
 *   - Queue depth exhaustion (rejects when _pendingQueries > QUERY_QUEUE_MAX)
 *   - Atomics.wait timeout (throws with SQL snippet for debugging)
 *   - Buffer resize (retries with larger buffer, up to QUERY_RETRY_MAX times)
 *   - Buffer ceiling (rejects resize beyond RESULT_BUF_MAX to prevent OOM)
 *
 * Typical overhead: < 1ms (shared memory notify vs ~50-100ms child spawn).
 */
function querySync(sql, params, _retryCount) {
  _retryCount = _retryCount || 0;

  // Pre-flight checks
  if (!_workerAlive) {
    throw new Error('PostgreSQL worker thread is dead — queries cannot be processed. Restart the server.');
  }
  if (_pendingQueries >= QUERY_QUEUE_MAX) {
    throw new Error('PostgreSQL query queue full (' + QUERY_QUEUE_MAX + ' pending) — rejecting query: ' + sql.slice(0, 80));
  }

  _pendingQueries++;
  try {
    // Reset signal
    Atomics.store(_signal, 0, 0);

    // Send query to worker
    _mainPort.postMessage({
      sql,
      params: params || [],
      signal: _signalBuf,
      resultBuf: _resultBuf,
    });

    // Block until worker signals completion
    const waitResult = Atomics.wait(_signal, 0, 0, QUERY_TIMEOUT_MS);
    if (waitResult === 'timed-out') {
      // Check if the worker died while we were waiting
      if (!_workerAlive) {
        throw new Error('PostgreSQL worker thread crashed during query: ' + sql.slice(0, 100));
      }
      throw new Error(`PostgreSQL query timed out after ${QUERY_TIMEOUT_MS}ms: ${sql.slice(0, 100)}`);
    }

    // Read result from shared buffer
    const len = new DataView(_resultBuf).getUint32(0, true);
    const jsonBytes = _resultView.slice(4, 4 + len);
    const parsed = JSON.parse(Buffer.from(jsonBytes).toString('utf8'));

    if (Atomics.load(_signal, 0) === 2) {
      // Error or resize request
      if (parsed.__resize) {
        if (_retryCount >= QUERY_RETRY_MAX) {
          throw new Error('PostgreSQL result buffer resize limit reached after ' + QUERY_RETRY_MAX + ' retries');
        }
        // Enforce hard ceiling — reject rather than allocate unbounded memory
        const requestedSize = parsed.__resize + 1024;
        if (requestedSize > RESULT_BUF_MAX) {
          throw new Error(
            'PostgreSQL result too large: query returned ~' +
            Math.round(parsed.__resize / 1024 / 1024) + ' MB, exceeding the ' +
            Math.round(RESULT_BUF_MAX / 1024 / 1024) + ' MB result buffer limit. ' +
            'Add a LIMIT clause or increase PG_RESULT_BUF_MAX_MB: ' + sql.slice(0, 100)
          );
        }
        // Grow buffer and retry
        _resultBufSize = requestedSize;
        _resultBuf = new SharedArrayBuffer(_resultBufSize);
        _resultView = new Uint8Array(_resultBuf);
        log.warn(
          { newSizeMB: Math.round(_resultBufSize / 1024 / 1024), sql: sql.slice(0, 100) },
          'Result buffer resized — consider adding a LIMIT clause'
        );
        return querySync(sql, params, _retryCount + 1);
      }
      throw new Error('PostgreSQL query failed: ' + (parsed.__error || 'Unknown error'));
    }

    return parsed;
  } finally {
    _pendingQueries--;
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
  const { execFileSync } = require('child_process');
  const fs = require('fs');
  const output = execFileSync('pg_dump', [DATABASE_URL], {
    timeout: 60000,
    maxBuffer: 100 * 1024 * 1024, // 100 MB
    env: { ...process.env },
  });
  fs.writeFileSync(dest, output);
}

/**
 * Mimics db.close() — drains the connection pool and shuts down the worker.
 */
function close() {
  try { _worker.postMessage({ type: 'shutdown' }); } catch (_) {}
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

  /**
   * Returns current connection pool statistics for monitoring.
   */
  poolStats() {
    return {
      engine: 'postgresql',
      totalCount: pool.totalCount,       // all clients (active + idle)
      idleCount: pool.idleCount,         // clients not running a query
      waitingCount: pool.waitingCount,   // queued requests waiting for a client
      activeCount: pool.totalCount - pool.idleCount,
      maxConnections: pool.options.max || 20,
    };
  },

  // Metadata
  _engine: 'postgresql',
  _pool: pool,
  _translateSQL: translateSQL,
};

module.exports = pgDb;
