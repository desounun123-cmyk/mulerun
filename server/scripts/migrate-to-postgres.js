#!/usr/bin/env node
/**
 * SQLite → PostgreSQL data migration tool.
 *
 * Reads the live SQLite database (or a backup), introspects every table,
 * and generates a complete PostgreSQL-compatible migration bundle:
 *
 *   1. Schema DDL  — CREATE TABLE / INDEX statements translated from SQLite
 *   2. Data INSERT — batched multi-row INSERT statements for every row
 *   3. Sequences   — reset SERIAL sequences to MAX(id) + 1
 *
 * Output modes:
 *   --sql   (default) Write a single .sql file ready to pipe into psql
 *   --json  Write per-table JSON files (for programmatic import / COPY)
 *   --dry   Print summary without writing any files
 *
 * Usage:
 *   node scripts/migrate-to-postgres.js                     # export all tables
 *   node scripts/migrate-to-postgres.js --out ./pg-export   # custom output dir
 *   node scripts/migrate-to-postgres.js --db ./backups/x.db # use a backup file
 *   node scripts/migrate-to-postgres.js --tables users,user_settings  # subset
 *   node scripts/migrate-to-postgres.js --json              # JSON per table
 *   node scripts/migrate-to-postgres.js --dry               # dry-run summary
 *   node scripts/migrate-to-postgres.js --batch-size 500    # rows per INSERT
 *
 * The generated SQL is idempotent: tables use IF NOT EXISTS / DROP + CREATE
 * depending on the --drop flag. Foreign key constraints are deferred to the
 * end so table creation order does not matter.
 *
 * Environment:
 *   DB_PATH — path to the SQLite database (default: ./data.db)
 */

'use strict';

const path = require('path');
const fs = require('fs');

// ── Argument parsing ─────────────────────────────────────────────
const args = process.argv.slice(2);

function getArg(name, fallback) {
  const idx = args.indexOf('--' + name);
  if (idx === -1) return fallback;
  return args[idx + 1] || fallback;
}
function hasFlag(name) { return args.includes('--' + name); }

const DB_FILE = getArg('db',
  process.env.DB_PATH
    ? path.resolve(process.env.DB_PATH)
    : path.join(__dirname, '..', 'data.db')
);
const OUT_DIR     = path.resolve(getArg('out', path.join(__dirname, '..', 'pg-export')));
const BATCH_SIZE  = parseInt(getArg('batch-size', '200'), 10);
const MODE_JSON   = hasFlag('json');
const MODE_DRY    = hasFlag('dry');
const DROP_TABLES = hasFlag('drop');
const TABLE_FILTER = getArg('tables', '');

// Tables to skip (internal SQLite / session store / PITR internals)
const SKIP_TABLES = new Set([
  'sqlite_sequence',
  '_pitr_changelog',   // PITR is SQLite-specific; PG has its own WAL
  'sessions',          // session store will use connect-pg-simple
]);

// ── SQLite → PostgreSQL type mapping ─────────────────────────────

/**
 * Convert a SQLite column type to the closest PostgreSQL equivalent.
 * @param {boolean} isAutoIncrementPk — true only if the column is an
 *   INTEGER PRIMARY KEY on a table that uses AUTOINCREMENT.
 * @param {string}  dfltValue — the column's DEFAULT expression (for timestamp detection)
 */
function mapType(sqliteType, colName, isAutoIncrementPk, dfltValue) {
  const upper = (sqliteType || 'TEXT').toUpperCase().trim();

  // Only use SERIAL for true auto-increment PKs (not FK-based PKs like user_settings.user_id)
  if (isAutoIncrementPk && (upper === 'INTEGER' || upper === 'INT')) {
    return 'SERIAL';
  }

  // Detect timestamp columns: TEXT type with datetime('now') or strftime default,
  // or column names ending in _at / _until
  if (upper === 'TEXT') {
    const name = (colName || '').toLowerCase();
    const hasTimestampDefault = dfltValue && (/datetime\s*\(/i.test(dfltValue) || /strftime\s*\(/i.test(dfltValue));
    const hasTimestampName = name.endsWith('_at') || name.endsWith('_until') || name === 'expires'
      || name === 'last_login' || name === 'last_triggered_at' || name === 'locked_until';
    if (hasTimestampDefault || hasTimestampName) {
      return 'TIMESTAMP';
    }
  }

  if (upper === 'INTEGER' || upper === 'INT')     return 'INTEGER';
  if (upper === 'REAL' || upper === 'FLOAT' || upper === 'DOUBLE') return 'DOUBLE PRECISION';
  if (upper === 'BLOB')                           return 'BYTEA';
  if (upper.startsWith('VARCHAR'))                 return upper; // pass through
  if (upper.startsWith('CHAR'))                    return upper;
  if (upper === 'BOOLEAN')                         return 'BOOLEAN';
  // TEXT and anything else → TEXT
  return 'TEXT';
}

/**
 * Convert a SQLite DEFAULT expression to PostgreSQL syntax.
 */
function mapDefault(dflt, pgType) {
  if (dflt == null) return null;

  // SQLite datetime('now') → PG NOW()
  if (/datetime\s*\(\s*'now'\s*\)/i.test(dflt)) return 'NOW()';
  if (/strftime\s*\(/i.test(dflt)) return 'NOW()';

  // Boolean defaults: 0/1 → FALSE/TRUE when the column is BOOLEAN
  if (pgType === 'BOOLEAN') {
    if (dflt === '0') return 'FALSE';
    if (dflt === '1') return 'TRUE';
  }

  // Numeric defaults
  if (/^-?\d+(\.\d+)?$/.test(dflt)) return dflt;

  // String defaults
  if (/^'.*'$/.test(dflt)) return dflt;

  // Pass through anything else
  return dflt;
}

/**
 * Convert a SQLite CHECK constraint to PostgreSQL syntax.
 */
function mapCheck(sql) {
  if (!sql) return '';
  // Extract CHECK(...) clauses from the CREATE TABLE statement
  const checks = [];
  const re = /CHECK\s*\(([^)]+)\)/gi;
  let m;
  while ((m = re.exec(sql)) !== null) {
    checks.push('CHECK (' + m[1] + ')');
  }
  return checks.join(', ');
}

// ── SQLite value → PostgreSQL literal ────────────────────────────

function pgLiteral(val) {
  if (val === null || val === undefined) return 'NULL';
  if (typeof val === 'number') return String(val);
  if (typeof val === 'boolean') return val ? 'TRUE' : 'FALSE';
  if (Buffer.isBuffer(val)) return "E'\\\\x" + val.toString('hex') + "'";
  // Escape single quotes
  return "'" + String(val).replace(/'/g, "''") + "'";
}

// ══════════════════════════════════════════════════════════════════
// ── Main ─────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════

function main() {
  // Validate input
  if (!fs.existsSync(DB_FILE)) {
    console.error('ERROR: SQLite database not found: ' + DB_FILE);
    process.exit(1);
  }

  const Database = require('better-sqlite3');
  const db = new Database(DB_FILE, { readonly: true });

  console.log('SQLite → PostgreSQL Migration Tool');
  console.log('──────────────────────────────────');
  console.log('  Source : ' + DB_FILE);
  console.log('  Output : ' + (MODE_DRY ? '(dry run)' : OUT_DIR));
  console.log('  Mode   : ' + (MODE_JSON ? 'JSON' : 'SQL'));
  console.log('  Batch  : ' + BATCH_SIZE + ' rows/INSERT');
  console.log('');

  // ── Discover tables ────────────────────────────────────────────
  let tables = db.prepare(
    "SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
  ).all();

  // Filter out skipped tables
  tables = tables.filter(t => !SKIP_TABLES.has(t.name));

  // Apply user filter if specified
  if (TABLE_FILTER) {
    const allowed = new Set(TABLE_FILTER.split(',').map(s => s.trim()));
    tables = tables.filter(t => allowed.has(t.name));
  }

  if (tables.length === 0) {
    console.log('No tables to migrate.');
    db.close();
    return;
  }

  // ── Introspect each table ──────────────────────────────────────
  const tableSchemas = [];

  for (const tbl of tables) {
    const columns = db.prepare('PRAGMA table_info("' + tbl.name + '")').all();
    const fkeys   = db.prepare('PRAGMA foreign_key_list("' + tbl.name + '")').all();
    const indexes = db.prepare('PRAGMA index_list("' + tbl.name + '")').all();
    const rowCount = db.prepare('SELECT COUNT(*) AS cnt FROM "' + tbl.name + '"').get().cnt;

    // Get index details
    const indexDefs = [];
    for (const idx of indexes) {
      if (idx.origin === 'pk') continue; // skip auto PK indexes
      const idxCols = db.prepare('PRAGMA index_info("' + idx.name + '")').all();
      indexDefs.push({
        name: idx.name,
        unique: !!idx.unique,
        columns: idxCols.map(c => c.name),
      });
    }

    tableSchemas.push({
      name: tbl.name,
      sql: tbl.sql,
      columns,
      fkeys,
      indexes: indexDefs,
      rowCount,
    });
  }

  // ── Summary ────────────────────────────────────────────────────
  console.log('Tables to migrate:');
  let totalRows = 0;
  for (const s of tableSchemas) {
    console.log('  ' + s.name.padEnd(30) + s.rowCount.toLocaleString().padStart(8) + ' rows  (' + s.columns.length + ' cols)');
    totalRows += s.rowCount;
  }
  console.log('  ' + '─'.repeat(38));
  console.log('  ' + 'TOTAL'.padEnd(30) + totalRows.toLocaleString().padStart(8) + ' rows');
  console.log('');

  if (MODE_DRY) {
    console.log('Dry run — no files written.');
    db.close();
    return;
  }

  // ── Create output directory ────────────────────────────────────
  if (!fs.existsSync(OUT_DIR)) {
    fs.mkdirSync(OUT_DIR, { recursive: true });
  }

  if (MODE_JSON) {
    exportJSON(db, tableSchemas);
  } else {
    exportSQL(db, tableSchemas);
  }

  db.close();
  console.log('Done.');
}

// ══════════════════════════════════════════════════════════════════
// ── SQL export ───────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════

function exportSQL(db, tableSchemas) {
  const lines = [];

  lines.push('-- ══════════════════════════════════════════════════════════════');
  lines.push('-- Oil Benchmarks: SQLite → PostgreSQL migration');
  lines.push('-- Generated: ' + new Date().toISOString());
  lines.push('-- Source: ' + DB_FILE);
  lines.push('-- ══════════════════════════════════════════════════════════════');
  lines.push('');
  lines.push('BEGIN;');
  lines.push('');

  // Collect all FK constraints to add at the end (avoids ordering issues)
  const deferredFKs = [];
  const deferredIndexes = [];

  // ── Schema DDL ─────────────────────────────────────────────────
  for (const schema of tableSchemas) {
    if (DROP_TABLES) {
      lines.push('DROP TABLE IF EXISTS "' + schema.name + '" CASCADE;');
    }

    const colDefs = [];

    // Find primary key column(s)
    const pkCols = schema.columns.filter(c => c.pk > 0).sort((a, b) => a.pk - b.pk);
    const singlePk = pkCols.length === 1 ? pkCols[0].name : null;

    // Detect true AUTOINCREMENT: only the table's own auto-generated ID
    // (not FK-based PKs like user_settings.user_id which references users.id)
    const hasAutoIncrement = schema.sql && /AUTOINCREMENT/i.test(schema.sql);
    const hasFkOnPk = singlePk && schema.fkeys.some(f => f.from === singlePk);
    const isAutoIncrementPk = singlePk && hasAutoIncrement && !hasFkOnPk;

    for (const col of schema.columns) {
      const isPkAutoIncrement = col.name === singlePk && isAutoIncrementPk;
      let pgType = mapType(col.type, col.name, isPkAutoIncrement, col.dflt_value);

      // SQLite stores booleans as INTEGER; detect boolean-like columns
      if (pgType === 'INTEGER' && isBooleanColumn(col, schema)) {
        pgType = 'BOOLEAN';
      }

      let def = '  "' + col.name + '" ' + pgType;

      // NOT NULL (skip for SERIAL PKs — they're NOT NULL implicitly)
      if (col.notnull && pgType !== 'SERIAL') {
        def += ' NOT NULL';
      }

      // DEFAULT
      if (col.dflt_value != null) {
        const mapped = mapDefault(col.dflt_value, pgType);
        if (mapped != null) {
          def += ' DEFAULT ' + mapped;
        }
      }

      colDefs.push(def);
    }

    // Primary key constraint
    if (pkCols.length > 0) {
      if (singlePk && isAutoIncrementPk) {
        colDefs.push('  PRIMARY KEY ("' + singlePk + '")');
      } else {
        colDefs.push('  PRIMARY KEY (' + pkCols.map(c => '"' + c.name + '"').join(', ') + ')');
      }
    }

    // UNIQUE constraints from CREATE TABLE sql (inline UNIQUE)
    for (const col of schema.columns) {
      if (schema.sql && new RegExp('"?' + col.name + '"?\\s[^,]*\\bUNIQUE\\b', 'i').test(schema.sql)) {
        // Check it's not already covered by a named index
        const hasNamedUnique = schema.indexes.some(i => i.unique && i.columns.length === 1 && i.columns[0] === col.name);
        if (!hasNamedUnique) {
          colDefs.push('  UNIQUE ("' + col.name + '")');
        }
      }
    }

    // CHECK constraints from original SQL
    if (schema.sql) {
      const checkStr = mapCheck(schema.sql);
      if (checkStr) colDefs.push('  ' + checkStr);
    }

    lines.push('CREATE TABLE IF NOT EXISTS "' + schema.name + '" (');
    lines.push(colDefs.join(',\n'));
    lines.push(');');
    lines.push('');

    // Collect FK constraints
    if (schema.fkeys.length > 0) {
      // Group FKs by id (composite FKs share the same id)
      const fkGroups = {};
      for (const fk of schema.fkeys) {
        if (!fkGroups[fk.id]) fkGroups[fk.id] = [];
        fkGroups[fk.id].push(fk);
      }
      for (const fkId of Object.keys(fkGroups)) {
        const fks = fkGroups[fkId];
        const fromCols = fks.map(f => '"' + f.from + '"').join(', ');
        const toCols   = fks.map(f => '"' + f.to + '"').join(', ');
        let constraint = 'ALTER TABLE "' + schema.name + '" ADD FOREIGN KEY (' + fromCols + ') '
          + 'REFERENCES "' + fks[0].table + '" (' + toCols + ')';
        if (fks[0].on_delete && fks[0].on_delete !== 'NO ACTION') {
          constraint += ' ON DELETE ' + fks[0].on_delete;
        }
        if (fks[0].on_update && fks[0].on_update !== 'NO ACTION') {
          constraint += ' ON UPDATE ' + fks[0].on_update;
        }
        constraint += ';';
        deferredFKs.push(constraint);
      }
    }

    // Collect indexes
    for (const idx of schema.indexes) {
      const unique = idx.unique ? 'UNIQUE ' : '';
      const cols = idx.columns.map(c => '"' + c + '"').join(', ');
      // Generate a PG-safe index name
      const pgName = 'idx_' + schema.name + '_' + idx.columns.join('_');
      deferredIndexes.push(
        'CREATE ' + unique + 'INDEX IF NOT EXISTS "' + pgName + '" ON "' + schema.name + '" (' + cols + ');'
      );
    }
  }

  // ── Data INSERT ────────────────────────────────────────────────
  lines.push('-- ── Data ──────────────────────────────────────────────────────');
  lines.push('');

  for (const schema of tableSchemas) {
    if (schema.rowCount === 0) {
      lines.push('-- ' + schema.name + ': 0 rows (skipped)');
      lines.push('');
      continue;
    }

    const colNames = schema.columns.map(c => '"' + c.name + '"').join(', ');
    const boolCols = new Set(
      schema.columns
        .filter(c => isBooleanColumn(c, schema))
        .map(c => c.name)
    );

    // Read in batches to keep memory bounded
    const countAll = schema.rowCount;
    let offset = 0;

    lines.push('-- ' + schema.name + ': ' + countAll.toLocaleString() + ' rows');

    while (offset < countAll) {
      const rows = db.prepare(
        'SELECT * FROM "' + schema.name + '" LIMIT ' + BATCH_SIZE + ' OFFSET ' + offset
      ).all();

      if (rows.length === 0) break;

      lines.push('INSERT INTO "' + schema.name + '" (' + colNames + ') VALUES');

      const valueSets = [];
      for (const row of rows) {
        const vals = schema.columns.map(c => {
          const v = row[c.name];
          // Convert 0/1 to FALSE/TRUE for boolean columns
          if (boolCols.has(c.name) && (v === 0 || v === 1)) {
            return v ? 'TRUE' : 'FALSE';
          }
          return pgLiteral(v);
        });
        valueSets.push('(' + vals.join(', ') + ')');
      }

      lines.push(valueSets.join(',\n') + ';');
      lines.push('');

      offset += rows.length;
    }
  }

  // ── Foreign keys (deferred) ────────────────────────────────────
  if (deferredFKs.length > 0) {
    lines.push('-- ── Foreign Key Constraints ───────────────────────────────────');
    lines.push('');
    for (const fk of deferredFKs) lines.push(fk);
    lines.push('');
  }

  // ── Indexes (deferred) ─────────────────────────────────────────
  if (deferredIndexes.length > 0) {
    lines.push('-- ── Indexes ──────────────────────────────────────────────────');
    lines.push('');
    for (const idx of deferredIndexes) lines.push(idx);
    lines.push('');
  }

  // ── Reset sequences ────────────────────────────────────────────
  lines.push('-- ── Sequence resets (SERIAL columns) ──────────────────────────');
  lines.push('');
  for (const schema of tableSchemas) {
    const pkCols = schema.columns.filter(c => c.pk > 0);
    const hasAutoIncrement = schema.sql && /AUTOINCREMENT/i.test(schema.sql);
    const hasFkOnPk = pkCols.length === 1 && schema.fkeys.some(f => f.from === pkCols[0].name);
    if (pkCols.length === 1 && (pkCols[0].type || '').toUpperCase() === 'INTEGER'
        && hasAutoIncrement && !hasFkOnPk) {
      const col = pkCols[0].name;
      const seqName = schema.name + '_' + col + '_seq';
      lines.push(
        "SELECT setval('\"" + seqName + "\"', COALESCE((SELECT MAX(\"" + col + '") FROM "' + schema.name + '"), 1));'
      );
    }
  }
  lines.push('');

  lines.push('COMMIT;');
  lines.push('');
  lines.push('-- ══════════════════════════════════════════════════════════════');
  lines.push('-- Migration complete. To import:');
  lines.push('--   psql -U your_user -d your_db -f migration.sql');
  lines.push('-- ══════════════════════════════════════════════════════════════');

  const sqlFile = path.join(OUT_DIR, 'migration.sql');
  fs.writeFileSync(sqlFile, lines.join('\n'), 'utf8');
  const sizeKB = (fs.statSync(sqlFile).size / 1024).toFixed(1);
  console.log('SQL file written: ' + sqlFile + ' (' + sizeKB + ' KB)');
}

// ══════════════════════════════════════════════════════════════════
// ── JSON export ──────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════

function exportJSON(db, tableSchemas) {
  // Write a schema manifest
  const manifest = {
    generated: new Date().toISOString(),
    source: DB_FILE,
    tables: [],
  };

  for (const schema of tableSchemas) {
    const pkCols = schema.columns.filter(c => c.pk > 0);
    const singlePk = pkCols.length === 1 ? pkCols[0].name : null;
    const hasAutoIncrement = schema.sql && /AUTOINCREMENT/i.test(schema.sql);
    const hasFkOnPk = singlePk && schema.fkeys.some(f => f.from === singlePk);
    const isAutoIncrementPk = singlePk && hasAutoIncrement && !hasFkOnPk;
    const boolCols = new Set(
      schema.columns
        .filter(c => isBooleanColumn(c, schema))
        .map(c => c.name)
    );

    const tableMeta = {
      name: schema.name,
      rowCount: schema.rowCount,
      columns: schema.columns.map(c => ({
        name: c.name,
        sqliteType: c.type,
        pgType: mapType(c.type, c.name, c.name === singlePk && isAutoIncrementPk, c.dflt_value),
        isBoolean: boolCols.has(c.name),
        notNull: !!c.notnull,
        defaultValue: c.dflt_value,
        primaryKey: c.pk > 0,
      })),
      foreignKeys: schema.fkeys.map(f => ({
        from: f.from,
        table: f.table,
        to: f.to,
        onDelete: f.on_delete,
      })),
      indexes: schema.indexes,
    };

    manifest.tables.push(tableMeta);

    // Write data file
    if (schema.rowCount > 0) {
      const rows = db.prepare('SELECT * FROM "' + schema.name + '"').all();

      // Convert boolean columns
      for (const row of rows) {
        for (const bCol of boolCols) {
          if (row[bCol] === 0) row[bCol] = false;
          if (row[bCol] === 1) row[bCol] = true;
        }
      }

      const dataFile = path.join(OUT_DIR, schema.name + '.json');
      fs.writeFileSync(dataFile, JSON.stringify(rows, null, 2), 'utf8');
      console.log('  ' + schema.name + '.json — ' + rows.length + ' rows');
    }
  }

  const manifestFile = path.join(OUT_DIR, '_manifest.json');
  fs.writeFileSync(manifestFile, JSON.stringify(manifest, null, 2), 'utf8');
  console.log('  _manifest.json — schema + metadata');
}

// ══════════════════════════════════════════════════════════════════
// ── Helpers ──────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════

/**
 * Heuristic: detect if an INTEGER column is actually boolean.
 * Checks: column name patterns, DEFAULT 0/1, CHECK(col IN (0,1)).
 */
function isBooleanColumn(col, schema) {
  if ((col.type || '').toUpperCase() !== 'INTEGER') return false;

  // Name-based heuristics
  const name = col.name.toLowerCase();
  const boolPatterns = [
    'active', 'enabled', 'triggered', 'used', 'read',
    'dark_mode', 'price_alerts', 'weekly_newsletter',
    'notify_email', 'notify_inapp', 'notify_push',
    'email_verified', 'totp_enabled', 'cookie_secure',
  ];
  if (boolPatterns.some(p => name === p || name.startsWith('is_') || name.startsWith('has_'))) {
    return true;
  }

  // Check if the CREATE TABLE SQL has CHECK(col IN (0,1))
  if (schema.sql) {
    const re = new RegExp(col.name + '\\s[^,]*CHECK\\s*\\(\\s*' + col.name + '\\s+IN\\s*\\(\\s*0\\s*,\\s*1\\s*\\)', 'i');
    if (re.test(schema.sql)) return true;
  }

  // DEFAULT 0 or 1 with NOT NULL is a strong boolean signal
  if (col.notnull && (col.dflt_value === '0' || col.dflt_value === '1')) {
    // But not for counters (login_count, failed_login_attempts, etc.)
    if (name.includes('count') || name.includes('attempts')) return false;
    return true;
  }

  return false;
}

// ── Run ──────────────────────────────────────────────────────────
main();
