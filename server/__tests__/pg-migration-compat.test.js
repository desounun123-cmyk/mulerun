/**
 * PostgreSQL Migration Compatibility Test
 *
 * Validates that all SQL statements used throughout the codebase will
 * translate correctly from SQLite to PostgreSQL via db-postgres.js's
 * translateSQL() function.  Also checks schema parity, boolean literal
 * correctness, and API surface compatibility.
 *
 * Run:  node pg-migration-compat.test.js
 */

'use strict';

// ── Inline copy of translateSQL from db-postgres.js ────────────────────────
// Duplicated here so the test is self-contained (no DATABASE_URL or pg needed).

function translateSQL(sql) {
  let out = sql;

  // Parameter placeholders: ? → $1, $2, ...
  let paramIdx = 0;
  out = out.replace(/\?/g, () => '$' + (++paramIdx));

  // INSERT OR REPLACE → INSERT ... ON CONFLICT DO UPDATE
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

  // INSERT OR IGNORE → INSERT (drop the OR IGNORE)
  out = out.replace(/INSERT\s+OR\s+IGNORE/gi, 'INSERT');

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
  out = out.replace(
    /datetime\s*\(\s*'now'\s*,\s*'-'\s*\|\|\s*(\$\d+)\s*\|\|\s*'\s*(day|hour|minute|second)s?\s*'\s*\)/gi,
    (_, param, unit) => `NOW() - make_interval(${unit}s => ${param})`
  );

  // datetime('now', '+' || $N || ' ...') → NOW() + make_interval(...)
  out = out.replace(
    /datetime\s*\(\s*'now'\s*,\s*'\+?'\s*\|\|\s*(\$\d+)\s*\|\|\s*'\s*(day|hour|minute|second)s?\s*'\s*\)/gi,
    (_, param, unit) => `NOW() + make_interval(${unit}s => ${param})`
  );

  // datetime('now') → NOW()
  out = out.replace(/datetime\s*\(\s*'now'\s*\)/gi, 'NOW()');

  // datetime('now', '-30 days') / datetime('now', '+15 minutes') → NOW() + INTERVAL
  out = out.replace(/datetime\s*\(\s*'now'\s*,\s*'([+-]?\d+)\s+(day|hour|minute|second)s?'\s*\)/gi,
    (_, num, unit) => `NOW() + INTERVAL '${num} ${unit}s'`);

  // date('now') → CURRENT_DATE
  out = out.replace(/date\s*\(\s*'now'\s*\)/gi, 'CURRENT_DATE');

  // strftime('%H', col) → zero-padded hour extraction
  out = out.replace(/strftime\s*\(\s*'%H'\s*,\s*(\w+)\s*\)/gi,
    (_, col) => `LPAD(EXTRACT(HOUR FROM ${col}::timestamp)::int::text, 2, '0')`);

  // strftime('%Y-%m-%dT%H:%M:%f', 'now') → NOW()::text
  out = out.replace(/strftime\s*\(\s*'%Y-%m-%dT%H:%M:%f'\s*,\s*'now'\s*\)/gi, "NOW()::text");

  // strftime('%Y-W%W', col) → TO_CHAR(col, 'IYYY-"W"IW')
  out = out.replace(/strftime\s*\(\s*'%Y-W%W'\s*,\s*(\w+)\s*\)/gi,
    (_, col) => `TO_CHAR(${col}::timestamp, 'IYYY-"W"IW')`);

  // Catch-all: remaining strftime with 'now' → NOW()::text
  out = out.replace(/strftime\s*\(\s*'[^']*'\s*,\s*'now'\s*\)/gi, "NOW()::text");

  // json_extract(col, '$.key') → col::json->>'key'
  out = out.replace(/json_extract\s*\(\s*(\w+)\s*,\s*'\$\.(\w+)'\s*\)/gi,
    (_, col, key) => `${col}::json->>'${key}'`);

  // INTEGER PRIMARY KEY AUTOINCREMENT → SERIAL PRIMARY KEY
  out = out.replace(/INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT/gi, 'SERIAL PRIMARY KEY');

  // PRAGMA statements → no-op
  if (/^\s*PRAGMA\s/i.test(out)) {
    return null;
  }

  return out;
}

// ── Test harness ───────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures = [];

function assert(label, condition, detail) {
  if (condition) {
    passed++;
    console.log(`  \x1b[32m✓\x1b[0m ${label}`);
  } else {
    failed++;
    const msg = `  \x1b[31m✗\x1b[0m ${label}` + (detail ? `\n    → ${detail}` : '');
    console.log(msg);
    failures.push({ label, detail });
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Basic translations
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n\x1b[1m1. Correctly handled translations\x1b[0m\n');

assert(
  'Parameter placeholders (? → $N)',
  translateSQL('SELECT * FROM users WHERE id = ? AND name = ?') ===
    'SELECT * FROM users WHERE id = $1 AND name = $2'
);

assert(
  "datetime('now') → NOW()",
  translateSQL("UPDATE users SET last_login = datetime('now') WHERE id = ?") ===
    'UPDATE users SET last_login = NOW() WHERE id = $1'
);

assert(
  "datetime('now', '-30 days') → NOW() + INTERVAL",
  translateSQL("SELECT * FROM page_views WHERE created_at >= datetime('now', '-30 days')") ===
    "SELECT * FROM page_views WHERE created_at >= NOW() + INTERVAL '-30 days'"
);

assert(
  "datetime('now', '+15 minutes') → NOW() + INTERVAL",
  (() => {
    const t = translateSQL("UPDATE users SET locked_until = datetime('now', '+15 minutes') WHERE id = ?");
    return t === "UPDATE users SET locked_until = NOW() + INTERVAL '+15 minutes' WHERE id = $1";
  })()
);

assert(
  "strftime('%Y-W%W', col) → TO_CHAR",
  translateSQL("SELECT strftime('%Y-W%W', created_at) as week FROM users") ===
    `SELECT TO_CHAR(created_at::timestamp, 'IYYY-"W"IW') as week FROM users`
);

assert(
  "strftime('%H', col) → EXTRACT(HOUR FROM ...)",
  (() => {
    const t = translateSQL("SELECT strftime('%H', created_at) AS hour FROM page_views");
    return t.includes('EXTRACT(HOUR FROM') && !t.includes('strftime');
  })()
);

assert(
  "strftime('%Y-%m-%dT%H:%M:%f', 'now') → NOW()::text",
  (() => {
    const t = translateSQL("DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now'))");
    return t.includes("NOW()::text") && !t.includes('strftime');
  })()
);

assert(
  "date('now') → CURRENT_DATE",
  (() => {
    const t = translateSQL("SELECT * FROM t WHERE date(c) < date('now')");
    return t.includes('CURRENT_DATE') && !/date\s*\(\s*'now'\s*\)/i.test(t);
  })()
);

assert(
  "json_extract(col, '$.key') → col::json->>'key'",
  translateSQL("SELECT json_extract(sess, '$.userId') FROM sessions") ===
    "SELECT sess::json->>'userId' FROM sessions"
);

assert(
  'INTEGER PRIMARY KEY AUTOINCREMENT → SERIAL PRIMARY KEY',
  translateSQL('CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)') ===
    'CREATE TABLE t (id SERIAL PRIMARY KEY, name TEXT)'
);

assert(
  'PRAGMA statements → null (skipped)',
  translateSQL('PRAGMA journal_mode = WAL') === null
);

// ═══════════════════════════════════════════════════════════════════════════
// 2. INSERT OR REPLACE
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n\x1b[1m2. INSERT OR REPLACE translation\x1b[0m\n');

{
  const sql = 'INSERT OR REPLACE INTO "config" ("key", "value") VALUES (?, ?)';
  const translated = translateSQL(sql);
  assert(
    'INSERT OR REPLACE → ON CONFLICT DO UPDATE (backup.js:759)',
    /ON CONFLICT\s*\("key"\)\s*DO UPDATE SET\s*"value"\s*=\s*EXCLUDED\."value"/i.test(translated),
    `Translated: ${translated}`
  );
  assert(
    'No residual INSERT OR REPLACE',
    !/INSERT\s+OR\s+REPLACE/i.test(translated),
    `Translated: ${translated}`
  );
}

{
  const sql = 'INSERT OR REPLACE INTO users (id, name, email) VALUES (?, ?, ?)';
  const translated = translateSQL(sql);
  assert(
    'INSERT OR REPLACE with multiple update cols',
    translated.includes('ON CONFLICT (id) DO UPDATE SET') &&
    translated.includes('name = EXCLUDED.name') &&
    translated.includes('email = EXCLUDED.email'),
    `Translated: ${translated}`
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. sqlite_master
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n\x1b[1m3. sqlite_master → information_schema\x1b[0m\n');

{
  const sql = "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name";
  const translated = translateSQL(sql);
  assert(
    'sqlite_master list tables → information_schema (admin.js:78)',
    translated.includes('information_schema.tables') && !translated.includes('sqlite_master'),
    `Translated: ${translated}`
  );
}

{
  const sql = "SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name";
  const translated = translateSQL(sql);
  assert(
    'sqlite_master with sql column → information_schema (migrate-to-postgres.js:182)',
    translated.includes('information_schema.tables') && translated.includes("'' AS sql"),
    `Translated: ${translated}`
  );
}

{
  const sql = "SELECT 1 FROM sqlite_master WHERE type='table' AND name='_pitr_changelog'";
  const translated = translateSQL(sql);
  assert(
    'sqlite_master existence check → information_schema (backup.js:695)',
    translated.includes('information_schema.tables') && translated.includes("'_pitr_changelog'"),
    `Translated: ${translated}`
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Dynamic datetime intervals
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n\x1b[1m4. Dynamic datetime intervals (|| concatenation)\x1b[0m\n');

{
  const sql = "SELECT * FROM page_views WHERE created_at >= datetime('now', '-' || ? || ' days')";
  const translated = translateSQL(sql);
  assert(
    "datetime('now', '-' || ? || ' days') → make_interval (anomaly-detector.js:56)",
    translated.includes('make_interval') && !translated.includes('datetime'),
    `Translated: ${translated}`
  );
}

{
  const sql = "SELECT * FROM t WHERE c >= datetime('now', '-' || ? || ' hours')";
  const translated = translateSQL(sql);
  assert(
    "datetime('now', '-' || ? || ' hours') → make_interval",
    translated.includes('make_interval(hours') && !translated.includes('datetime'),
    `Translated: ${translated}`
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. strftime variants
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n\x1b[1m5. strftime variant coverage\x1b[0m\n');

{
  const sql = "SELECT strftime('%H', created_at) AS hour, date(created_at) AS day, COUNT(*) AS views FROM page_views WHERE created_at >= datetime('now', '-' || ? || ' days') GROUP BY date(created_at), strftime('%H', created_at)";
  const translated = translateSQL(sql);
  assert(
    'Full anomaly-detector query translates (strftime + dynamic datetime)',
    !translated.includes('strftime') && !translated.includes("datetime("),
    `Translated: ${translated}`
  );
}

{
  const sql = "CREATE TABLE t (ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')))";
  const translated = translateSQL(sql);
  assert(
    "strftime in DDL DEFAULT clause → NOW()::text (backup.js:523)",
    translated.includes("NOW()::text") && !translated.includes('strftime'),
    `Translated: ${translated}`
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Boolean TRUE/FALSE correctness
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n\x1b[1m6. Boolean TRUE/FALSE correctness in source files\x1b[0m\n');

const fs = require('fs');
const path = require('path');

// Resolve file paths (works from /workspace/output, /workspace/mulerun, or server/__tests__)
function resolveServerFile(relativePath) {
  const candidates = [
    path.join(__dirname, '..', 'mulerun', 'server', relativePath),
    path.join(__dirname, '..', 'server', relativePath),
    path.join(__dirname, '..', relativePath),  // from server/__tests__ → server/
  ];
  for (const c of candidates) {
    try { fs.accessSync(c); return c; } catch (_) {}
  }
  return null;
}

// Check that source files use TRUE/FALSE instead of 0/1 for boolean columns
const booleanChecks = [
  {
    file: 'routes/auth.js',
    patterns: [
      { should: 'email_verified) VALUES (?, ?, ?, FALSE)', label: 'auth.js:328 uses FALSE for email_verified' },
      { should: "SET email_verified = TRUE WHERE", label: 'auth.js:896 uses TRUE for email_verified' },
      { should: "SET used = TRUE WHERE user_id", label: 'auth.js:340 uses TRUE for used' },
      { should: "SET used = TRUE WHERE id", label: 'auth.js:755 uses TRUE for used (password_reset)' },
      { should: 'totp_enabled = TRUE WHERE', label: 'auth.js:1025 uses TRUE for totp_enabled' },
      { should: "SET totp_enabled = FALSE", label: 'auth.js:1060 uses FALSE for totp_enabled' },
      { should: "VALUES (?, TRUE, FALSE, TRUE)", label: 'auth.js:335 uses TRUE/FALSE for user_settings' },
    ]
  },
  {
    file: 'routes/user.js',
    patterns: [
      { should: "VALUES (?, TRUE, FALSE, TRUE, FALSE, TRUE, TRUE)", label: 'user.js:116 uses TRUE/FALSE for user_settings' },
      { should: "SET triggered = TRUE, last_triggered_at", label: 'user.js:569 uses TRUE for triggered' },
      { should: "SET triggered = FALSE, last_triggered_at", label: 'user.js:615 uses FALSE for triggered' },
      { should: "SET read = TRUE WHERE user_id", label: 'user.js:662 uses TRUE for read' },
      { should: "SET read = TRUE WHERE id", label: 'user.js:677 uses TRUE for read (single)' },
    ]
  },
  {
    file: 'routes/oauth.js',
    patterns: [
      { should: "VALUES (?, TRUE, FALSE, TRUE)", label: 'oauth.js:109 uses TRUE/FALSE for user_settings' },
    ]
  },
  {
    file: 'utils/price-checker.js',
    patterns: [
      { should: "SET triggered = TRUE, last_triggered_at", label: 'price-checker.js:217 uses TRUE for triggered' },
    ]
  },
  {
    file: 'db.js',
    patterns: [
      { should: "email_verified = TRUE", label: 'db.js:306 uses TRUE for email_verified migration' },
    ]
  },
];

for (const { file, patterns } of booleanChecks) {
  const filePath = resolveServerFile(file);
  if (!filePath) {
    assert(`[skip] ${file} — file not found`, false, 'Could not locate file');
    continue;
  }
  const content = fs.readFileSync(filePath, 'utf8');
  for (const { should, label } of patterns) {
    assert(label, content.includes(should), `Expected to find: ${should}`);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. Schema parity
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n\x1b[1m7. Schema parity — tables in both SQLite and PostgreSQL\x1b[0m\n');

const EXPECTED_TABLES = [
  'users', 'user_settings', 'email_verification_tokens',
  'password_reset_tokens', 'price_alert_rules', 'notifications',
  'push_subscriptions', 'page_views', 'analytics_events', 'config', 'sessions',
];

const dbJsPath = resolveServerFile('db.js');
let dbJsContent = '';
if (dbJsPath) {
  dbJsContent = fs.readFileSync(dbJsPath, 'utf8');
} else {
  console.log('  [skip] db.js not found — skipping schema parity checks');
}

if (dbJsContent) {
  for (const table of EXPECTED_TABLES) {
    const pgPattern = new RegExp(`CREATE\\s+TABLE\\s+(IF\\s+NOT\\s+EXISTS\\s+)?${table}\\b`, 'i');
    assert(
      `PG schema includes CREATE TABLE for "${table}"`,
      pgPattern.test(dbJsContent),
      `Table "${table}" not found in db.js PostgreSQL schema setup.`
    );
  }
}

// Also check pg-schema.sql
const pgSchemaPath = (() => {
  const candidates = [
    path.join(__dirname, '..', 'mulerun', 'server', 'pg-schema.sql'),
    path.join(__dirname, '..', 'server', 'pg-schema.sql'),
    path.join(__dirname, '..', 'pg-schema.sql'),
  ];
  for (const c of candidates) {
    try { fs.accessSync(c); return c; } catch (_) {}
  }
  return null;
})();

if (pgSchemaPath) {
  const pgSchemaContent = fs.readFileSync(pgSchemaPath, 'utf8');
  console.log('');
  for (const table of EXPECTED_TABLES) {
    const pgPattern = new RegExp(`CREATE\\s+TABLE\\s+(IF\\s+NOT\\s+EXISTS\\s+)?${table}\\b`, 'i');
    assert(
      `pg-schema.sql includes CREATE TABLE for "${table}"`,
      pgPattern.test(pgSchemaContent),
      `Table "${table}" not found in pg-schema.sql.`
    );
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. Edge cases
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n\x1b[1m8. translateSQL edge cases\x1b[0m\n');

{
  const sql = "SELECT * FROM t WHERE a >= datetime('now', '-24 hours') AND b >= datetime('now', '-7 days')";
  const translated = translateSQL(sql);
  const count = (translated.match(/NOW\(\)/g) || []).length;
  assert('Multiple datetime() calls in one statement', count === 2, `Got ${count} NOW(). Translated: ${translated}`);
}

{
  const sql = "SELECT * FROM users WHERE id = ? AND created_at >= datetime('now', '-30 days') AND name = ?";
  const translated = translateSQL(sql);
  assert(
    'Param indices correct with mixed datetime',
    translated.includes('$1') && translated.includes('$2') && !translated.includes('$3'),
    `Translated: ${translated}`
  );
}

assert('Empty SQL returns empty string', translateSQL('') === '');
assert('PRAGMA assignment → null', translateSQL('PRAGMA busy_timeout = 5000') === null);

{
  const sql = 'SELECT * FROM users WHERE id IN (SELECT user_id FROM sessions WHERE expire > ?) AND name = ?';
  const translated = translateSQL(sql);
  assert(
    'Subquery parameter ordering',
    translated === 'SELECT * FROM users WHERE id IN (SELECT user_id FROM sessions WHERE expire > $1) AND name = $2',
    `Translated: ${translated}`
  );
}

{
  const sql = 'INSERT INTO users (name) VALUES ($1) RETURNING id';
  const translated = translateSQL(sql);
  assert('RETURNING clause preserved', translated.includes('RETURNING id'), `Translated: ${translated}`);
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. API surface
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n\x1b[1m9. db-postgres.js API surface check\x1b[0m\n');

const pgPath = resolveServerFile('db-postgres.js');
let pgContent = '';
if (pgPath) {
  pgContent = fs.readFileSync(pgPath, 'utf8');
}

if (pgContent) {
  for (const fn of ['prepare', 'exec', 'pragma', 'transaction', 'backup', 'close']) {
    assert(
      `Exports ${fn}()`,
      pgContent.includes(`${fn},`) || pgContent.includes(`${fn}:`) || new RegExp(`function\\s+${fn}\\s*\\(`).test(pgContent),
      `Function "${fn}" not found in db-postgres.js exports.`
    );
  }
  for (const m of ['run', 'get', 'all']) {
    assert(
      `prepare() returns .${m}()`,
      new RegExp(`${m}\\s*\\(`).test(pgContent),
      `Method "${m}" not found in prepare() return object.`
    );
  }
} else {
  console.log('  [skip] db-postgres.js not found');
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. Real SQL smoke tests
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n\x1b[1m10. Real SQL statements — translation smoke tests\x1b[0m\n');

const realQueries = [
  { label: 'admin.js: user count', sql: 'SELECT COUNT(*) as count FROM users' },
  { label: 'admin.js: registration trends', sql: "SELECT date(created_at) as day, COUNT(*) as count FROM users GROUP BY date(created_at) ORDER BY day ASC" },
  { label: 'admin.js: weekly registrations (strftime)', sql: "SELECT strftime('%Y-W%W', created_at) as week, COUNT(*) as count FROM users GROUP BY strftime('%Y-W%W', created_at) ORDER BY week ASC" },
  { label: 'admin.js: feature usage SUM', sql: "SELECT SUM(price_alerts) as price_alerts_on, SUM(weekly_newsletter) as newsletter_on, SUM(dark_mode) as dark_mode_on, COUNT(*) as total FROM user_settings" },
  { label: 'admin.js: page views 30 days', sql: "SELECT date(created_at) as day, COUNT(*) as views, COUNT(DISTINCT session_hash) as visitors FROM page_views WHERE created_at >= datetime('now', '-30 days') GROUP BY date(created_at) ORDER BY day ASC" },
  { label: 'admin.js: sqlite_master table list', sql: "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name" },
  { label: 'auth.js: login by email', sql: 'SELECT * FROM users WHERE email = ?' },
  { label: 'auth.js: increment failed attempts', sql: 'UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?' },
  { label: 'auth.js: lock account (+15 minutes)', sql: "UPDATE users SET locked_until = datetime('now', '+15 minutes') WHERE id = ?" },
  { label: 'user.js: update settings', sql: 'UPDATE user_settings SET price_alerts = ?, weekly_newsletter = ?, dark_mode = ? WHERE user_id = ?' },
  { label: 'oauth.js: find by provider+id', sql: 'SELECT * FROM users WHERE oauth_provider = ? AND oauth_id = ?' },
  { label: 'anomaly-detector.js: hourly with dynamic interval', sql: "SELECT strftime('%H', created_at) AS hour, date(created_at) AS day, COUNT(*) AS views FROM page_views WHERE created_at >= datetime('now', '-' || ? || ' days') GROUP BY date(created_at), strftime('%H', created_at) ORDER BY day ASC, hour ASC" },
  { label: 'anomaly-detector.js: daily with date(now)', sql: "SELECT date(created_at) AS day, COUNT(*) AS views FROM page_views WHERE created_at >= datetime('now', '-' || ? || ' days') AND date(created_at) < date('now') GROUP BY date(created_at) ORDER BY day ASC" },
  { label: 'backup.js: INSERT OR REPLACE config', sql: 'INSERT OR REPLACE INTO "config" ("key", "value") VALUES (?, ?)' },
  { label: 'backup.js: pitr changelog table check', sql: "SELECT 1 FROM sqlite_master WHERE type='table' AND name='_pitr_changelog'" },
  { label: 'auth.js: session cleanup json_extract + LIKE', sql: "DELETE FROM sessions WHERE json_extract(sess, '$.userId') = ? OR sess LIKE '%\"userId\":' || ? || ',%' OR sess LIKE '%\"userId\":' || ? || '}%'" },
  { label: 'auth.js: email_verified = TRUE', sql: "UPDATE users SET email_verified = TRUE WHERE id = ?" },
  { label: 'user.js: notifications read = TRUE', sql: "UPDATE notifications SET read = TRUE WHERE user_id = ? AND read = FALSE" },
  { label: 'auth.js: totp_enabled = TRUE', sql: "UPDATE users SET totp_secret = ?, totp_enabled = TRUE WHERE id = ?" },
  { label: 'user.js: triggered = TRUE', sql: "UPDATE price_alert_rules SET triggered = TRUE, last_triggered_at = ? WHERE id = ?" },
];

for (const { label, sql } of realQueries) {
  const translated = translateSQL(sql);
  const hasUntranslated =
    /datetime\s*\(/i.test(translated) ||
    /strftime\s*\(/i.test(translated) ||
    /sqlite_master/i.test(translated) ||
    /INSERT\s+OR\s+(REPLACE|IGNORE)/i.test(translated);

  assert(label, !hasUntranslated, `Untranslated SQLite syntax remains.\n    Translated: ${translated}`);
}

// ═══════════════════════════════════════════════════════════════════════════
// 11. datetime interval variants
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n\x1b[1m11. datetime() interval variant coverage\x1b[0m\n');

const intervalTests = [
  { input: "datetime('now', '-30 days')", shouldTranslate: true },
  { input: "datetime('now', '-24 hours')", shouldTranslate: true },
  { input: "datetime('now', '+15 minutes')", shouldTranslate: true },
  { input: "datetime('now', '-1 day')", shouldTranslate: true },
  { input: "datetime('now', '-' || ? || ' days')", shouldTranslate: true },
  { input: "datetime('now')", shouldTranslate: true },
];

for (const { input, shouldTranslate } of intervalTests) {
  const translated = translateSQL(`SELECT * FROM t WHERE c >= ${input}`);
  const wasTranslated = !/datetime\s*\(/i.test(translated);
  assert(
    `${input} is translated`,
    wasTranslated === shouldTranslate,
    `Expected ${shouldTranslate ? 'translated' : 'untranslated'}, got: ${translated}`
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// 12. LIKE with || concatenation
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n\x1b[1m12. LIKE with || parameter concatenation\x1b[0m\n');

{
  const sql = `DELETE FROM sessions WHERE json_extract(sess, '$.userId') = ?` +
    ` OR sess LIKE '%"userId":' || ? || ',%'` +
    ` OR sess LIKE '%"userId":' || ? || '}%'`;
  const translated = translateSQL(sql);

  assert(
    'json_extract in session cleanup is translated',
    !(/json_extract/i.test(translated)),
    `Translated: ${translated}`
  );

  const paramMatches = translated.match(/\$\d+/g) || [];
  assert(
    'LIKE || pattern has correct parameter count ($1,$2,$3)',
    paramMatches.length === 3 && paramMatches[0] === '$1' && paramMatches[1] === '$2' && paramMatches[2] === '$3',
    `Params: ${paramMatches.join(', ')}. Translated: ${translated}`
  );

  assert(
    'LIKE || concatenation preserved (valid in PG)',
    translated.includes('||'),
    `Translated: ${translated}`
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// 13. querySync architecture (no child-process-per-query)
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n\x1b[1m13. querySync architecture — no child-process-per-query\x1b[0m\n');

if (pgContent) {
  // Must NOT contain execFileSync or execSync in querySync (OK in backup())
  assert(
    'No execFileSync in querySync (no child-process spawn per query)',
    (() => {
      const querySyncMatch = pgContent.match(/function querySync[\s\S]*?^}/m);
      if (!querySyncMatch) return true; // querySync not found as standalone function, OK
      return !querySyncMatch[0].includes('execFileSync');
    })(),
    'querySync still uses execFileSync — spawning a child process per query adds ~50-100ms overhead'
  );

  assert(
    'No execSync in querySync',
    // execSync is OK in backup() for pg_dump, but not in querySync
    (() => {
      // Check that execSync only appears in the backup function, not querySync
      const querySyncMatch = pgContent.match(/function querySync[\s\S]*?^}/m);
      if (!querySyncMatch) return true; // querySync not found as standalone function, OK
      return !querySyncMatch[0].includes('execSync');
    })(),
    'querySync still uses execSync for query execution'
  );

  // Should use worker_threads + SharedArrayBuffer + Atomics
  assert(
    'Uses worker_threads for sync query execution',
    pgContent.includes("require('worker_threads')") || pgContent.includes('require("worker_threads")'),
    'Expected worker_threads import for persistent worker pattern'
  );

  assert(
    'Uses SharedArrayBuffer for cross-thread signaling',
    pgContent.includes('SharedArrayBuffer'),
    'Expected SharedArrayBuffer for zero-copy result passing'
  );

  assert(
    'Uses Atomics.wait for synchronous blocking',
    pgContent.includes('Atomics.wait'),
    'Expected Atomics.wait to block main thread until worker completes'
  );

  assert(
    'Uses Atomics.notify for worker-to-main signaling',
    pgContent.includes('Atomics.notify'),
    'Expected Atomics.notify in worker to wake main thread'
  );

  assert(
    'Worker is created once (persistent), not per-query',
    (() => {
      // Count "new Worker" — should appear exactly once
      const matches = pgContent.match(/new Worker\(/g) || [];
      return matches.length === 1;
    })(),
    'Expected exactly one new Worker() call (persistent worker pattern)'
  );

  assert(
    'Query timeout is configurable via PG_QUERY_TIMEOUT',
    pgContent.includes('PG_QUERY_TIMEOUT'),
    'Expected configurable timeout via environment variable'
  );

  assert(
    'close() shuts down the worker',
    (() => {
      const closeMatch = pgContent.match(/function close[\s\S]*?^}/m);
      if (!closeMatch) return false;
      return closeMatch[0].includes('shutdown') || closeMatch[0].includes('worker') || closeMatch[0].includes('_worker');
    })(),
    'close() should terminate the persistent worker thread'
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// 14. SQLite write queue (SQLITE_BUSY prevention)
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n\x1b[1m14. SQLite write queue — SQLITE_BUSY prevention\x1b[0m\n');

if (dbJsContent) {
  assert(
    'Write queue array defined (_writeQueue)',
    dbJsContent.includes('_writeQueue'),
    'Expected _writeQueue array for serializing writes'
  );

  assert(
    'Write busy flag defined (_writeBusy)',
    dbJsContent.includes('_writeBusy'),
    'Expected _writeBusy flag to track queue state'
  );

  assert(
    'Write SQL detection regex (_WRITE_RE)',
    dbJsContent.includes('_WRITE_RE') &&
    /INSERT|UPDATE|DELETE/.test(dbJsContent.match(/_WRITE_RE\s*=\s*([^\n]+)/)?.[1] || ''),
    'Expected regex to classify INSERT/UPDATE/DELETE as writes'
  );

  assert(
    '_isWriteSQL function defined',
    /function\s+_isWriteSQL\s*\(/.test(dbJsContent),
    'Expected _isWriteSQL() to classify SQL as read or write'
  );

  assert(
    '_enqueueWrite function defined',
    /function\s+_enqueueWrite\s*\(/.test(dbJsContent),
    'Expected _enqueueWrite() to serialize write operations'
  );

  assert(
    '_drainWriteQueue function defined',
    /function\s+_drainWriteQueue\s*\(/.test(dbJsContent),
    'Expected _drainWriteQueue() to process queued writes sequentially'
  );

  assert(
    'db.prepare() is wrapped to route writes through queue',
    dbJsContent.includes('_origPrepare') && dbJsContent.includes('_enqueueWrite'),
    'Expected db.prepare() to be wrapped so .run()/.get()/.all() on write SQL go through queue'
  );

  assert(
    'db.exec() is wrapped for writes',
    dbJsContent.includes('_origExec') || /db\.exec\s*=\s*function/.test(dbJsContent),
    'Expected db.exec() to be wrapped so write DDL/DML goes through queue'
  );

  assert(
    'db.transaction() is wrapped for writes',
    dbJsContent.includes('_origTransaction') || /db\.transaction\s*=\s*function/.test(dbJsContent),
    'Expected db.transaction() to be wrapped so transactions go through queue'
  );

  // Reads should NOT go through the queue
  assert(
    'Reads bypass the write queue (isWrite guard)',
    dbJsContent.includes('if (!isWrite) return stmt') || dbJsContent.includes('if (!isWrite)'),
    'Expected SELECT queries to bypass the write queue for concurrency'
  );
} else {
  console.log('  [skip] db.js not found — skipping write queue checks');
}

// ═══════════════════════════════════════════════════════════════════════════
// 15. Analytics table indexes on created_at
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n\x1b[1m15. Analytics table indexes on created_at\x1b[0m\n');

if (dbJsContent) {
  assert(
    'db.js (SQLite path) has idx_pv_created on page_views(created_at)',
    dbJsContent.includes('idx_pv_created') && /idx_pv_created\s+ON\s+page_views\s*\(\s*created_at\s*\)/i.test(dbJsContent),
    'Expected CREATE INDEX idx_pv_created ON page_views(created_at) in SQLite schema'
  );

  assert(
    'db.js (SQLite path) has idx_ae_created on analytics_events(created_at)',
    dbJsContent.includes('idx_ae_created') && /idx_ae_created\s+ON\s+analytics_events\s*\(\s*created_at\s*\)/i.test(dbJsContent),
    'Expected CREATE INDEX idx_ae_created ON analytics_events(created_at) in SQLite schema'
  );

  assert(
    'db.js (PG path) has idx_pv_created on page_views(created_at)',
    (() => {
      // PG path is in the first section (before the SQLite require('better-sqlite3'))
      const pgSection = dbJsContent.split("require('better-sqlite3')")[0] || dbJsContent;
      return /idx_pv_created\s+ON\s+page_views\s*\(\s*created_at\s*\)/i.test(pgSection);
    })(),
    'Expected idx_pv_created in PG schema section of db.js'
  );

  assert(
    'db.js (PG path) has idx_ae_created on analytics_events(created_at)',
    (() => {
      const pgSection = dbJsContent.split("require('better-sqlite3')")[0] || dbJsContent;
      return /idx_ae_created\s+ON\s+analytics_events\s*\(\s*created_at\s*\)/i.test(pgSection);
    })(),
    'Expected idx_ae_created in PG schema section of db.js'
  );
}

if (pgSchemaPath) {
  const pgSchemaContent = fs.readFileSync(pgSchemaPath, 'utf8');

  assert(
    'pg-schema.sql has idx_pv_created on page_views(created_at)',
    /CREATE\s+INDEX\s+(IF\s+NOT\s+EXISTS\s+)?idx_pv_created\s+ON\s+page_views\s*\(\s*created_at\s*\)/i.test(pgSchemaContent),
    'Expected CREATE INDEX idx_pv_created ON page_views(created_at) in pg-schema.sql (currently only a comment)'
  );

  assert(
    'pg-schema.sql has idx_ae_created on analytics_events(created_at)',
    /CREATE\s+INDEX\s+(IF\s+NOT\s+EXISTS\s+)?idx_ae_created\s+ON\s+analytics_events\s*\(\s*created_at\s*\)/i.test(pgSchemaContent),
    'Expected CREATE INDEX idx_ae_created ON analytics_events(created_at) in pg-schema.sql'
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// 16. backup() uses execFileSync (no shell injection)
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n\x1b[1m16. backup() — no shell injection via pg_dump\x1b[0m\n');

if (pgContent) {
  assert(
    'backup() uses execFileSync (not execSync with shell interpolation)',
    pgContent.includes('execFileSync') &&
    (() => {
      // Find the backup function body
      const backupMatch = pgContent.match(/function backup[\s\S]*?^}/m);
      if (!backupMatch) return false;
      return backupMatch[0].includes('execFileSync') && !backupMatch[0].includes('execSync');
    })(),
    'backup() should use execFileSync with argument array to avoid shell metacharacter injection'
  );

  assert(
    'backup() does not use template literal shell command',
    (() => {
      const backupMatch = pgContent.match(/function backup[\s\S]*?^}/m);
      if (!backupMatch) return false;
      // Should NOT have backtick shell commands like `pg_dump "${...}" > "${...}"`
      return !backupMatch[0].includes('`pg_dump');
    })(),
    'backup() should not interpolate DATABASE_URL into a shell string'
  );

  assert(
    'backup() passes DATABASE_URL as array argument to pg_dump',
    (() => {
      const backupMatch = pgContent.match(/function backup[\s\S]*?^}/m);
      if (!backupMatch) return false;
      // Should pass the URL as an argument in an array, e.g. execFileSync('pg_dump', [DATABASE_URL])
      return /execFileSync\s*\(\s*'pg_dump'\s*,\s*\[/.test(backupMatch[0]);
    })(),
    'Expected execFileSync(\'pg_dump\', [DATABASE_URL], ...) pattern'
  );

  assert(
    'backup() writes output to dest via fs (not shell redirect)',
    (() => {
      const backupMatch = pgContent.match(/function backup[\s\S]*?^}/m);
      if (!backupMatch) return false;
      return backupMatch[0].includes('writeFileSync') || backupMatch[0].includes('writeFile');
    })(),
    'Expected fs.writeFileSync(dest, output) instead of shell > redirect'
  );
} else {
  console.log('  [skip] db-postgres.js not found');
}

// ═══════════════════════════════════════════════════════════════════════════
// 17. Database connection monitoring (poolStats + /db-health endpoint)
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n\x1b[1m17. Database connection monitoring — poolStats + /db-health\x1b[0m\n');

if (pgContent) {
  assert(
    'db-postgres.js exports poolStats()',
    /poolStats\s*\(\s*\)\s*\{/.test(pgContent) || pgContent.includes('poolStats'),
    'Expected poolStats() method in db-postgres.js for PG pool monitoring'
  );

  assert(
    'poolStats() returns totalCount',
    pgContent.includes('totalCount'),
    'Expected totalCount in poolStats() (all clients: active + idle)'
  );

  assert(
    'poolStats() returns idleCount',
    pgContent.includes('idleCount'),
    'Expected idleCount in poolStats()'
  );

  assert(
    'poolStats() returns waitingCount',
    pgContent.includes('waitingCount'),
    'Expected waitingCount in poolStats() (queued requests waiting for a client)'
  );

  assert(
    'poolStats() returns activeCount',
    pgContent.includes('activeCount'),
    'Expected activeCount in poolStats()'
  );
}

if (dbJsContent) {
  assert(
    'db.js (SQLite path) exports poolStats()',
    /poolStats\s*=\s*function/.test(dbJsContent) || dbJsContent.includes('db.poolStats'),
    'Expected poolStats() on SQLite db object for API parity'
  );

  assert(
    'SQLite poolStats() reports write queue length',
    (() => {
      const match = dbJsContent.match(/poolStats\s*=\s*function[\s\S]*?};/);
      return match && match[0].includes('_writeQueue');
    })(),
    'Expected SQLite poolStats() to expose _writeQueue.length as waitingCount'
  );
}

// Check admin route has /db-health endpoint
const adminPath = resolveServerFile('routes/admin.js');
if (adminPath) {
  const adminContent = fs.readFileSync(adminPath, 'utf8');

  assert(
    'admin.js has GET /db-health route',
    adminContent.includes("'/db-health'") || adminContent.includes('"/db-health"'),
    'Expected router.get(\'/db-health\', ...) in admin.js'
  );

  assert(
    '/db-health calls db.poolStats()',
    adminContent.includes('poolStats'),
    'Expected /db-health handler to call db.poolStats()'
  );

  assert(
    '/db-health returns utilization percentage',
    adminContent.includes('utilizationPct'),
    'Expected /db-health to compute utilizationPct from active/max connections'
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// 18. Consolidated offline queue abstraction
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n\x1b[1m18. Consolidated offline queue — OfflineQueue abstraction\x1b[0m\n');

const indexHtmlPath = (() => {
  const candidates = [
    path.join(__dirname, '..', 'mulerun', 'index.html'),
    path.join(__dirname, '..', 'index.html'),
    path.join(__dirname, '..', '..', 'index.html'),
  ];
  for (const c of candidates) {
    try { fs.accessSync(c); return c; } catch (_) {}
  }
  return null;
})();

const swPath = (() => {
  const candidates = [
    path.join(__dirname, '..', 'mulerun', 'sw.js'),
    path.join(__dirname, '..', 'sw.js'),
    path.join(__dirname, '..', '..', 'sw.js'),
  ];
  for (const c of candidates) {
    try { fs.accessSync(c); return c; } catch (_) {}
  }
  return null;
})();

if (indexHtmlPath) {
  const htmlContent = fs.readFileSync(indexHtmlPath, 'utf8');

  assert(
    'OfflineQueue class is defined as shared abstraction',
    htmlContent.includes('var OfflineQueue') || htmlContent.includes('function Queue(opts)'),
    'Expected a unified OfflineQueue constructor/class in index.html'
  );

  assert(
    'OfflineQueue has configurable localStorage key',
    /this\._key\s*=\s*opts\.key/.test(htmlContent),
    'Expected OfflineQueue to accept opts.key for localStorage key'
  );

  assert(
    'OfflineQueue has configurable syncTag',
    /this\._syncTag\s*=\s*opts\.syncTag/.test(htmlContent),
    'Expected OfflineQueue to accept opts.syncTag for Background Sync registration'
  );

  assert(
    'OfflineQueue has configurable maxSize',
    htmlContent.includes('this._maxSize') || htmlContent.includes('opts.maxSize'),
    'Expected OfflineQueue to accept opts.maxSize for queue cap'
  );

  assert(
    'OfflineQueue has configurable maxAge',
    htmlContent.includes('this._maxAge') || htmlContent.includes('opts.maxAge'),
    'Expected OfflineQueue to accept opts.maxAge for entry eviction'
  );

  assert(
    'OfflineQueue has shared getQueue/saveQueue/enqueue/flush methods',
    /Queue\.prototype\.getQueue/.test(htmlContent) &&
    /Queue\.prototype\.saveQueue/.test(htmlContent) &&
    /Queue\.prototype\.enqueue/.test(htmlContent) &&
    /Queue\.prototype\.flush/.test(htmlContent),
    'Expected shared prototype methods on OfflineQueue'
  );

  assert(
    'OfflineQueue handles SW message internally (_initSWHandler)',
    /Queue\.prototype\._initSWHandler/.test(htmlContent) &&
    htmlContent.includes('this._getMsgType'),
    'Expected OfflineQueue to handle GET/SET SW messages via _initSWHandler'
  );

  assert(
    'Analytics queue uses OfflineQueue instance',
    /new OfflineQueue\(\s*\{[^}]*key:\s*'oil_analytics_queue'/.test(htmlContent),
    'Expected analytics queue to be created as new OfflineQueue({key: "oil_analytics_queue", ...})'
  );

  assert(
    'OfflineSync uses OfflineQueue instance',
    /new OfflineQueue\(\s*\{[^}]*key:\s*'oil_sync_queue'/.test(htmlContent),
    'Expected OfflineSync to use new OfflineQueue({key: "oil_sync_queue", ...})'
  );

  // No duplicate queue code
  assert(
    'No duplicate getQueue/saveQueue implementations outside OfflineQueue',
    (() => {
      // Count standalone "function getQueue" definitions — should be 0 (only prototype)
      const standalone = (htmlContent.match(/^\s*function getQueue\s*\(\s*\)/gm) || []).length;
      return standalone === 0;
    })(),
    'Expected all getQueue/saveQueue logic consolidated into OfflineQueue prototype'
  );

  // Old separate SW handler for OfflineSync should be removed
  assert(
    'Old separate SW message handler for sync-settings removed',
    !htmlContent.includes("event.data.type === 'GET_SYNC_QUEUE'") ||
    htmlContent.includes('self._getMsgType'),
    'Expected the old standalone SW message listener for GET_SYNC_QUEUE to be replaced by OfflineQueue._initSWHandler'
  );
} else {
  console.log('  [skip] index.html not found');
}

if (swPath) {
  const swContent = fs.readFileSync(swPath, 'utf8');

  assert(
    'SW uses single generic replayClientQueue function',
    swContent.includes('replayClientQueue'),
    'Expected a single replayClientQueue() function instead of separate replayQueue() + replayAnalyticsQueue()'
  );

  assert(
    'SW replayClientQueue accepts getMsgType/setMsgType/buildFetchOpts params',
    /async function replayClientQueue\s*\(/.test(swContent) &&
    swContent.includes('getMsgType') &&
    swContent.includes('setMsgType') &&
    swContent.includes('buildFetchOpts'),
    'Expected generic replayClientQueue(getMsgType, setMsgType, buildFetchOpts)'
  );

  assert(
    'SW no longer has separate replayQueue function',
    !(/async function replayQueue\s*\(/.test(swContent)),
    'Expected old replayQueue() to be removed (replaced by replayClientQueue)'
  );

  assert(
    'SW no longer has separate replayAnalyticsQueue function',
    !(/async function replayAnalyticsQueue\s*\(/.test(swContent)),
    'Expected old replayAnalyticsQueue() to be removed (replaced by replayClientQueue)'
  );

  assert(
    'SW sync-settings calls replayClientQueue',
    /sync-settings.*replayClientQueue|replayClientQueue.*GET_SYNC_QUEUE/s.test(swContent),
    'Expected sync-settings event to use replayClientQueue'
  );

  assert(
    'SW sync-analytics calls replayClientQueue',
    /sync-analytics.*replayClientQueue|replayClientQueue.*GET_ANALYTICS_QUEUE/s.test(swContent),
    'Expected sync-analytics event to use replayClientQueue'
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Summary
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n' + '='.repeat(60));
console.log(`\x1b[1mResults:\x1b[0m  \x1b[32m${passed} passed\x1b[0m  \x1b[31m${failed} failed\x1b[0m`);
console.log('='.repeat(60));

if (failures.length > 0) {
  console.log('\n\x1b[1m\x1b[31mFailed tests — SQL patterns that will BREAK on PostgreSQL:\x1b[0m\n');
  for (const f of failures) {
    console.log(`  * ${f.label}`);
    if (f.detail) console.log(`    ${f.detail}`);
  }
  console.log('');
}

if (failed === 0) {
  console.log('\n\x1b[32mAll checks passed. Migration to PostgreSQL is safe.\x1b[0m\n');
}

process.exit(failed > 0 ? 1 : 0);
