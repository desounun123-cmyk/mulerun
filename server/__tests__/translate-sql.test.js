/**
 * Unit tests for translateSQL() — the SQLite-to-PostgreSQL dialect translator.
 *
 * Since db-postgres.js throws at module level if DATABASE_URL is not set,
 * we extract translateSQL via a regex-based loader to test it in isolation.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

// ── Extract translateSQL without requiring db-postgres.js ──────────────
// The module has top-level side effects (Pool creation, Worker spawn) that
// need DATABASE_URL. We extract just the function source and run it in a
// sandboxed context.
const src = fs.readFileSync(path.join(__dirname, '..', 'db-postgres.js'), 'utf8');
const fnStart = src.indexOf('function translateSQL(sql) {');
if (fnStart === -1) throw new Error('Could not find translateSQL in db-postgres.js');
// The function ends just before the next top-level section comment
const fnEnd = src.indexOf('\n// ──', fnStart + 1);
const fnSource = src.slice(fnStart, fnEnd).trimEnd();

// Run in a VM context to avoid scope issues with regex braces
const sandbox = {};
vm.runInNewContext(fnSource + '\nresult = translateSQL;', sandbox);
const translateSQL = sandbox.result;

// ── Tests ──────────────────────────────────────────────────────────────

describe('translateSQL', () => {
  // ── Parameter placeholders ──────────────────────────────────────────
  describe('parameter placeholders', () => {
    it('replaces single ? with $1', () => {
      expect(translateSQL('SELECT * FROM users WHERE id = ?'))
        .toBe('SELECT * FROM users WHERE id = $1');
    });

    it('replaces multiple ? with incrementing $N', () => {
      expect(translateSQL('SELECT * FROM t WHERE a = ? AND b = ? AND c = ?'))
        .toBe('SELECT * FROM t WHERE a = $1 AND b = $2 AND c = $3');
    });

    it('leaves SQL without ? unchanged', () => {
      expect(translateSQL('SELECT 1')).toBe('SELECT 1');
    });
  });

  // ── INSERT OR REPLACE ──────────────────────────────────────────────
  describe('INSERT OR REPLACE', () => {
    it('translates to ON CONFLICT DO UPDATE SET with multiple columns', () => {
      const input = 'INSERT OR REPLACE INTO "config" ("key", "value") VALUES (?, ?)';
      const result = translateSQL(input);
      expect(result).toContain('INSERT INTO "config"');
      expect(result).toContain('ON CONFLICT ("key") DO UPDATE SET');
      expect(result).toContain('"value" = EXCLUDED."value"');
    });

    it('translates single-column INSERT OR REPLACE to DO NOTHING', () => {
      const input = 'INSERT OR REPLACE INTO tags (name) VALUES (?)';
      const result = translateSQL(input);
      expect(result).toContain('ON CONFLICT (name) DO NOTHING');
    });

    it('handles multiple non-PK columns in SET clause', () => {
      const input = 'INSERT OR REPLACE INTO user_settings (user_id, price_alerts, dark_mode) VALUES (?, ?, ?)';
      const result = translateSQL(input);
      expect(result).toContain('ON CONFLICT (user_id) DO UPDATE SET');
      expect(result).toContain('price_alerts = EXCLUDED.price_alerts');
      expect(result).toContain('dark_mode = EXCLUDED.dark_mode');
    });
  });

  // ── INSERT OR IGNORE ───────────────────────────────────────────────
  describe('INSERT OR IGNORE', () => {
    it('strips the OR IGNORE clause', () => {
      const input = 'INSERT OR IGNORE INTO visits (id, page) VALUES (?, ?)';
      const result = translateSQL(input);
      expect(result).not.toMatch(/OR IGNORE/i);
      expect(result).toMatch(/^INSERT INTO/);
    });
  });

  // ── datetime() functions ───────────────────────────────────────────
  describe('datetime translations', () => {
    it("converts datetime('now') to NOW()", () => {
      const input = "UPDATE users SET last_login = datetime('now') WHERE id = ?";
      expect(translateSQL(input)).toContain('NOW()');
      expect(translateSQL(input)).not.toContain("datetime('now')");
    });

    it("converts datetime('now', '-30 days') to NOW() + INTERVAL", () => {
      const input = "SELECT * FROM t WHERE c >= datetime('now', '-30 days')";
      const result = translateSQL(input);
      expect(result).toContain("NOW() + INTERVAL '-30 days'");
    });

    it("converts dynamic interval datetime('now', '-' || $N || ' days') to make_interval", () => {
      const input = "SELECT * FROM t WHERE c >= datetime('now', '-' || ? || ' days')";
      const result = translateSQL(input);
      expect(result).toContain('NOW() - make_interval(days => $1)');
    });

    it("converts positive dynamic interval to NOW() + make_interval", () => {
      const input = "UPDATE users SET locked_until = datetime('now', '+' || ? || ' minutes') WHERE id = ?";
      const result = translateSQL(input);
      expect(result).toContain('NOW() + make_interval(minutes => $1)');
    });

    it('handles hour and second units', () => {
      expect(translateSQL("SELECT * FROM t WHERE c >= datetime('now', '-2 hours')"))
        .toContain("NOW() + INTERVAL '-2 hours'");
      expect(translateSQL("SELECT * FROM t WHERE c >= datetime('now', '-5 seconds')"))
        .toContain("NOW() + INTERVAL '-5 seconds'");
    });
  });

  // ── date('now') ────────────────────────────────────────────────────
  describe('date translations', () => {
    it("converts date('now') to CURRENT_DATE", () => {
      const input = "SELECT * FROM t WHERE date(c) < date('now')";
      const result = translateSQL(input);
      expect(result).toContain('CURRENT_DATE');
      expect(result).not.toContain("date('now')");
    });
  });

  // ── strftime ───────────────────────────────────────────────────────
  describe('strftime translations', () => {
    it("converts strftime('%H', col) to LPAD(EXTRACT(HOUR ...))", () => {
      const input = "SELECT strftime('%H', created_at) AS hour FROM page_views";
      const result = translateSQL(input);
      expect(result).toContain('EXTRACT(HOUR FROM created_at::timestamp)');
      expect(result).toContain('LPAD');
    });

    it("converts strftime('%Y-W%W', col) to TO_CHAR with ISO week", () => {
      const input = "SELECT strftime('%Y-W%W', created_at) as week FROM users";
      const result = translateSQL(input);
      expect(result).toContain('TO_CHAR(created_at::timestamp');
      expect(result).toContain('IYYY');
    });

    it("converts strftime('%Y-%m-%dT%H:%M:%f', 'now') to NOW()::text", () => {
      const input = "DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now'))";
      const result = translateSQL(input);
      expect(result).toContain('NOW()::text');
    });

    it("converts unknown strftime with 'now' to NOW()::text (catch-all)", () => {
      const input = "SELECT strftime('%Y-%m-%d', 'now')";
      const result = translateSQL(input);
      expect(result).toContain('NOW()::text');
    });
  });

  // ── json_extract ───────────────────────────────────────────────────
  describe('json_extract', () => {
    it("converts json_extract(col, '$.key') to col::json->>'key'", () => {
      const input = "SELECT json_extract(sess, '$.userId') FROM sessions";
      const result = translateSQL(input);
      expect(result).toBe("SELECT sess::json->>'userId' FROM sessions");
    });
  });

  // ── AUTOINCREMENT ──────────────────────────────────────────────────
  describe('AUTOINCREMENT', () => {
    it('converts INTEGER PRIMARY KEY AUTOINCREMENT to SERIAL PRIMARY KEY', () => {
      const input = 'CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)';
      const result = translateSQL(input);
      expect(result).toContain('SERIAL PRIMARY KEY');
      expect(result).not.toContain('AUTOINCREMENT');
    });
  });

  // ── PRAGMA ─────────────────────────────────────────────────────────
  describe('PRAGMA handling', () => {
    it('returns null for PRAGMA statements', () => {
      expect(translateSQL('PRAGMA journal_mode = WAL')).toBeNull();
      expect(translateSQL('PRAGMA busy_timeout = 5000')).toBeNull();
    });
  });

  // ── sqlite_master ──────────────────────────────────────────────────
  describe('sqlite_master translations', () => {
    it('translates table list query to information_schema', () => {
      const input = "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'";
      const result = translateSQL(input);
      expect(result).toContain('information_schema.tables');
      expect(result).toContain("table_schema = 'public'");
    });

    it('translates table existence check', () => {
      const input = "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?";
      const result = translateSQL(input);
      expect(result).toContain('information_schema.tables');
      expect(result).toContain('table_name = $1');
    });

    it('translates name + sql listing query', () => {
      const input = "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'";
      const result = translateSQL(input);
      expect(result).toContain("'' AS sql");
      expect(result).toContain('information_schema.tables');
    });
  });

  // ── Edge cases ─────────────────────────────────────────────────────
  describe('edge cases', () => {
    it('returns empty string for empty input', () => {
      expect(translateSQL('')).toBe('');
    });

    it('passes through standard SQL unchanged', () => {
      const input = 'SELECT id, name FROM users ORDER BY id DESC LIMIT 10';
      expect(translateSQL(input)).toBe(input);
    });

    it('handles multiple translations in a single statement', () => {
      const input = "SELECT * FROM page_views WHERE created_at >= datetime('now', '-' || ? || ' days') AND session_hash = ?";
      const result = translateSQL(input);
      expect(result).toContain('make_interval(days => $1)');
      expect(result).toContain('session_hash = $2');
    });

    it('parameter numbering is correct with many placeholders', () => {
      const input = 'INSERT INTO t (a, b, c, d, e) VALUES (?, ?, ?, ?, ?)';
      const result = translateSQL(input);
      expect(result).toContain('$1');
      expect(result).toContain('$5');
      expect(result).not.toContain('?');
    });
  });
});
