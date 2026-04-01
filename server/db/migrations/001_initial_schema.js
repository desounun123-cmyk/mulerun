'use strict';

/**
 * Migration 001 — Initial Schema
 *
 * Consolidates all existing tables and columns into a single versioned
 * migration.  Every statement uses IF NOT EXISTS / column-exists checks
 * so it is safe to run against databases that already have this schema.
 *
 * This migration represents the full schema as of the migration system
 * introduction.  All future changes go in 002+.
 */

// ── Helpers ─────────────────────────────────────────────────────────

/** Check if a column exists in a table (works for both SQLite and PG). */
function hasColumn(db, engine, table, column) {
  if (engine === 'postgresql') {
    const row = db.prepare(
      "SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = ? AND column_name = ?"
    ).get(table, column);
    return !!row;
  }
  // SQLite
  const cols = db.pragma('table_info(' + table + ')');
  return cols.some(c => c.name === column);
}

/** Add a column if it doesn't already exist. */
function addColumnIfMissing(db, engine, table, column, definition) {
  if (hasColumn(db, engine, table, column)) return;
  db.exec('ALTER TABLE ' + table + ' ADD COLUMN ' + column + ' ' + definition);
}

// ── UP ──────────────────────────────────────────────────────────────

function up(db, engine) {
  if (engine === 'postgresql') {
    upPostgres(db);
  } else {
    upSQLite(db);
  }
}

function upSQLite(db) {
  // ── Core tables ─────────────────────────────────────────────────
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

  // ── Users table columns ─────────────────────────────────────────
  addColumnIfMissing(db, 'sqlite', 'users', 'avatar', "TEXT DEFAULT NULL");
  addColumnIfMissing(db, 'sqlite', 'users', 'avatar_bg', "TEXT DEFAULT NULL");
  addColumnIfMissing(db, 'sqlite', 'users', 'last_login', "TEXT DEFAULT NULL");
  addColumnIfMissing(db, 'sqlite', 'users', 'login_count', "INTEGER NOT NULL DEFAULT 0");
  addColumnIfMissing(db, 'sqlite', 'users', 'last_settings_change', "TEXT DEFAULT NULL");
  addColumnIfMissing(db, 'sqlite', 'users', 'oauth_provider', "TEXT DEFAULT NULL");
  addColumnIfMissing(db, 'sqlite', 'users', 'oauth_id', "TEXT DEFAULT NULL");
  addColumnIfMissing(db, 'sqlite', 'users', 'failed_login_attempts', "INTEGER NOT NULL DEFAULT 0");
  addColumnIfMissing(db, 'sqlite', 'users', 'locked_until', "TEXT DEFAULT NULL");
  addColumnIfMissing(db, 'sqlite', 'users', 'totp_secret', "TEXT DEFAULT NULL");
  addColumnIfMissing(db, 'sqlite', 'users', 'totp_enabled', "INTEGER NOT NULL DEFAULT 0");
  addColumnIfMissing(db, 'sqlite', 'users', 'email_verified', "INTEGER NOT NULL DEFAULT 0");

  // ── User settings columns ──────────────────────────────────────
  addColumnIfMissing(db, 'sqlite', 'user_settings', 'notify_email', "INTEGER NOT NULL DEFAULT 0");
  addColumnIfMissing(db, 'sqlite', 'user_settings', 'notify_inapp', "INTEGER NOT NULL DEFAULT 1");
  addColumnIfMissing(db, 'sqlite', 'user_settings', 'notify_push', "INTEGER NOT NULL DEFAULT 1");
  addColumnIfMissing(db, 'sqlite', 'user_settings', 'sync_version', "INTEGER NOT NULL DEFAULT 1");

  // ── Email verification tokens ───────────────────────────────────
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

  // ── Price alert rules ───────────────────────────────────────────
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

  // ── Password reset tokens ──────────────────────────────────────
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

  // ── Analytics: page views ──────────────────────────────────────
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
      bot_score INTEGER NOT NULL DEFAULT 0,
      bot_signals TEXT DEFAULT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_pv_created ON page_views(created_at);
  `);

  // bot columns for existing page_views tables
  addColumnIfMissing(db, 'sqlite', 'page_views', 'bot_score', "INTEGER NOT NULL DEFAULT 0");
  addColumnIfMissing(db, 'sqlite', 'page_views', 'bot_signals', "TEXT DEFAULT NULL");

  // ── Analytics: events ──────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS analytics_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event TEXT NOT NULL,
      meta TEXT DEFAULT NULL,
      session_hash TEXT DEFAULT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_ae_created ON analytics_events(created_at);
  `);

  // ── Analytics: daily rollups ───────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS daily_stats (
      day TEXT NOT NULL,
      page TEXT NOT NULL DEFAULT '/',
      ua_browser TEXT DEFAULT NULL,
      ua_os TEXT DEFAULT NULL,
      ua_device TEXT DEFAULT 'desktop',
      referrer TEXT DEFAULT NULL,
      views INTEGER NOT NULL DEFAULT 0,
      visitors INTEGER NOT NULL DEFAULT 0,
      bot_views INTEGER NOT NULL DEFAULT 0,
      bot_sessions INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_ds_day_page_dims
      ON daily_stats(day, page, COALESCE(ua_browser,''), COALESCE(ua_os,''), COALESCE(ua_device,''), COALESCE(referrer,''));
    CREATE INDEX IF NOT EXISTS idx_ds_day ON daily_stats(day);
  `);

  // ── Analytics: daily event rollups ─────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS daily_event_stats (
      day TEXT NOT NULL,
      event TEXT NOT NULL,
      count INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_des_day_event
      ON daily_event_stats(day, event);
    CREATE INDEX IF NOT EXISTS idx_des_day ON daily_event_stats(day);
  `);

  // ── Notifications ──────────────────────────────────────────────
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

  // ── Push subscriptions ─────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      endpoint TEXT UNIQUE NOT NULL,
      keys_p256dh TEXT NOT NULL,
      keys_auth TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_push_sub_user ON push_subscriptions(user_id);
  `);

  // ── Config key-value store ─────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS config (
      key TEXT PRIMARY KEY,
      value TEXT
    );
  `);
}

function upPostgres(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      plan TEXT NOT NULL DEFAULT 'Free',
      avatar TEXT DEFAULT NULL,
      avatar_bg TEXT DEFAULT NULL,
      last_login TIMESTAMP DEFAULT NULL,
      login_count INTEGER NOT NULL DEFAULT 0,
      last_settings_change TIMESTAMP DEFAULT NULL,
      oauth_provider TEXT DEFAULT NULL,
      oauth_id TEXT DEFAULT NULL,
      failed_login_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until TIMESTAMP DEFAULT NULL,
      totp_secret TEXT DEFAULT NULL,
      totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
      email_verified BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS user_settings (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      price_alerts BOOLEAN NOT NULL DEFAULT TRUE,
      weekly_newsletter BOOLEAN NOT NULL DEFAULT FALSE,
      dark_mode BOOLEAN NOT NULL DEFAULT TRUE,
      notify_email BOOLEAN NOT NULL DEFAULT FALSE,
      notify_inapp BOOLEAN NOT NULL DEFAULT TRUE,
      notify_push BOOLEAN NOT NULL DEFAULT TRUE,
      sync_version INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS email_verification_tokens (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token TEXT UNIQUE NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      used BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS price_alert_rules (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      product TEXT NOT NULL,
      direction TEXT NOT NULL CHECK(direction IN ('above','below')),
      threshold DOUBLE PRECISION NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      triggered BOOLEAN NOT NULL DEFAULT FALSE,
      last_triggered_at TIMESTAMP DEFAULT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_par_user ON price_alert_rules(user_id, active);

    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token TEXT UNIQUE NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      used BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS page_views (
      id SERIAL PRIMARY KEY,
      page TEXT NOT NULL DEFAULT '/',
      referrer TEXT DEFAULT NULL,
      screen_w INTEGER DEFAULT NULL,
      screen_h INTEGER DEFAULT NULL,
      lang TEXT DEFAULT NULL,
      ua_browser TEXT DEFAULT NULL,
      ua_os TEXT DEFAULT NULL,
      ua_device TEXT DEFAULT 'desktop',
      session_hash TEXT DEFAULT NULL,
      bot_score INTEGER NOT NULL DEFAULT 0,
      bot_signals TEXT DEFAULT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_pv_created ON page_views(created_at);

    CREATE TABLE IF NOT EXISTS analytics_events (
      id SERIAL PRIMARY KEY,
      event TEXT NOT NULL,
      meta TEXT DEFAULT NULL,
      session_hash TEXT DEFAULT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_ae_created ON analytics_events(created_at);

    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL DEFAULT 'info',
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      read BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, read, created_at);

    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      endpoint TEXT UNIQUE NOT NULL,
      keys_p256dh TEXT NOT NULL,
      keys_auth TEXT NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_push_sub_user ON push_subscriptions(user_id);

    CREATE TABLE IF NOT EXISTS config (
      key TEXT PRIMARY KEY,
      value TEXT
    );

    CREATE TABLE IF NOT EXISTS sessions (
      sid TEXT PRIMARY KEY,
      sess TEXT NOT NULL,
      expire TIMESTAMP NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_expire ON sessions(expire);
  `);
}

// ── DOWN ─────────────────────────────────────────────────────────────
// Dropping the initial schema means dropping everything.  This is
// intentionally destructive — only use in development or testing.

function down(db, engine) {
  const tables = [
    'push_subscriptions', 'notifications', 'daily_event_stats',
    'daily_stats', 'analytics_events', 'page_views',
    'password_reset_tokens', 'price_alert_rules',
    'email_verification_tokens', 'user_settings', 'config',
  ];

  if (engine === 'postgresql') {
    tables.push('sessions');
  }

  // users last (other tables reference it)
  tables.push('users');

  for (const t of tables) {
    db.exec('DROP TABLE IF EXISTS ' + t + ' CASCADE');
  }
}

module.exports = {
  version: 1,
  name: 'initial_schema',
  up,
  down,
};
