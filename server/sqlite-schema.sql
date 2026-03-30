-- ══════════════════════════════════════════════════════════════════════════
-- OIL Benchmarks — SQLite Schema (complete, post-migration)
--
-- This is the canonical SQLite DDL representing the full schema after all
-- incremental ALTER TABLE migrations have been applied. Use this file to
-- create a fresh database from scratch instead of relying on the runtime
-- migration checks in db.js.
--
-- Usage:
--   sqlite3 data.db < sqlite-schema.sql
--
-- Notes:
--   - All tables use IF NOT EXISTS for idempotency
--   - Booleans are stored as INTEGER (0/1) per SQLite convention
--   - Timestamps are stored as TEXT in ISO-8601 format
--   - AUTOINCREMENT ensures rowids are never reused after deletion
--   - Foreign keys require PRAGMA foreign_keys = ON at runtime
-- ══════════════════════════════════════════════════════════════════════════

PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;

-- ── Core: Users ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
  id                      INTEGER PRIMARY KEY AUTOINCREMENT,
  name                    TEXT NOT NULL,
  email                   TEXT UNIQUE NOT NULL,
  password_hash           TEXT NOT NULL,
  plan                    TEXT NOT NULL DEFAULT 'Free',
  avatar                  TEXT DEFAULT NULL,
  avatar_bg               TEXT DEFAULT NULL,
  last_login              TEXT DEFAULT NULL,
  login_count             INTEGER NOT NULL DEFAULT 0,
  last_settings_change    TEXT DEFAULT NULL,
  oauth_provider          TEXT DEFAULT NULL,
  oauth_id                TEXT DEFAULT NULL,
  failed_login_attempts   INTEGER NOT NULL DEFAULT 0,
  locked_until            TEXT DEFAULT NULL,
  totp_secret             TEXT DEFAULT NULL,
  totp_enabled            INTEGER NOT NULL DEFAULT 0,
  email_verified          INTEGER NOT NULL DEFAULT 0,
  created_at              TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Core: User Settings ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS user_settings (
  user_id             INTEGER PRIMARY KEY,
  price_alerts        INTEGER NOT NULL DEFAULT 1,
  weekly_newsletter   INTEGER NOT NULL DEFAULT 0,
  dark_mode           INTEGER NOT NULL DEFAULT 1,
  notify_email        INTEGER NOT NULL DEFAULT 0,
  notify_inapp        INTEGER NOT NULL DEFAULT 1,
  notify_push         INTEGER NOT NULL DEFAULT 1,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ── Auth: Email Verification Tokens ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS email_verification_tokens (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL,
  token       TEXT UNIQUE NOT NULL,
  expires_at  TEXT NOT NULL,
  used        INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ── Auth: Password Reset Tokens ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL,
  token       TEXT UNIQUE NOT NULL,
  expires_at  TEXT NOT NULL,
  used        INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ── Feature: Price Alert Rules ───────────────────────────────────────────

CREATE TABLE IF NOT EXISTS price_alert_rules (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id           INTEGER NOT NULL,
  product           TEXT NOT NULL,
  direction         TEXT NOT NULL CHECK(direction IN ('above','below')),
  threshold         REAL NOT NULL,
  active            INTEGER NOT NULL DEFAULT 1,
  triggered         INTEGER NOT NULL DEFAULT 0,
  last_triggered_at TEXT DEFAULT NULL,
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_par_user
  ON price_alert_rules(user_id, active);

-- ── Analytics: Page Views ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS page_views (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  page          TEXT NOT NULL DEFAULT '/',
  referrer      TEXT DEFAULT NULL,
  screen_w      INTEGER DEFAULT NULL,
  screen_h      INTEGER DEFAULT NULL,
  lang          TEXT DEFAULT NULL,
  ua_browser    TEXT DEFAULT NULL,
  ua_os         TEXT DEFAULT NULL,
  ua_device     TEXT DEFAULT 'desktop',
  session_hash  TEXT DEFAULT NULL,
  bot_score     INTEGER NOT NULL DEFAULT 0,
  bot_signals   TEXT DEFAULT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Analytics: Events ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS analytics_events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  event         TEXT NOT NULL,
  meta          TEXT DEFAULT NULL,
  session_hash  TEXT DEFAULT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Notifications ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS notifications (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL,
  type        TEXT NOT NULL DEFAULT 'info',
  title       TEXT NOT NULL,
  message     TEXT NOT NULL,
  read        INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_notif_user
  ON notifications(user_id, read, created_at);

-- ── Push Subscriptions (Web Push API) ────────────────────────────────────

CREATE TABLE IF NOT EXISTS push_subscriptions (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL,
  endpoint      TEXT NOT NULL,
  keys_p256dh   TEXT NOT NULL,
  keys_auth     TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_push_endpoint
  ON push_subscriptions(endpoint);

CREATE INDEX IF NOT EXISTS idx_push_user
  ON push_subscriptions(user_id);

-- ── Config (key-value store for VAPID keys, etc.) ────────────────────────

CREATE TABLE IF NOT EXISTS config (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- ── Sessions (managed by better-sqlite3-session-store) ───────────────────
-- Note: This table is normally created automatically by the session store
-- module at runtime. It is included here for documentation and for manual
-- database provisioning.

CREATE TABLE IF NOT EXISTS sessions (
  sid     TEXT PRIMARY KEY,
  sess    TEXT NOT NULL,
  expire  TEXT NOT NULL
);

-- ══════════════════════════════════════════════════════════════════════════
-- Schema summary
--
--   11 tables:
--     users, user_settings, email_verification_tokens, password_reset_tokens,
--     price_alert_rules, page_views, analytics_events, notifications,
--     push_subscriptions, config, sessions
--
--   5 indexes:
--     idx_par_user           — price_alert_rules(user_id, active)
--     idx_notif_user         — notifications(user_id, read, created_at)
--     idx_push_endpoint      — push_subscriptions(endpoint) UNIQUE
--     idx_push_user          — push_subscriptions(user_id)
--     (sessions PK)          — sessions(sid)
--
--   6 foreign keys (all ON DELETE CASCADE):
--     user_settings.user_id       → users.id
--     email_verification_tokens   → users.id
--     password_reset_tokens       → users.id
--     price_alert_rules           → users.id
--     notifications               → users.id
--     push_subscriptions          → users.id
--
--   Runtime pragmas (set by db.js, not in this file):
--     journal_mode = WAL
--     busy_timeout = 5000
--     wal_autocheckpoint = 1000 (default, configurable via WAL_AUTOCHECKPOINT)
-- ══════════════════════════════════════════════════════════════════════════
