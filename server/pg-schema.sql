-- ══════════════════════════════════════════════════════════════════════════
-- OIL Benchmarks — PostgreSQL Schema
--
-- Complete DDL for running the application on PostgreSQL instead of SQLite.
-- This file is idempotent: all statements use IF NOT EXISTS.
--
-- Usage:
--   createdb oilbench
--   psql -U your_user -d oilbench -f pg-schema.sql
--
-- After creating the schema, import data from SQLite:
--   node server/scripts/migrate-to-postgres.js --out ./pg-export
--   psql -d oilbench -f pg-export/migration.sql
--
-- Then start the server with:
--   DATABASE_URL=postgres://user:pass@localhost:5432/oilbench node server/index.js
-- ══════════════════════════════════════════════════════════════════════════

BEGIN;

-- ── Core: Users ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
  id              SERIAL PRIMARY KEY,
  name            TEXT NOT NULL,
  email           TEXT UNIQUE NOT NULL,
  password_hash   TEXT NOT NULL,
  plan            TEXT NOT NULL DEFAULT 'Free',
  avatar          TEXT DEFAULT NULL,
  avatar_bg       TEXT DEFAULT NULL,
  last_login      TIMESTAMP DEFAULT NULL,
  login_count     INTEGER NOT NULL DEFAULT 0,
  last_settings_change TIMESTAMP DEFAULT NULL,
  oauth_provider  TEXT DEFAULT NULL,
  oauth_id        TEXT DEFAULT NULL,
  failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until    TIMESTAMP DEFAULT NULL,
  totp_secret     TEXT DEFAULT NULL,
  totp_enabled    BOOLEAN NOT NULL DEFAULT FALSE,
  email_verified  BOOLEAN NOT NULL DEFAULT FALSE,
  created_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

-- ── Core: User Settings ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS user_settings (
  user_id             INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  price_alerts        BOOLEAN NOT NULL DEFAULT TRUE,
  weekly_newsletter   BOOLEAN NOT NULL DEFAULT FALSE,
  dark_mode           BOOLEAN NOT NULL DEFAULT TRUE,
  notify_email        BOOLEAN NOT NULL DEFAULT FALSE,
  notify_inapp        BOOLEAN NOT NULL DEFAULT TRUE,
  notify_push         BOOLEAN NOT NULL DEFAULT TRUE
);

-- ── Auth: Email Verification Tokens ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS email_verification_tokens (
  id          SERIAL PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token       TEXT UNIQUE NOT NULL,
  expires_at  TIMESTAMP NOT NULL,
  used        BOOLEAN NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMP NOT NULL DEFAULT NOW()
);

-- ── Auth: Password Reset Tokens ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id          SERIAL PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token       TEXT UNIQUE NOT NULL,
  expires_at  TIMESTAMP NOT NULL,
  used        BOOLEAN NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMP NOT NULL DEFAULT NOW()
);

-- ── Feature: Price Alert Rules ───────────────────────────────────────────

CREATE TABLE IF NOT EXISTS price_alert_rules (
  id                SERIAL PRIMARY KEY,
  user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  product           TEXT NOT NULL,
  direction         TEXT NOT NULL CHECK (direction IN ('above', 'below')),
  threshold         DOUBLE PRECISION NOT NULL,
  active            BOOLEAN NOT NULL DEFAULT TRUE,
  triggered         BOOLEAN NOT NULL DEFAULT FALSE,
  last_triggered_at TIMESTAMP DEFAULT NULL,
  created_at        TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_par_user
  ON price_alert_rules (user_id, active);

-- ── Analytics: Page Views ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS page_views (
  id            SERIAL PRIMARY KEY,
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
  created_at    TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pv_created
  ON page_views (created_at);

-- ── Analytics: Events ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS analytics_events (
  id            SERIAL PRIMARY KEY,
  event         TEXT NOT NULL,
  meta          TEXT DEFAULT NULL,
  session_hash  TEXT DEFAULT NULL,
  created_at    TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ae_created
  ON analytics_events (created_at);

-- ── Notifications ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS notifications (
  id          SERIAL PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type        TEXT NOT NULL DEFAULT 'info',
  title       TEXT NOT NULL,
  message     TEXT NOT NULL,
  read        BOOLEAN NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notif_user
  ON notifications (user_id, read, created_at);

-- ── Push Subscriptions (Web Push API) ────────────────────────────────────

CREATE TABLE IF NOT EXISTS push_subscriptions (
  id            SERIAL PRIMARY KEY,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  endpoint      TEXT NOT NULL,
  keys_p256dh   TEXT NOT NULL,
  keys_auth     TEXT NOT NULL,
  created_at    TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_push_endpoint
  ON push_subscriptions (endpoint);

CREATE INDEX IF NOT EXISTS idx_push_user
  ON push_subscriptions (user_id);

-- ── Config (key-value store for VAPID keys, etc.) ────────────────────────

CREATE TABLE IF NOT EXISTS config (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- ── Sessions (used by connect-pg-simple) ─────────────────────────────────

CREATE TABLE IF NOT EXISTS sessions (
  sid     TEXT PRIMARY KEY,
  sess    TEXT NOT NULL,
  expire  TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_expire
  ON sessions (expire);

-- ══════════════════════════════════════════════════════════════════════════
-- Performance recommendations for production:
--
--   -- Partial index for active alerts only (most queries filter on active=true)
--   CREATE INDEX IF NOT EXISTS idx_par_active
--     ON price_alert_rules (user_id) WHERE active = TRUE;
--
--   -- Covering index for the analytics dashboard date-range queries
--   CREATE INDEX IF NOT EXISTS idx_pv_created
--     ON page_views (created_at) INCLUDE (session_hash, ua_browser, ua_device);
--
--   -- Partial index for unread notifications
--   CREATE INDEX IF NOT EXISTS idx_notif_unread
--     ON notifications (user_id, created_at) WHERE read = FALSE;
--
--   -- Autovacuum tuning for high-write tables
--   ALTER TABLE page_views SET (autovacuum_vacuum_scale_factor = 0.05);
--   ALTER TABLE analytics_events SET (autovacuum_vacuum_scale_factor = 0.05);
--   ALTER TABLE sessions SET (autovacuum_vacuum_scale_factor = 0.02);
-- ══════════════════════════════════════════════════════════════════════════

COMMIT;
