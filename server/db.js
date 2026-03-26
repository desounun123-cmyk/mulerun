const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = process.env.DB_PATH
  ? require('path').resolve(process.env.DB_PATH)
  : path.join(__dirname, 'data.db');

const db = new Database(DB_PATH);

// Enable WAL mode and busy timeout
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');

// Create tables
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

// Add avatar column if missing (migration)
const cols = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
if (!cols.includes('avatar')) {
  db.exec("ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT NULL");
}
if (!cols.includes('avatar_bg')) {
  db.exec("ALTER TABLE users ADD COLUMN avatar_bg TEXT DEFAULT NULL");
}

// User activity tracking columns (migration)
if (!cols.includes('last_login')) {
  db.exec("ALTER TABLE users ADD COLUMN last_login TEXT DEFAULT NULL");
}
if (!cols.includes('login_count')) {
  db.exec("ALTER TABLE users ADD COLUMN login_count INTEGER NOT NULL DEFAULT 0");
}
if (!cols.includes('last_settings_change')) {
  db.exec("ALTER TABLE users ADD COLUMN last_settings_change TEXT DEFAULT NULL");
}

// Password reset tokens table
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

// Privacy-respecting analytics — page views
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
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// Analytics events (feature usage, button clicks, etc.)
db.exec(`
  CREATE TABLE IF NOT EXISTS analytics_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,
    meta TEXT DEFAULT NULL,
    session_hash TEXT DEFAULT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// Seed demo user if not present
const existingDemo = db.prepare('SELECT id FROM users WHERE email = ?').get('demo@oil.com');
if (!existingDemo) {
  const hash = bcrypt.hashSync('oil2026', 10);
  const result = db.prepare(
    'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)'
  ).run('Demo', 'demo@oil.com', hash);

  db.prepare(
    'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode) VALUES (?, 1, 0, 1)'
  ).run(result.lastInsertRowid);
}

// Seed admin user if not present
const existingAdmin = db.prepare('SELECT id FROM users WHERE email = ?').get('siteadmin@oil.com');
if (!existingAdmin) {
  const adminHash = bcrypt.hashSync('nimdaetis123&', 10);
  const adminResult = db.prepare(
    'INSERT INTO users (name, email, password_hash, plan) VALUES (?, ?, ?, ?)'
  ).run('Admin', 'siteadmin@oil.com', adminHash, 'Admin');

  db.prepare(
    'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode) VALUES (?, 1, 1, 1)'
  ).run(adminResult.lastInsertRowid);
} else {
  db.prepare("UPDATE users SET plan = 'Admin', name = 'Admin' WHERE email = 'siteadmin@oil.com'").run();
}

module.exports = db;
