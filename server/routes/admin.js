/**
 * Admin data API — extracted from the monolithic /admin route.
 *
 * Provides JSON endpoints for chart data, user/session tables,
 * and summary stats so the admin page can fetch them asynchronously.
 */
const express = require('express');
const fs = require('fs');
const path = require('path');
const db = require('../db');
const log = require('../logger').child({ module: 'admin' });

const router = express.Router();

// ─── Helpers ────────────────────────────────────────────────────

function getDbSize() {
  const dbPath = process.env.DB_PATH
    ? path.resolve(process.env.DB_PATH)
    : path.join(__dirname, '..', 'data.db');
  try { return fs.statSync(dbPath).size; } catch (_) { return 0; }
}

function parseSessionRows(sessionsRaw, userMap) {
  return sessionsRaw.map(s => {
    let parsed = {};
    try { parsed = JSON.parse(s.sess); } catch (_) {}
    const userId = parsed.userId || null;
    const owner = userId ? userMap[userId] : null;
    return {
      sid: s.sid,
      expire: s.expire,
      userId,
      userName: owner ? owner.name : null,
      userEmail: owner ? owner.email : null,
      ipHash: parsed.ipHash || null,
      ua: parsed.ua || null,
      lastSeen: parsed.lastSeen || null,
    };
  });
}

// ─── Data query functions ───────────────────────────────────────

function getSummaryStats() {
  const users = db.prepare('SELECT COUNT(*) as count FROM users').get();
  const sessions = db.prepare('SELECT COUNT(*) as count FROM sessions').get();
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all();
  return {
    userCount: users.count,
    sessionCount: sessions.count,
    tableCount: tables.length,
    tables: tables.map(t => t.name),
    dbSizeKB: +(getDbSize() / 1024).toFixed(1),
  };
}

function getUserChartData() {
  const regTrends = db.prepare(`
    SELECT date(created_at) as day, COUNT(*) as count
    FROM users GROUP BY date(created_at) ORDER BY day ASC
  `).all();

  let cumulative = 0;
  const cumulativeData = regTrends.map(r => {
    cumulative += r.count;
    return { day: r.day, total: cumulative };
  });

  const regWeekly = db.prepare(`
    SELECT strftime('%Y-W%W', created_at) as week, COUNT(*) as count
    FROM users GROUP BY strftime('%Y-W%W', created_at) ORDER BY week ASC
  `).all();

  const featureUsage = db.prepare(`
    SELECT
      SUM(price_alerts) as price_alerts_on,
      SUM(weekly_newsletter) as newsletter_on,
      SUM(dark_mode) as dark_mode_on,
      COUNT(*) as total
    FROM user_settings
  `).get();

  const planDist = db.prepare(`
    SELECT plan, COUNT(*) as count FROM users GROUP BY plan ORDER BY count DESC
  `).all();

  const activeSessions = db.prepare('SELECT COUNT(*) as count FROM sessions').get().count;

  const loginActivity = db.prepare(`
    SELECT name, login_count FROM users
    WHERE login_count > 0
    ORDER BY login_count DESC LIMIT 10
  `).all();

  const recentLogins = db.prepare(`
    SELECT date(last_login) as day, COUNT(*) as count
    FROM users
    WHERE last_login IS NOT NULL AND last_login >= datetime('now', '-30 days')
    GROUP BY date(last_login) ORDER BY day ASC
  `).all();

  return {
    regTrends,
    cumulativeData,
    regWeekly,
    featureUsage: {
      priceAlerts: featureUsage ? featureUsage.price_alerts_on || 0 : 0,
      newsletter: featureUsage ? featureUsage.newsletter_on || 0 : 0,
      darkMode: featureUsage ? featureUsage.dark_mode_on || 0 : 0,
      total: featureUsage ? featureUsage.total || 0 : 0,
    },
    planDist,
    activeSessions,
    loginActivity,
    recentLogins,
  };
}

function getSiteAnalytics() {
  const viewsPerDay = db.prepare(`
    SELECT date(created_at) as day, COUNT(*) as views, COUNT(DISTINCT session_hash) as visitors
    FROM page_views WHERE created_at >= datetime('now', '-30 days')
    GROUP BY date(created_at) ORDER BY day ASC
  `).all();

  const browsers = db.prepare(`
    SELECT ua_browser as name, COUNT(*) as count FROM page_views
    WHERE created_at >= datetime('now', '-30 days')
    GROUP BY ua_browser ORDER BY count DESC
  `).all();

  const devices = db.prepare(`
    SELECT ua_device as name, COUNT(*) as count FROM page_views
    WHERE created_at >= datetime('now', '-30 days')
    GROUP BY ua_device ORDER BY count DESC
  `).all();

  const referrers = db.prepare(`
    SELECT referrer, COUNT(*) as count FROM page_views
    WHERE referrer IS NOT NULL AND referrer != '' AND created_at >= datetime('now', '-30 days')
    GROUP BY referrer ORDER BY count DESC LIMIT 10
  `).all();

  const events = db.prepare(`
    SELECT event, COUNT(*) as count FROM analytics_events
    WHERE created_at >= datetime('now', '-30 days')
    GROUP BY event ORDER BY count DESC LIMIT 15
  `).all();

  const totals = db.prepare(`
    SELECT COUNT(*) as total_views, COUNT(DISTINCT session_hash) as unique_visitors
    FROM page_views WHERE created_at >= datetime('now', '-30 days')
  `).get();

  return {
    viewsPerDay,
    browsers,
    devices,
    referrers,
    events,
    totalViews: totals.total_views,
    uniqueVisitors: totals.unique_visitors,
  };
}

function getUsersTable() {
  return db.prepare(
    'SELECT id, name, email, plan, avatar, avatar_bg, created_at, last_login, login_count, last_settings_change FROM users'
  ).all();
}

function getSettingsTable() {
  return db.prepare(`
    SELECT u.id, u.name, u.email, s.price_alerts, s.weekly_newsletter, s.dark_mode
    FROM users u LEFT JOIN user_settings s ON u.id = s.user_id
  `).all();
}

function getSessionsTable() {
  const users = getUsersTable();
  const userMap = {};
  users.forEach(u => { userMap[u.id] = u; });

  const sessionsRaw = db.prepare('SELECT sid, sess, expire FROM sessions').all();
  return parseSessionRows(sessionsRaw, userMap);
}

// ─── API routes ─────────────────────────────────────────────────

// GET /api/admin/summary — top-level stats (user count, session count, etc.)
router.get('/summary', (req, res) => {
  try {
    res.json(getSummaryStats());
  } catch (err) {
    log.error({ err }, 'Admin summary query failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// GET /api/admin/charts/users — user-related chart data
router.get('/charts/users', (req, res) => {
  try {
    res.json(getUserChartData());
  } catch (err) {
    log.error({ err }, 'Admin user charts query failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// GET /api/admin/charts/analytics — site analytics chart data
router.get('/charts/analytics', (req, res) => {
  try {
    res.json(getSiteAnalytics());
  } catch (err) {
    log.error({ err }, 'Admin site analytics query failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// GET /api/admin/users — users table data
router.get('/users', (req, res) => {
  try {
    res.json({ users: getUsersTable() });
  } catch (err) {
    log.error({ err }, 'Admin users query failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// GET /api/admin/settings — user settings table data
router.get('/settings', (req, res) => {
  try {
    res.json({ settings: getSettingsTable() });
  } catch (err) {
    log.error({ err }, 'Admin settings query failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// GET /api/admin/sessions — sessions table data
router.get('/sessions', (req, res) => {
  try {
    res.json({ sessions: getSessionsTable() });
  } catch (err) {
    log.error({ err }, 'Admin sessions query failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

module.exports = router;
module.exports.getSummaryStats = getSummaryStats;
module.exports.getUserChartData = getUserChartData;
module.exports.getSiteAnalytics = getSiteAnalytics;
module.exports.getUsersTable = getUsersTable;
module.exports.getSettingsTable = getSettingsTable;
module.exports.getSessionsTable = getSessionsTable;
