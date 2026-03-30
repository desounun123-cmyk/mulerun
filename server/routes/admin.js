/**
 * Admin data API — extracted from the monolithic /admin route.
 *
 * Provides JSON endpoints for chart data, user/session tables,
 * and summary stats so the admin page can fetch them asynchronously.
 */
const express = require('express');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const db = require('../db/db');
const log = require('../utils/logger').child({ module: 'admin' });

const router = express.Router();

// ─── Pagination helper ─────────────────────────────────────────
// Parses ?page=&limit= from query string. Returns safe integers.
// Defaults: page 1, limit 50 (or 25 for Save-Data clients), max limit 200.
function parsePagination(query, defaultLimit = 50, saveData = false) {
  const MAX_LIMIT = 200;
  let page = parseInt(query.page, 10) || 1;
  let limit = parseInt(query.limit, 10) || (saveData ? Math.min(defaultLimit, 25) : defaultLimit);
  if (page < 1) page = 1;
  if (limit < 1) limit = 1;
  if (limit > MAX_LIMIT) limit = MAX_LIMIT;
  const offset = (page - 1) * limit;
  return { page, limit, offset };
}

// ─── Adaptive quality helper ───────────────────────────────────
// Trims array-based chart data when Save-Data or slow connection is detected.
// Keeps every Nth item to reduce payload, always preserving first and last.
function trimChartArray(arr, maxPoints) {
  if (!Array.isArray(arr) || arr.length <= maxPoints) return arr;
  const step = Math.ceil(arr.length / maxPoints);
  const result = [];
  for (let i = 0; i < arr.length; i += step) result.push(arr[i]);
  if (result[result.length - 1] !== arr[arr.length - 1]) result.push(arr[arr.length - 1]);
  return result;
}

function isSaveDataRequest(res) {
  return res.locals && res.locals.saveData;
}

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

function getUsersTable(limit, offset) {
  const total = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  const users = db.prepare(
    'SELECT id, name, email, plan, avatar, avatar_bg, created_at, last_login, login_count, last_settings_change FROM users ORDER BY id ASC LIMIT ? OFFSET ?'
  ).all(limit, offset);
  return { users, total };
}

function getSettingsTable(limit, offset) {
  const total = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  const settings = db.prepare(`
    SELECT u.id, u.name, u.email, s.price_alerts, s.weekly_newsletter, s.dark_mode
    FROM users u LEFT JOIN user_settings s ON u.id = s.user_id
    ORDER BY u.id ASC LIMIT ? OFFSET ?
  `).all(limit, offset);
  return { settings, total };
}

function getSessionsTable(limit, offset) {
  const users = db.prepare('SELECT id, name, email FROM users').all();
  const userMap = {};
  users.forEach(u => { userMap[u.id] = u; });

  const total = db.prepare('SELECT COUNT(*) as count FROM sessions').get().count;
  const sessionsRaw = db.prepare('SELECT sid, sess, expire FROM sessions LIMIT ? OFFSET ?').all(limit, offset);
  return { sessions: parseSessionRows(sessionsRaw, userMap), total };
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
    const data = getUserChartData();
    if (isSaveDataRequest(res)) {
      data.regTrends = trimChartArray(data.regTrends, 30);
      data.cumulativeData = trimChartArray(data.cumulativeData, 30);
      data.regWeekly = trimChartArray(data.regWeekly, 20);
      data.recentLogins = trimChartArray(data.recentLogins, 15);
      data.loginActivity = data.loginActivity.slice(0, 5);
    }
    res.json(data);
  } catch (err) {
    log.error({ err }, 'Admin user charts query failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// GET /api/admin/charts/analytics — site analytics chart data
router.get('/charts/analytics', (req, res) => {
  try {
    const data = getSiteAnalytics();
    if (isSaveDataRequest(res)) {
      data.viewsPerDay = trimChartArray(data.viewsPerDay, 15);
      data.browsers = data.browsers.slice(0, 5);
      data.devices = data.devices.slice(0, 5);
      data.referrers = data.referrers.slice(0, 5);
      data.events = data.events.slice(0, 8);
    }
    res.json(data);
  } catch (err) {
    log.error({ err }, 'Admin site analytics query failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// GET /api/admin/users — users table data (paginated: ?page=1&limit=50)
router.get('/users', (req, res) => {
  try {
    const { page, limit, offset } = parsePagination(req.query, 50, isSaveDataRequest(res));
    const { users, total } = getUsersTable(limit, offset);
    res.json({ users, page, limit, total, totalPages: Math.ceil(total / limit) });
  } catch (err) {
    log.error({ err }, 'Admin users query failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// GET /api/admin/settings — user settings table data (paginated: ?page=1&limit=50)
router.get('/settings', (req, res) => {
  try {
    const { page, limit, offset } = parsePagination(req.query, 50, isSaveDataRequest(res));
    const { settings, total } = getSettingsTable(limit, offset);
    res.json({ settings, page, limit, total, totalPages: Math.ceil(total / limit) });
  } catch (err) {
    log.error({ err }, 'Admin settings query failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// GET /api/admin/sessions — sessions table data (paginated: ?page=1&limit=50)
router.get('/sessions', (req, res) => {
  try {
    const { page, limit, offset } = parsePagination(req.query, 50, isSaveDataRequest(res));
    const { sessions, total } = getSessionsTable(limit, offset);
    res.json({ sessions, page, limit, total, totalPages: Math.ceil(total / limit) });
  } catch (err) {
    log.error({ err }, 'Admin sessions query failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// ─── Bulk Export ────────────────────────────────────────────────
// GET /api/admin/export?format=json  (default)
// GET /api/admin/export?format=csv
//
// Streams a full dump of users, user_settings, page_views, analytics_events,
// sessions, notifications, and price_alert_rules as a single downloadable file.

function getAllUsers() {
  return db.prepare(`
    SELECT id, name, email, plan, avatar, avatar_bg,
           created_at, last_login, login_count, last_settings_change,
           oauth_provider, email_verified, totp_enabled,
           failed_login_attempts, locked_until
    FROM users ORDER BY id ASC
  `).all();
}

function getAllSettings() {
  return db.prepare(`
    SELECT u.id AS user_id, u.name, u.email,
           s.price_alerts, s.weekly_newsletter, s.dark_mode,
           s.notify_email, s.notify_inapp, s.notify_push
    FROM users u LEFT JOIN user_settings s ON u.id = s.user_id
    ORDER BY u.id ASC
  `).all();
}

function getAllPageViews() {
  return db.prepare(`
    SELECT id, page, referrer, screen_w, screen_h, lang,
           ua_browser, ua_os, ua_device, session_hash, created_at
    FROM page_views ORDER BY id ASC
  `).all();
}

function getAllAnalyticsEvents() {
  return db.prepare(`
    SELECT id, event, meta, session_hash, created_at
    FROM analytics_events ORDER BY id ASC
  `).all();
}

function getAllSessions() {
  const users = db.prepare('SELECT id, name, email FROM users').all();
  const userMap = {};
  users.forEach(u => { userMap[u.id] = u; });
  const raw = db.prepare('SELECT sid, sess, expire FROM sessions ORDER BY expire DESC').all();
  return parseSessionRows(raw, userMap);
}

function getAllNotifications() {
  try {
    return db.prepare(`
      SELECT n.id, n.user_id, u.name AS user_name, n.type, n.title, n.message, n.read, n.created_at
      FROM notifications n LEFT JOIN users u ON n.user_id = u.id
      ORDER BY n.id ASC
    `).all();
  } catch (_) { return []; }
}

function getAllPriceAlertRules() {
  try {
    return db.prepare(`
      SELECT r.id, r.user_id, u.name AS user_name, r.product, r.direction, r.threshold,
             r.active, r.triggered, r.last_triggered_at, r.created_at
      FROM price_alert_rules r LEFT JOIN users u ON r.user_id = u.id
      ORDER BY r.id ASC
    `).all();
  } catch (_) { return []; }
}

function buildFullExport() {
  return {
    exportedAt: new Date().toISOString(),
    users: getAllUsers(),
    settings: getAllSettings(),
    pageViews: getAllPageViews(),
    analyticsEvents: getAllAnalyticsEvents(),
    sessions: getAllSessions(),
    notifications: getAllNotifications(),
    priceAlertRules: getAllPriceAlertRules(),
  };
}

/**
 * Convert an array of objects to CSV string.
 * Handles nested values by JSON-stringifying them.
 */
function arrayToCsv(rows, sectionName) {
  if (!rows || rows.length === 0) return '';
  const headers = Object.keys(rows[0]);
  const lines = [
    '## ' + sectionName,
    headers.join(','),
  ];
  for (const row of rows) {
    const values = headers.map(h => {
      const v = row[h];
      if (v === null || v === undefined) return '';
      const s = String(v);
      // Quote if contains comma, newline, or double-quote
      if (s.includes(',') || s.includes('\n') || s.includes('"')) {
        return '"' + s.replace(/"/g, '""') + '"';
      }
      return s;
    });
    lines.push(values.join(','));
  }
  return lines.join('\n');
}

// Rate limiter for bulk export — heavy DB query, large response payload
const isTest = process.env.NODE_ENV === 'test';
const exportLimiter = isTest
  ? (req, res, next) => next()
  : rateLimit({
      windowMs: 5 * 60 * 1000,   // 5 minutes
      max: 3,                     // 3 exports per window
      standardHeaders: true,
      legacyHeaders: false,
      message: { error: 'Export rate limit reached. Please wait a few minutes.' },
    });

router.get('/export', exportLimiter, (req, res) => {
  try {
    const format = (req.query.format || 'json').toLowerCase();
    const data = buildFullExport();

    if (format === 'csv') {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="admin-export-' + timestamp + '.csv"');

      const sections = [
        arrayToCsv(data.users, 'USERS'),
        arrayToCsv(data.settings, 'USER_SETTINGS'),
        arrayToCsv(data.pageViews, 'PAGE_VIEWS'),
        arrayToCsv(data.analyticsEvents, 'ANALYTICS_EVENTS'),
        arrayToCsv(data.sessions, 'SESSIONS'),
        arrayToCsv(data.notifications, 'NOTIFICATIONS'),
        arrayToCsv(data.priceAlertRules, 'PRICE_ALERT_RULES'),
      ].filter(Boolean);

      res.send(sections.join('\n\n'));
    } else {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="admin-export-' + timestamp + '.json"');
      res.json(data);
    }

    log.warn({ audit: true, action: 'bulk-export', adminId: req.session.userId, format, users: data.users.length, pageViews: data.pageViews.length, events: data.analyticsEvents.length },
      'ADMIN AUDIT: bulk data export completed');
  } catch (err) {
    log.error({ err }, 'Admin bulk export failed');
    res.status(500).json({ error: 'Export failed: ' + err.message });
  }
});

// ─── Database health / connection pool monitoring ─────────────
// Exposes pool stats for PostgreSQL and write-queue stats for SQLite.
// GET /api/admin/db-health
router.get('/db-health', (req, res) => {
  try {
    const stats = typeof db.poolStats === 'function'
      ? db.poolStats()
      : { engine: db._engine || 'unknown', error: 'poolStats not available' };

    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      ...stats,
      utilizationPct: stats.maxConnections
        ? Math.round((stats.activeCount / stats.maxConnections) * 100)
        : null,
    });
  } catch (err) {
    log.error({ err }, 'db-health check failed');
    res.status(500).json({ status: 'error', error: err.message });
  }
});

module.exports = router;
module.exports.getSummaryStats = getSummaryStats;
module.exports.getUserChartData = getUserChartData;
module.exports.getSiteAnalytics = getSiteAnalytics;
module.exports.getUsersTable = getUsersTable;
module.exports.getSettingsTable = getSettingsTable;
module.exports.getSessionsTable = getSessionsTable;
