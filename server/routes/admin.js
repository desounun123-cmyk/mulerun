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
const { ok, paginated, fail } = require('../utils/response');

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
  // Read from pre-computed daily_stats / daily_event_stats rollup tables.
  // These are populated by the background rollup job in index.js.
  const viewsPerDay = db.prepare(`
    SELECT day, SUM(views) as views, SUM(visitors) as visitors
    FROM daily_stats WHERE day >= date('now', '-30 days')
    GROUP BY day ORDER BY day ASC
  `).all();

  const browsers = db.prepare(`
    SELECT ua_browser as name, SUM(views) as count FROM daily_stats
    WHERE day >= date('now', '-30 days')
    GROUP BY ua_browser ORDER BY count DESC
  `).all();

  const devices = db.prepare(`
    SELECT ua_device as name, SUM(views) as count FROM daily_stats
    WHERE day >= date('now', '-30 days')
    GROUP BY ua_device ORDER BY count DESC
  `).all();

  const referrers = db.prepare(`
    SELECT referrer, SUM(views) as count FROM daily_stats
    WHERE referrer IS NOT NULL AND day >= date('now', '-30 days')
    GROUP BY referrer ORDER BY count DESC LIMIT 10
  `).all();

  const events = db.prepare(`
    SELECT event, SUM(count) as count FROM daily_event_stats
    WHERE day >= date('now', '-30 days')
    GROUP BY event ORDER BY count DESC LIMIT 15
  `).all();

  const totals = db.prepare(`
    SELECT SUM(views) as total_views, SUM(visitors) as unique_visitors
    FROM daily_stats WHERE day >= date('now', '-30 days')
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
    ok(res, getSummaryStats());
  } catch (err) {
    log.error({ err }, 'Admin summary query failed');
    fail(res, 500, 'Internal server error.');
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
    ok(res, data);
  } catch (err) {
    log.error({ err }, 'Admin user charts query failed');
    fail(res, 500, 'Internal server error.');
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
    ok(res, data);
  } catch (err) {
    log.error({ err }, 'Admin site analytics query failed');
    fail(res, 500, 'Internal server error.');
  }
});

// GET /api/admin/users — users table data (paginated: ?page=1&limit=50)
router.get('/users', (req, res) => {
  try {
    const { page, limit, offset } = parsePagination(req.query, 50, isSaveDataRequest(res));
    const { users, total } = getUsersTable(limit, offset);
    paginated(res, users, { page, limit, total, totalPages: Math.ceil(total / limit) });
  } catch (err) {
    log.error({ err }, 'Admin users query failed');
    fail(res, 500, 'Internal server error.');
  }
});

// GET /api/admin/settings — user settings table data (paginated: ?page=1&limit=50)
router.get('/settings', (req, res) => {
  try {
    const { page, limit, offset } = parsePagination(req.query, 50, isSaveDataRequest(res));
    const { settings, total } = getSettingsTable(limit, offset);
    paginated(res, settings, { page, limit, total, totalPages: Math.ceil(total / limit) });
  } catch (err) {
    log.error({ err }, 'Admin settings query failed');
    fail(res, 500, 'Internal server error.');
  }
});

// GET /api/admin/sessions — sessions table data (paginated: ?page=1&limit=50)
router.get('/sessions', (req, res) => {
  try {
    const { page, limit, offset } = parsePagination(req.query, 50, isSaveDataRequest(res));
    const { sessions, total } = getSessionsTable(limit, offset);
    paginated(res, sessions, { page, limit, total, totalPages: Math.ceil(total / limit) });
  } catch (err) {
    log.error({ err }, 'Admin sessions query failed');
    fail(res, 500, 'Internal server error.');
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
 *
 * Defends against CSV formula injection (CWE-1236): cells whose first
 * character is =, +, -, @, \t, or \r are prefixed with a leading single
 * quote so spreadsheet applications (Excel, Sheets, LibreOffice) treat
 * them as plain text rather than executable formulas.
 */

// Characters that trigger formula evaluation in common spreadsheet apps.
const CSV_FORMULA_PREFIXES = new Set(['=', '+', '-', '@', '\t', '\r']);

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
      let s = String(v);
      // Neutralise formula injection — prefix dangerous first characters
      // with a single quote so spreadsheet apps parse the cell as text.
      if (s.length > 0 && CSV_FORMULA_PREFIXES.has(s[0])) {
        s = "'" + s;
      }
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
    fail(res, 500, 'Export failed: ' + err.message);
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

    const timestamp = new Date().toISOString();
    const utilizationPct = stats.maxConnections
      ? Math.round((stats.activeCount / stats.maxConnections) * 100)
      : null;
    ok(res, { status: 'ok', timestamp, ...stats, utilizationPct });
  } catch (err) {
    log.error({ err }, 'db-health check failed');
    fail(res, 500, err.message);
  }
});

// ─── Server metrics summary for admin dashboard ─────────────
// GET /api/admin/metrics-summary
// Returns a lightweight snapshot of Prometheus metrics formatted for the
// admin panel UI. Does NOT require prom-client — falls back gracefully.
router.get('/metrics-summary', (req, res) => {
  try {
    const mem = process.memoryUsage();
    const cpu = process.cpuUsage();
    const uptime = process.uptime();

    const payload = {
      timestamp: new Date().toISOString(),
      uptime: Math.floor(uptime),
      uptimeFormatted: formatUptime(uptime),
      node: {
        version: process.version,
        pid: process.pid,
        platform: process.platform,
        arch: process.arch,
      },
      memory: {
        rssBytes: mem.rss,
        rssMB: +(mem.rss / 1048576).toFixed(1),
        heapUsedBytes: mem.heapUsed,
        heapUsedMB: +(mem.heapUsed / 1048576).toFixed(1),
        heapTotalBytes: mem.heapTotal,
        heapTotalMB: +(mem.heapTotal / 1048576).toFixed(1),
        externalBytes: mem.external,
        externalMB: +(mem.external / 1048576).toFixed(1),
        heapUsedPct: +(mem.heapUsed / mem.heapTotal * 100).toFixed(1),
      },
      cpu: {
        userMicros: cpu.user,
        systemMicros: cpu.system,
      },
      eventLoop: {
        // High-res event loop lag — only available on Node 16+
        lagMs: typeof performance !== 'undefined' && performance.eventLoopUtilization
          ? null  // placeholder — ELU is more useful than lag
          : null,
      },
      db: getDbMetrics(),
      prometheus: getPrometheusSnapshot(),
    };

    ok(res, payload);
  } catch (err) {
    log.error({ err }, 'Admin metrics-summary failed');
    fail(res, 500, 'Internal server error.');
  }
});

function formatUptime(seconds) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  const parts = [];
  if (d > 0) parts.push(d + 'd');
  if (h > 0) parts.push(h + 'h');
  if (m > 0) parts.push(m + 'm');
  parts.push(s + 's');
  return parts.join(' ');
}

function getDbMetrics() {
  try {
    const userCount = db.prepare('SELECT COUNT(*) AS cnt FROM users').get().cnt;
    const sessionCount = db.prepare('SELECT COUNT(*) AS cnt FROM sessions').get().cnt;

    let pageViews30d = 0;
    try {
      pageViews30d = db.prepare(
        "SELECT COALESCE(SUM(views), 0) AS v FROM daily_stats WHERE day >= date('now', '-30 days')"
      ).get().v;
    } catch (_) { /* table may not exist */ }

    let notifCount = 0;
    try {
      notifCount = db.prepare('SELECT COUNT(*) AS cnt FROM notifications').get().cnt;
    } catch (_) { /* table may not exist */ }

    let alertRuleCount = 0;
    try {
      alertRuleCount = db.prepare('SELECT COUNT(*) AS cnt FROM price_alert_rules WHERE active = 1').get().cnt;
    } catch (_) { /* table may not exist */ }

    return {
      users: userCount,
      sessions: sessionCount,
      pageViews30d,
      notifications: notifCount,
      activeAlertRules: alertRuleCount,
      sizeKB: +(getDbSize() / 1024).toFixed(1),
    };
  } catch (err) {
    return { error: err.message };
  }
}

function getPrometheusSnapshot() {
  // Try to read counters/histograms from the prometheus module if loaded
  try {
    const metrics = require('../utils/prometheus');
    if (!metrics.enabled) return { enabled: false };

    // prom-client exposes .get() on each metric which returns a promise,
    // but for the admin summary we just report whether it's active.
    return { enabled: true, endpoint: process.env.METRICS_PATH || '/metrics' };
  } catch (_) {
    return { enabled: false };
  }
}

module.exports = router;
module.exports.getSummaryStats = getSummaryStats;
module.exports.getUserChartData = getUserChartData;
module.exports.getSiteAnalytics = getSiteAnalytics;
module.exports.getUsersTable = getUsersTable;
module.exports.getSettingsTable = getSettingsTable;
module.exports.getSessionsTable = getSessionsTable;
