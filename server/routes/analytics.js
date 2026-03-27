const express = require('express');
const crypto = require('crypto');
const db = require('../db');
const log = require('../logger').child({ module: 'analytics' });

const router = express.Router();

// Simple user-agent parser (no dependency needed)
function parseUA(ua) {
  if (!ua) return { browser: 'Unknown', os: 'Unknown', device: 'desktop' };
  let browser = 'Other';
  let os = 'Other';
  let device = 'desktop';

  // Browser
  if (/Edg\//i.test(ua)) browser = 'Edge';
  else if (/Chrome/i.test(ua) && !/Chromium/i.test(ua)) browser = 'Chrome';
  else if (/Firefox/i.test(ua)) browser = 'Firefox';
  else if (/Safari/i.test(ua) && !/Chrome/i.test(ua)) browser = 'Safari';
  else if (/MSIE|Trident/i.test(ua)) browser = 'IE';

  // OS
  if (/Windows/i.test(ua)) os = 'Windows';
  else if (/Macintosh|Mac OS/i.test(ua)) os = 'macOS';
  else if (/Linux/i.test(ua) && !/Android/i.test(ua)) os = 'Linux';
  else if (/Android/i.test(ua)) os = 'Android';
  else if (/iPhone|iPad|iPod/i.test(ua)) os = 'iOS';

  // Device
  if (/Mobile|Android.*Mobile|iPhone/i.test(ua)) device = 'mobile';
  else if (/iPad|Tablet|Android(?!.*Mobile)/i.test(ua)) device = 'tablet';

  return { browser, os, device };
}

// Generate a daily session hash from IP + UA + date (no cookies, rotates daily)
function sessionHash(ip, ua) {
  const day = new Date().toISOString().slice(0, 10);
  return crypto.createHash('sha256').update(`${ip}|${ua}|${day}`).digest('hex').slice(0, 16);
}

// ── Input sanitization helpers ────────────────────────────────
function sanitizeStr(val, maxLen) {
  if (!val || typeof val !== 'string') return null;
  // Strip HTML tags and null bytes
  return val.replace(/<[^>]*>/g, '').replace(/\0/g, '').slice(0, maxLen).trim() || null;
}

// POST /api/analytics/pageview — record a page view
router.post('/pageview', (req, res) => {
  try {
    const { page, referrer, screenW, screenH, lang } = req.body;
    const ua = req.headers['user-agent'] || '';
    const ip = req.ip || req.connection.remoteAddress || '';
    const parsed = parseUA(ua);
    const hash = sessionHash(ip, ua);

    const safePage = sanitizeStr(page, 500) || '/';
    const safeReferrer = sanitizeStr(referrer, 1000);
    const safeLang = sanitizeStr(lang, 20);

    db.prepare(`
      INSERT INTO page_views (page, referrer, screen_w, screen_h, lang, ua_browser, ua_os, ua_device, session_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      safePage,
      safeReferrer,
      typeof screenW === 'number' ? Math.min(Math.abs(Math.round(screenW)), 99999) : null,
      typeof screenH === 'number' ? Math.min(Math.abs(Math.round(screenH)), 99999) : null,
      safeLang,
      parsed.browser,
      parsed.os,
      parsed.device,
      hash
    );

    res.status(204).end();
  } catch (err) {
    log.error({ err }, 'Analytics pageview failed');
    res.status(204).end(); // fail silently
  }
});

// POST /api/analytics/event — record a custom event
router.post('/event', (req, res) => {
  try {
    const { event, meta } = req.body;
    const safeEvent = sanitizeStr(event, 200);
    if (!safeEvent) return res.status(204).end();

    const ua = req.headers['user-agent'] || '';
    const ip = req.ip || req.connection.remoteAddress || '';
    const hash = sessionHash(ip, ua);

    // Sanitize meta: must be a plain object, stringify with size limit
    let safeMeta = null;
    if (meta && typeof meta === 'object' && !Array.isArray(meta)) {
      const s = JSON.stringify(meta);
      if (s.length <= 2000) safeMeta = s;
    }

    db.prepare(
      'INSERT INTO analytics_events (event, meta, session_hash) VALUES (?, ?, ?)'
    ).run(safeEvent, safeMeta, hash);

    res.status(204).end();
  } catch (err) {
    log.error({ err }, 'Analytics event failed');
    res.status(204).end();
  }
});

// GET /api/analytics/stats — admin-only stats summary
router.get('/stats', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }
  // Check if admin
  const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.plan !== 'Admin') {
    return res.status(403).json({ error: 'Admin access required.' });
  }

  try {
    // Page views per day (last 30 days)
    const viewsPerDay = db.prepare(`
      SELECT date(created_at) as day, COUNT(*) as views, COUNT(DISTINCT session_hash) as visitors
      FROM page_views
      WHERE created_at >= datetime('now', '-30 days')
      GROUP BY date(created_at)
      ORDER BY day ASC
    `).all();

    // Top pages
    const topPages = db.prepare(`
      SELECT page, COUNT(*) as views
      FROM page_views
      WHERE created_at >= datetime('now', '-30 days')
      GROUP BY page
      ORDER BY views DESC
      LIMIT 10
    `).all();

    // Browser breakdown
    const browsers = db.prepare(`
      SELECT ua_browser as name, COUNT(*) as count
      FROM page_views
      WHERE created_at >= datetime('now', '-30 days')
      GROUP BY ua_browser
      ORDER BY count DESC
    `).all();

    // OS breakdown
    const systems = db.prepare(`
      SELECT ua_os as name, COUNT(*) as count
      FROM page_views
      WHERE created_at >= datetime('now', '-30 days')
      GROUP BY ua_os
      ORDER BY count DESC
    `).all();

    // Device breakdown
    const devices = db.prepare(`
      SELECT ua_device as name, COUNT(*) as count
      FROM page_views
      WHERE created_at >= datetime('now', '-30 days')
      GROUP BY ua_device
      ORDER BY count DESC
    `).all();

    // Top referrers
    const referrers = db.prepare(`
      SELECT referrer, COUNT(*) as count
      FROM page_views
      WHERE referrer IS NOT NULL AND referrer != '' AND created_at >= datetime('now', '-30 days')
      GROUP BY referrer
      ORDER BY count DESC
      LIMIT 10
    `).all();

    // Custom events
    const events = db.prepare(`
      SELECT event, COUNT(*) as count
      FROM analytics_events
      WHERE created_at >= datetime('now', '-30 days')
      GROUP BY event
      ORDER BY count DESC
      LIMIT 20
    `).all();

    // Totals
    const totals = db.prepare(`
      SELECT
        COUNT(*) as total_views,
        COUNT(DISTINCT session_hash) as unique_visitors
      FROM page_views
      WHERE created_at >= datetime('now', '-30 days')
    `).get();

    res.json({
      viewsPerDay,
      topPages,
      browsers,
      systems,
      devices,
      referrers,
      events,
      totalViews: totals.total_views,
      uniqueVisitors: totals.unique_visitors
    });
  } catch (err) {
    log.error({ err }, 'Analytics stats query failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

module.exports = router;
