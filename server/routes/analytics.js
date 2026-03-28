const express = require('express');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const db = require('../db');
const log = require('../utils/logger').child({ module: 'analytics' });

const router = express.Router();
const isTest = process.env.NODE_ENV === 'test';

// ── Client-side bot score threshold ─────────────────────────────
// Requests with a client-reported botScore >= this value are silently
// discarded. The client-side fingerprinter scores 0 for normal browsers
// and assigns points for each headless/automation signal detected.
// Score 5+ is a strong indicator of automation (e.g., webdriver + headlessUA).
const BOT_SCORE_THRESHOLD = parseInt(process.env.BOT_SCORE_THRESHOLD, 10) || 5;

// ── Bot / crawler detection ─────────────────────────────────────
// Comprehensive pattern matching known bots, crawlers, headless browsers,
// SEO tools, monitoring agents, and feed fetchers.
const BOT_UA_PATTERN = /bot|crawl|spider|slurp|baiduspider|yandex|duckduckgo|semrush|ahrefs|mj12bot|dotbot|rogerbot|screaming\s?frog|archive\.org|wayback|facebookexternalhit|twitterbot|linkedinbot|whatsapp|telegrambot|discordbot|slackbot|pinterestbot|applebot|googlebot|bingbot|ia_archiver|wget|curl|httpie|python-requests|python-urllib|java\/|libwww|lwp-|go-http-client|axios|node-fetch|undici|scrapy|phantomjs|headlesschrome|puppeteer|playwright|selenium|httrack|nikto|sqlmap|nmap|zgrab|masscan|censys|shodan|netcraft|pingdom|uptimerobot|statuscake|newrelic|datadog|site24x7|gtmetrix|pagespeed|lighthouse|feedfetcher|feedly|newsblur|tiny\s?rss|superfeedr|monitor|checker|scan|probe|test/i;

// Additional suspicious signals: missing or extremely short UAs
function isBot(ua) {
  if (!ua || ua.length < 15) return true;
  return BOT_UA_PATTERN.test(ua);
}

// ── Rate limiters for write endpoints ───────────────────────────
// Generous enough for legitimate SPA navigation, tight enough to stop floods.
const noopLimiter = (req, res, next) => next();

// Pageview: 60 per minute per IP (1 per second average, allows burst)
const pageviewLimiter = isTest ? noopLimiter : rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: '', // silent — analytics should not leak rate limit info
  keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown',
  handler: (_req, res) => res.status(204).end() // fail silently like the endpoint itself
});

// Events: 120 per minute per IP (button clicks can be bursty)
const eventLimiter = isTest ? noopLimiter : rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: '',
  keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown',
  handler: (_req, res) => res.status(204).end()
});

// ── Duplicate suppression ───────────────────────────────────────
// Skip recording the same (session_hash + page) more than once within
// a short window. Prevents double-fires from SPA re-renders / retries.
// Uses an in-memory LRU-style Map with TTL-based eviction.
const DEDUP_TTL_MS = 5 * 1000; // 5 seconds
const DEDUP_MAX_SIZE = 10000;   // cap memory usage
const recentPageviews = new Map();

function isDuplicatePageview(hash, page) {
  const key = hash + ':' + (page || '/');
  const now = Date.now();
  const prev = recentPageviews.get(key);
  if (prev && (now - prev) < DEDUP_TTL_MS) return true;
  // Evict oldest entries if map grows too large
  if (recentPageviews.size >= DEDUP_MAX_SIZE) {
    const cutoff = now - DEDUP_TTL_MS;
    for (const [k, ts] of recentPageviews) {
      if (ts < cutoff) recentPageviews.delete(k);
    }
    // If still over limit after eviction, drop the oldest quarter
    if (recentPageviews.size >= DEDUP_MAX_SIZE) {
      let toDelete = Math.floor(DEDUP_MAX_SIZE / 4);
      for (const k of recentPageviews.keys()) {
        if (toDelete-- <= 0) break;
        recentPageviews.delete(k);
      }
    }
  }
  recentPageviews.set(key, now);
  return false;
}

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
router.post('/pageview', pageviewLimiter, (req, res) => {
  try {
    const ua = req.headers['user-agent'] || '';

    // ── Bot filter: silently discard bot/crawler traffic ──────
    if (isBot(ua)) return res.status(204).end();

    const { page, referrer, screenW, screenH, lang, botScore, botSignals } = req.body;

    // ── Client-side bot fingerprint filter ────────────────────
    const score = typeof botScore === 'number' ? Math.min(Math.max(Math.round(botScore), 0), 99) : 0;
    if (score >= BOT_SCORE_THRESHOLD) {
      log.debug({ score, ip: req.ip }, 'Headless browser detected — discarding pageview');
      return res.status(204).end();
    }

    // Serialize bot signals for forensic analysis (admin dashboard)
    let safeSignals = null;
    if (botSignals && typeof botSignals === 'object' && !Array.isArray(botSignals)) {
      const s = JSON.stringify(botSignals);
      if (s.length <= 500) safeSignals = s;
    }

    const ip = req.ip || req.connection.remoteAddress || '';
    const parsed = parseUA(ua);
    const hash = sessionHash(ip, ua);

    const safePage = sanitizeStr(page, 500) || '/';

    // ── Duplicate suppression ────────────────────────────────
    if (isDuplicatePageview(hash, safePage)) return res.status(204).end();

    const safeReferrer = sanitizeStr(referrer, 1000);
    const safeLang = sanitizeStr(lang, 20);

    db.prepare(`
      INSERT INTO page_views (page, referrer, screen_w, screen_h, lang, ua_browser, ua_os, ua_device, session_hash, bot_score, bot_signals)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      safePage,
      safeReferrer,
      typeof screenW === 'number' ? Math.min(Math.abs(Math.round(screenW)), 99999) : null,
      typeof screenH === 'number' ? Math.min(Math.abs(Math.round(screenH)), 99999) : null,
      safeLang,
      parsed.browser,
      parsed.os,
      parsed.device,
      hash,
      score,
      safeSignals
    );

    res.status(204).end();
  } catch (err) {
    log.error({ err }, 'Analytics pageview failed');
    res.status(204).end(); // fail silently
  }
});

// POST /api/analytics/event — record a custom event
router.post('/event', eventLimiter, (req, res) => {
  try {
    const ua = req.headers['user-agent'] || '';

    // ── Bot filter: silently discard bot/crawler traffic ──────
    if (isBot(ua)) return res.status(204).end();

    const { event, meta, botScore } = req.body;

    // ── Client-side bot fingerprint filter ────────────────────
    const score = typeof botScore === 'number' ? Math.min(Math.max(Math.round(botScore), 0), 99) : 0;
    if (score >= BOT_SCORE_THRESHOLD) return res.status(204).end();

    const safeEvent = sanitizeStr(event, 200);
    if (!safeEvent) return res.status(204).end();

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
    // Common filter: only human traffic (bot_score below threshold)
    const humanFilter = 'AND bot_score < ' + BOT_SCORE_THRESHOLD;

    // Page views per day (last 30 days)
    const viewsPerDay = db.prepare(`
      SELECT date(created_at) as day, COUNT(*) as views, COUNT(DISTINCT session_hash) as visitors
      FROM page_views
      WHERE created_at >= datetime('now', '-30 days') ${humanFilter}
      GROUP BY date(created_at)
      ORDER BY day ASC
    `).all();

    // Top pages
    const topPages = db.prepare(`
      SELECT page, COUNT(*) as views
      FROM page_views
      WHERE created_at >= datetime('now', '-30 days') ${humanFilter}
      GROUP BY page
      ORDER BY views DESC
      LIMIT 10
    `).all();

    // Browser breakdown
    const browsers = db.prepare(`
      SELECT ua_browser as name, COUNT(*) as count
      FROM page_views
      WHERE created_at >= datetime('now', '-30 days') ${humanFilter}
      GROUP BY ua_browser
      ORDER BY count DESC
    `).all();

    // OS breakdown
    const systems = db.prepare(`
      SELECT ua_os as name, COUNT(*) as count
      FROM page_views
      WHERE created_at >= datetime('now', '-30 days') ${humanFilter}
      GROUP BY ua_os
      ORDER BY count DESC
    `).all();

    // Device breakdown
    const devices = db.prepare(`
      SELECT ua_device as name, COUNT(*) as count
      FROM page_views
      WHERE created_at >= datetime('now', '-30 days') ${humanFilter}
      GROUP BY ua_device
      ORDER BY count DESC
    `).all();

    // Top referrers
    const referrers = db.prepare(`
      SELECT referrer, COUNT(*) as count
      FROM page_views
      WHERE referrer IS NOT NULL AND referrer != '' AND created_at >= datetime('now', '-30 days') ${humanFilter}
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

    // Totals (human only)
    const totals = db.prepare(`
      SELECT
        COUNT(*) as total_views,
        COUNT(DISTINCT session_hash) as unique_visitors
      FROM page_views
      WHERE created_at >= datetime('now', '-30 days') ${humanFilter}
    `).get();

    // Bot traffic summary — how much was filtered
    const botStats = db.prepare(`
      SELECT
        COUNT(*) as total_bot_views,
        COUNT(DISTINCT session_hash) as bot_sessions,
        ROUND(AVG(bot_score), 1) as avg_bot_score
      FROM page_views
      WHERE created_at >= datetime('now', '-30 days') AND bot_score >= ${BOT_SCORE_THRESHOLD}
    `).get();

    // Top bot signals (which checks are firing most)
    const botSignalRows = db.prepare(`
      SELECT bot_signals FROM page_views
      WHERE created_at >= datetime('now', '-30 days') AND bot_score >= ${BOT_SCORE_THRESHOLD} AND bot_signals IS NOT NULL
      ORDER BY created_at DESC LIMIT 200
    `).all();
    const signalCounts = {};
    for (const row of botSignalRows) {
      try {
        const s = JSON.parse(row.bot_signals);
        for (const key of Object.keys(s)) {
          signalCounts[key] = (signalCounts[key] || 0) + 1;
        }
      } catch (_) {}
    }

    res.json({
      viewsPerDay,
      topPages,
      browsers,
      systems,
      devices,
      referrers,
      events,
      totalViews: totals.total_views,
      uniqueVisitors: totals.unique_visitors,
      botTraffic: {
        totalBotViews: botStats.total_bot_views || 0,
        botSessions: botStats.bot_sessions || 0,
        avgBotScore: botStats.avg_bot_score || 0,
        topSignals: signalCounts
      }
    });
  } catch (err) {
    log.error({ err }, 'Analytics stats query failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

module.exports = router;
