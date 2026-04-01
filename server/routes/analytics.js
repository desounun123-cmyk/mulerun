const express = require('express');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const db = require('../db/db');
const log = require('../utils/logger').child({ module: 'analytics' });
const { ok, fail, noContent } = require('../utils/response');

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

// ══════════════════════════════════════════════════════════════════
// ── Server-side behavioral bot detection ─────────────────────────
// ══════════════════════════════════════════════════════════════════
//
// Supplements UA regex and client-side fingerprinting with heuristics
// that sophisticated bots (spoofed UA, JS execution) cannot easily evade:
//
//   1. Request timing: impossibly fast page transitions (< 800ms)
//   2. Timing regularity: near-identical intervals between hits (low σ)
//   3. Missing browser headers: real browsers send Accept-Language,
//      Accept-Encoding, Sec-Fetch-Dest, etc.
//   4. No interaction events: many pageviews, zero events (clicks, mouse)
//   5. Endpoint sequence: hitting non-page endpoints before loading a page
//
// Each signal adds to a server_bot_score. If the combined score crosses
// SERVER_BOT_THRESHOLD the pageview is silently discarded.

const SERVER_BOT_THRESHOLD = parseInt(process.env.SERVER_BOT_THRESHOLD, 10) || 6;

// ── In-memory session behavior tracker ─────────────────────────
// Keyed by session_hash. Entries auto-expire after SESSION_TTL_MS.
const SESSION_TTL_MS = 30 * 60 * 1000;   // 30 minutes
const SESSION_MAX_SIZE = 20000;           // cap memory
const sessionBehavior = new Map();

// Periodic eviction of stale sessions (every 5 minutes)
const _evictionTimer = setInterval(() => {
  const cutoff = Date.now() - SESSION_TTL_MS;
  for (const [key, s] of sessionBehavior) {
    if (s.lastSeen < cutoff) sessionBehavior.delete(key);
  }
}, 5 * 60 * 1000);
_evictionTimer.unref();

function getSession(hash) {
  let s = sessionBehavior.get(hash);
  if (!s) {
    // Evict oldest quarter if over capacity
    if (sessionBehavior.size >= SESSION_MAX_SIZE) {
      let toDelete = Math.floor(SESSION_MAX_SIZE / 4);
      for (const k of sessionBehavior.keys()) {
        if (toDelete-- <= 0) break;
        sessionBehavior.delete(k);
      }
    }
    s = {
      pageviews: 0,
      events: 0,
      timestamps: [],     // last N pageview timestamps (ms)
      firstPage: null,    // first page path hit
      hasNavigation: false, // hit "/" or an HTML page first
      lastSeen: Date.now(),
    };
    sessionBehavior.set(hash, s);
  }
  return s;
}

/**
 * Compute a server-side bot score based on behavioral signals.
 * Returns { score: number, signals: string[] }.
 */
function serverBotScore(req, hash, page) {
  const now = Date.now();
  const s = getSession(hash);
  let score = 0;
  const signals = [];

  // ── 1. Missing browser headers ───────────────────────────────
  // Real browsers always send these. Headless tools often omit some.
  const headers = req.headers;
  if (!headers['accept-language']) {
    score += 2;
    signals.push('no-accept-language');
  }
  if (!headers['accept-encoding']) {
    score += 1;
    signals.push('no-accept-encoding');
  }
  // Sec-Fetch-* headers are sent by all modern browsers (Chrome 76+, FF 90+, Safari 16.4+)
  if (!headers['sec-fetch-dest'] && !headers['sec-fetch-mode']) {
    score += 2;
    signals.push('no-sec-fetch');
  }
  // Connection: keep-alive is standard for browsers; missing suggests CLI/script
  if (!headers['accept'] || headers['accept'] === '*/*') {
    score += 1;
    signals.push('generic-accept');
  }

  // ── 2. Request timing analysis ───────────────────────────────
  // Record timestamp and analyze intervals
  s.timestamps.push(now);
  if (s.timestamps.length > 20) s.timestamps.shift(); // keep last 20

  if (s.timestamps.length >= 2) {
    const intervals = [];
    for (let i = 1; i < s.timestamps.length; i++) {
      intervals.push(s.timestamps[i] - s.timestamps[i - 1]);
    }

    // 2a. Impossibly fast navigation (< 800ms between pages)
    const lastInterval = intervals[intervals.length - 1];
    if (lastInterval < 800) {
      score += 3;
      signals.push('fast-nav-' + lastInterval + 'ms');
    }

    // 2b. Metronomic timing: bots often have very regular intervals
    //     (low coefficient of variation). Humans are noisy.
    if (intervals.length >= 5) {
      const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      if (mean > 0) {
        const variance = intervals.reduce((a, b) => a + (b - mean) ** 2, 0) / intervals.length;
        const cv = Math.sqrt(variance) / mean; // coefficient of variation
        if (cv < 0.1) {
          score += 3;
          signals.push('metronomic-cv-' + cv.toFixed(3));
        } else if (cv < 0.2) {
          score += 1;
          signals.push('regular-cv-' + cv.toFixed(3));
        }
      }
    }
  }

  // ── 3. No interaction events ─────────────────────────────────
  // Sessions with many pageviews but zero events are suspicious.
  // Real users click, scroll, or interact within a few page loads.
  if (s.pageviews >= 8 && s.events === 0) {
    score += 2;
    signals.push('no-events-after-' + s.pageviews + '-pv');
  }

  // ── 4. Endpoint sequence anomaly ─────────────────────────────
  // First request should be a page load (/, /index.html, etc.)
  // Bots often hit API endpoints or deep paths directly.
  if (!s.hasNavigation && s.pageviews === 0) {
    const p = (page || '/').toLowerCase();
    if (p === '/' || p === '/index.html' || p === '/market-data.html') {
      s.hasNavigation = true;
    }
    s.firstPage = p;
  }
  if (s.pageviews >= 3 && !s.hasNavigation) {
    score += 2;
    signals.push('no-root-nav');
  }

  // Update session state
  s.pageviews++;
  s.lastSeen = now;

  return { score, signals };
}

/**
 * Record that a session produced an interaction event (click, scroll, etc.).
 * Called from the /event endpoint to update the behavior profile.
 */
function recordSessionEvent(hash) {
  const s = sessionBehavior.get(hash);
  if (s) {
    s.events++;
    s.lastSeen = Date.now();
  }
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
  handler: (_req, res) => noContent(res) // fail silently like the endpoint itself
});

// Events: 120 per minute per IP (button clicks can be bursty)
const eventLimiter = isTest ? noopLimiter : rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: '',
  keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown',
  handler: (_req, res) => noContent(res)
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

// Generate a session hash from IP + UA + time window (no cookies).
// Uses 6-hour buckets (0-5, 6-11, 12-17, 18-23) so that legitimate
// return visits hours apart produce distinct hashes, while repeat
// hits within the same window still deduplicate correctly.
// Previous implementation used day-level precision (.slice(0,10)),
// which collapsed all visits from the same IP within a calendar day
// into a single session — undercounting real traffic.
const SESSION_WINDOW_HOURS = parseInt(process.env.ANALYTICS_SESSION_WINDOW_HOURS, 10) || 6;
const { hashIP } = require('../utils/ip-hash');
function sessionHash(ip, ua) {
  const now = new Date();
  const day = now.toISOString().slice(0, 10);
  const bucket = Math.floor(now.getUTCHours() / SESSION_WINDOW_HOURS);
  return hashIP(`${ip}|${ua}|${day}T${bucket}`, 16);
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
    if (isBot(ua)) return noContent(res);

    const { page, referrer, screenW, screenH, lang, botScore, botSignals } = req.body;

    // ── Client-side bot fingerprint filter ────────────────────
    const score = typeof botScore === 'number' ? Math.min(Math.max(Math.round(botScore), 0), 99) : 0;
    if (score >= BOT_SCORE_THRESHOLD) {
      log.debug({ score, ip: req.ip }, 'Headless browser detected — discarding pageview');
      return noContent(res);
    }

    // Serialize bot signals for forensic analysis (admin dashboard).
    // If the full JSON exceeds 500 chars, progressively drop keys until
    // it fits, keeping as many signals as possible. A _truncated flag is
    // added so the admin panel can indicate partial data.
    let safeSignals = null;
    if (botSignals && typeof botSignals === 'object' && !Array.isArray(botSignals)) {
      const MAX_LEN = 500;
      const s = JSON.stringify(botSignals);
      if (s.length <= MAX_LEN) {
        safeSignals = s;
      } else {
        // Keep only keys whose values are truthy (the actual signals that
        // fired) and drop the rest to shed size.  Then trim keys one-by-one
        // from the end until the result fits.
        const keys = Object.keys(botSignals).filter(k => botSignals[k]);
        const trimmed = {};
        for (const k of keys) trimmed[k] = botSignals[k];
        trimmed._truncated = true;
        while (Object.keys(trimmed).length > 1) {
          const json = JSON.stringify(trimmed);
          if (json.length <= MAX_LEN) { safeSignals = json; break; }
          // Remove the last real key (keep _truncated)
          const realKeys = Object.keys(trimmed).filter(k => k !== '_truncated');
          if (realKeys.length === 0) break;
          delete trimmed[realKeys[realKeys.length - 1]];
        }
        if (!safeSignals && Object.keys(trimmed).length) {
          safeSignals = JSON.stringify(trimmed).slice(0, MAX_LEN);
        }
        log.warn({ originalLength: s.length, keyCount: keys.length },
          'Bot signals truncated — exceeded 500 char limit');
      }
    }

    const ip = req.ip || req.connection.remoteAddress || '';
    const parsed = parseUA(ua);
    const hash = sessionHash(ip, ua);

    const safePage = sanitizeStr(page, 500) || '/';

    // ── Server-side behavioral bot detection ─────────────────
    const serverResult = serverBotScore(req, hash, safePage);
    if (serverResult.score >= SERVER_BOT_THRESHOLD) {
      log.debug({
        serverScore: serverResult.score,
        signals: serverResult.signals,
        sessionHash: hash,
      }, 'Server-side bot heuristic triggered — discarding pageview');
      return noContent(res);
    }

    // ── Duplicate suppression ────────────────────────────────
    if (isDuplicatePageview(hash, safePage)) return noContent(res);

    const safeReferrer = sanitizeStr(referrer, 1000);
    const safeLang = sanitizeStr(lang, 20);

    // Combine client + server bot scores for storage (capped at 99)
    const combinedScore = Math.min(score + serverResult.score, 99);

    // Merge server signals into bot_signals for forensic analysis
    if (serverResult.signals.length > 0 && !safeSignals) {
      safeSignals = JSON.stringify({ _server: serverResult.signals });
    } else if (serverResult.signals.length > 0 && safeSignals) {
      try {
        const existing = JSON.parse(safeSignals);
        existing._server = serverResult.signals;
        const merged = JSON.stringify(existing);
        if (merged.length <= 500) safeSignals = merged;
      } catch (_) { /* keep original */ }
    }

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
      combinedScore,
      safeSignals
    );

    noContent(res);
  } catch (err) {
    log.error({ err }, 'Analytics pageview failed');
    noContent(res); // fail silently
  }
});

// POST /api/analytics/event — record a custom event
router.post('/event', eventLimiter, (req, res) => {
  try {
    const ua = req.headers['user-agent'] || '';

    // ── Bot filter: silently discard bot/crawler traffic ──────
    if (isBot(ua)) return noContent(res);

    const { event, meta, botScore } = req.body;

    // ── Client-side bot fingerprint filter ────────────────────
    const score = typeof botScore === 'number' ? Math.min(Math.max(Math.round(botScore), 0), 99) : 0;
    if (score >= BOT_SCORE_THRESHOLD) return noContent(res);

    const safeEvent = sanitizeStr(event, 200);
    if (!safeEvent) return noContent(res);

    const ip = req.ip || req.connection.remoteAddress || '';
    const hash = sessionHash(ip, ua);

    // Update session behavior profile with this interaction event
    recordSessionEvent(hash);

    // Sanitize meta: must be a plain object, stringify with size limit
    let safeMeta = null;
    if (meta && typeof meta === 'object' && !Array.isArray(meta)) {
      const s = JSON.stringify(meta);
      if (s.length <= 2000) safeMeta = s;
    }

    db.prepare(
      'INSERT INTO analytics_events (event, meta, session_hash) VALUES (?, ?, ?)'
    ).run(safeEvent, safeMeta, hash);

    noContent(res);
  } catch (err) {
    log.error({ err }, 'Analytics event failed');
    noContent(res);
  }
});

// GET /api/analytics/stats — admin-only stats summary
router.get('/stats', (req, res) => {
  if (!req.session.userId) {
    return fail(res, 401, 'Not authenticated.');
  }
  // Check if admin
  const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.plan !== 'Admin') {
    return fail(res, 403, 'Admin access required.');
  }

  try {
    // All dashboard queries now read from pre-computed daily_stats and
    // daily_event_stats rollup tables, making them O(days) not O(raw-rows).
    // Bot-signal detail queries still hit raw page_views (bounded to 200 rows).

    // Page views per day (last 30 days) — human traffic only
    const viewsPerDay = db.prepare(`
      SELECT day, SUM(views) as views, SUM(visitors) as visitors
      FROM daily_stats
      WHERE day >= date('now', '-30 days')
      GROUP BY day ORDER BY day ASC
    `).all();

    // Top pages
    const topPages = db.prepare(`
      SELECT page, SUM(views) as views
      FROM daily_stats
      WHERE day >= date('now', '-30 days')
      GROUP BY page ORDER BY views DESC LIMIT 10
    `).all();

    // Browser breakdown
    const browsers = db.prepare(`
      SELECT ua_browser as name, SUM(views) as count
      FROM daily_stats
      WHERE day >= date('now', '-30 days')
      GROUP BY ua_browser ORDER BY count DESC
    `).all();

    // OS breakdown
    const systems = db.prepare(`
      SELECT ua_os as name, SUM(views) as count
      FROM daily_stats
      WHERE day >= date('now', '-30 days')
      GROUP BY ua_os ORDER BY count DESC
    `).all();

    // Device breakdown
    const devices = db.prepare(`
      SELECT ua_device as name, SUM(views) as count
      FROM daily_stats
      WHERE day >= date('now', '-30 days')
      GROUP BY ua_device ORDER BY count DESC
    `).all();

    // Top referrers
    const referrers = db.prepare(`
      SELECT referrer, SUM(views) as count
      FROM daily_stats
      WHERE referrer IS NOT NULL AND day >= date('now', '-30 days')
      GROUP BY referrer ORDER BY count DESC LIMIT 10
    `).all();

    // Custom events
    const events = db.prepare(`
      SELECT event, SUM(count) as count
      FROM daily_event_stats
      WHERE day >= date('now', '-30 days')
      GROUP BY event ORDER BY count DESC LIMIT 20
    `).all();

    // Totals (human only)
    const totals = db.prepare(`
      SELECT SUM(views) as total_views, SUM(visitors) as unique_visitors
      FROM daily_stats
      WHERE day >= date('now', '-30 days')
    `).get();

    // Bot traffic summary from rollup
    const botStats = db.prepare(`
      SELECT
        SUM(bot_views) as total_bot_views,
        SUM(bot_sessions) as bot_sessions
      FROM daily_stats
      WHERE day >= date('now', '-30 days')
    `).get();

    // Top bot signals — still queries raw table but bounded to 200 rows
    const threshold = BOT_SCORE_THRESHOLD;
    const botSignalRows = db.prepare(`
      SELECT bot_signals FROM page_views
      WHERE created_at >= datetime('now', '-30 days') AND bot_score >= ? AND bot_signals IS NOT NULL
      ORDER BY created_at DESC LIMIT 200
    `).all(threshold);
    const signalCounts = {};
    for (const row of botSignalRows) {
      try {
        const s = JSON.parse(row.bot_signals);
        for (const key of Object.keys(s)) {
          signalCounts[key] = (signalCounts[key] || 0) + 1;
        }
      } catch (_) {}
    }

    ok(res, {
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
        topSignals: signalCounts
      }
    });
  } catch (err) {
    log.error({ err }, 'Analytics stats query failed');
    fail(res, 500, 'Internal server error.');
  }
});

module.exports = router;

// Expose shutdown hook so the graceful shutdown handler in index.js can
// cancel the eviction timer and free the session map.
module.exports.shutdown = function () {
  clearInterval(_evictionTimer);
  sessionBehavior.clear();
};
