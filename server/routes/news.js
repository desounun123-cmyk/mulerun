const express = require('express');
const https = require('https');
const http = require('http');
const db = require('../db/db');
const log = require('../utils/logger').child({ module: 'news' });
const { ok, fail, conditionalOk } = require('../utils/response');

const router = express.Router();

// ── News Headlines Proxy ─────────────────────────────────────────────
// Fetches oil & energy headlines from external news APIs and returns a
// normalized array for the frontend ticker. Runs server-side so API keys
// stay secret and CORS is not an issue.
//
// Supported providers (configure via environment variables):
//   1. NewsAPI.org      — NEWS_API_KEY     (free tier: 100 req/day)
//   2. Mediastack       — MEDIASTACK_KEY   (free tier: 500 req/month)
//   3. Reuters/Bloomberg — via NewsAPI sources filter
//
// The endpoint merges results from all configured providers, dedupes by
// title similarity, and caches for CACHE_TTL_MS to stay within rate limits.

const NEWS_API_KEY    = process.env.NEWS_API_KEY || '';
const MEDIASTACK_KEY  = process.env.MEDIASTACK_KEY || '';
const CACHE_TTL_MS    = parseInt(process.env.NEWS_CACHE_TTL_MS, 10) || 5 * 60 * 1000; // 5 min
const MAX_HEADLINES   = 20;

// Maximum age before stale cache is considered expired and discarded.
// After this threshold, clients receive an empty result instead of ancient data.
const STALE_MAX_MS    = parseInt(process.env.NEWS_STALE_MAX_MS, 10) || 60 * 60 * 1000; // 1 hour

// In-memory cache (warm layer — backed by the `config` table for cold starts)
let headlineCache = null;
let cacheTimestamp = 0;
let consecutiveFailures = 0;       // tracks how many refreshes returned 0 results in a row
let lastFailureTimestamp = 0;       // when the last failure occurred

// ── DB-backed cache helpers ───────────────────────────────────────
// On cold start, load the last cached headlines from the `config` table
// so the first request doesn't have to hit external APIs immediately.

const NEWS_CACHE_DB_KEY = 'news_headlines_cache';

function loadCacheFromDB() {
  try {
    const row = db.prepare("SELECT value FROM config WHERE key = ?").get(NEWS_CACHE_DB_KEY);
    if (!row) return;
    const parsed = JSON.parse(row.value);
    if (parsed && Array.isArray(parsed.headlines) && parsed.headlines.length > 0 && parsed.cachedAt) {
      headlineCache = parsed.headlines;
      cacheTimestamp = new Date(parsed.cachedAt).getTime() || 0;
      log.info({ count: headlineCache.length, age: Date.now() - cacheTimestamp }, 'Loaded news cache from DB');
    }
  } catch (err) {
    log.warn({ err }, 'Failed to load news cache from DB — starting cold');
  }
}

function saveCacheToDB(headlines, timestamp) {
  try {
    const payload = JSON.stringify({
      headlines,
      cachedAt: new Date(timestamp).toISOString(),
    });
    db.prepare(
      'INSERT OR REPLACE INTO "config" ("key", "value") VALUES (?, ?)'
    ).run(NEWS_CACHE_DB_KEY, payload);
  } catch (err) {
    log.warn({ err }, 'Failed to persist news cache to DB');
  }
}

// Seed in-memory cache from DB on module load
loadCacheFromDB();

// ── Helpers ──────────────────────────────────────────────────────────

/**
 * HTTP GET with optional headers. Returns parsed JSON.
 * Any error message redacts query parameters to prevent key leakage in logs.
 *
 * Hardened against:
 *   - Unbounded response bodies (MAX_RESPONSE_BYTES limit prevents OOM)
 *   - Hanging connections (timeout on both request and response stream)
 *   - Response stream errors (connection reset mid-transfer)
 */
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024; // 2 MB — news payloads are typically < 100 KB

function httpGet(url, headers) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const parsed = new URL(url);
    const safeUrl = parsed.origin + parsed.pathname; // strip querystring for logging
    let settled = false;

    function settle(fn, val) {
      if (settled) return;
      settled = true;
      fn(val);
    }

    const options = {
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      timeout: 10000,
      headers: headers || {},
    };
    const req = mod.get(options, (res) => {
      let body = '';
      let bytes = 0;

      // Guard against non-2xx redirects / errors from the upstream API
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume(); // drain the response to free the socket
        return settle(reject, new Error(safeUrl + ': HTTP ' + res.statusCode));
      }

      // Response-level timeout: if the body takes too long to arrive
      // (e.g., slow-drip attack), abort after the same timeout as the request.
      res.setTimeout(10000, () => {
        req.destroy();
        settle(reject, new Error('Response stream timeout: ' + safeUrl));
      });

      res.on('error', (err) => {
        settle(reject, new Error(safeUrl + ' response error: ' + err.message));
      });

      res.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes > MAX_RESPONSE_BYTES) {
          req.destroy();
          settle(reject, new Error(safeUrl + ': response exceeded ' + MAX_RESPONSE_BYTES + ' bytes'));
          return;
        }
        body += chunk;
      });

      res.on('end', () => {
        try { settle(resolve, JSON.parse(body)); }
        catch (e) { settle(reject, new Error('Invalid JSON from ' + safeUrl)); }
      });
    });
    req.on('error', (err) => settle(reject, new Error(safeUrl + ': ' + err.message)));
    req.on('timeout', () => { req.destroy(); settle(reject, new Error('Timeout: ' + safeUrl)); });
  });
}

// Normalize a headline object to { title, url, source, publishedAt }
function normalize(title, url, source, publishedAt) {
  return {
    title: (title || '').trim().slice(0, 200),
    url: url || '#',
    source: (source || 'NEWS').slice(0, 30),
    publishedAt: publishedAt || new Date().toISOString(),
  };
}

// Simple dedup: normalise whitespace, keep meaningful symbols (%, $, etc.)
function dedupeKey(title) {
  return (title || '').toLowerCase().replace(/\s+/g, ' ').trim().slice(0, 80);
}

// ── Provider: NewsAPI.org ────────────────────────────────────────────
// Searches for oil/energy headlines from Reuters, Bloomberg, AP, etc.
async function fetchNewsAPI() {
  if (!NEWS_API_KEY) return [];
  const q = encodeURIComponent('oil OR crude OR OPEC OR petroleum OR Brent OR WTI');
  const sources = 'reuters,bloomberg,associated-press,the-wall-street-journal,financial-times,bbc-news';
  const url = 'https://newsapi.org/v2/everything'
    + '?q=' + q
    + '&sources=' + sources
    + '&sortBy=publishedAt'
    + '&pageSize=' + MAX_HEADLINES
    + '&language=en';
  try {
    const data = await httpGet(url, { 'X-Api-Key': NEWS_API_KEY });
    if (!data.articles) return [];
    return data.articles.map(a => normalize(
      a.title,
      a.url,
      a.source && a.source.name ? a.source.name : 'NewsAPI',
      a.publishedAt
    ));
  } catch (err) {
    log.warn({ err, provider: 'newsapi' }, 'NewsAPI fetch failed');
    return [];
  }
}

// ── Provider: Mediastack ─────────────────────────────────────────────
async function fetchMediastack() {
  if (!MEDIASTACK_KEY) return [];
  const keywords = 'oil,crude,OPEC,petroleum,brent';
  // Mediastack free tier is HTTP only
  const url = 'http://api.mediastack.com/v1/news'
    + '?access_key=' + MEDIASTACK_KEY
    + '&keywords=' + keywords
    + '&categories=business'
    + '&languages=en'
    + '&sort=published_desc'
    + '&limit=' + MAX_HEADLINES;
  try {
    const data = await httpGet(url);
    if (!data.data) return [];
    return data.data.map(a => normalize(
      a.title,
      a.url,
      a.source || 'Mediastack',
      a.published_at
    ));
  } catch (err) {
    log.warn({ err, provider: 'mediastack' }, 'Mediastack fetch failed');
    return [];
  }
}

// ── Merge & dedupe from all providers ────────────────────────────────
async function fetchAllHeadlines() {
  const [newsapi, mediastack] = await Promise.allSettled([
    fetchNewsAPI(),
    fetchMediastack(),
  ]);

  const all = [];
  if (newsapi.status === 'fulfilled') all.push(...newsapi.value);
  if (mediastack.status === 'fulfilled') all.push(...mediastack.value);

  // Deduplicate by title similarity
  const seen = {};
  const unique = [];
  for (const h of all) {
    const key = dedupeKey(h.title);
    if (!key || seen[key]) continue;
    seen[key] = true;
    unique.push(h);
  }

  // Sort newest first
  unique.sort((a, b) => new Date(b.publishedAt) - new Date(a.publishedAt));

  return unique.slice(0, MAX_HEADLINES);
}

// ── Route: GET /api/news/headlines ───────────────────────────────────
// Returns { headlines: [...], cachedAt, ttl, provider }
// Cached in memory for CACHE_TTL_MS to respect API rate limits.
//
// Staleness handling:
//   - If the cache is fresh (< CACHE_TTL_MS old), serve it immediately.
//   - If the cache is stale but within STALE_MAX_MS, serve it with `stale: true`
//     and metadata (staleSince, failCount) so the client can show a warning.
//   - If the cache exceeds STALE_MAX_MS, discard it — return empty headlines
//     so the client doesn't display misleadingly old data.
//   - ?force=1 query parameter bypasses the TTL and forces a fresh fetch.

// Save-Data: reduce headline count and trim fields for low-bandwidth clients
function trimHeadlines(headlines) {
  return headlines.slice(0, 8).map(h => ({
    title: h.title.slice(0, 100),
    source: h.source,
    publishedAt: h.publishedAt,
    // omit url to save bytes — titles are informational in the ticker
  }));
}

/**
 * Checks whether the current cache has exceeded the maximum staleness
 * threshold and should be discarded.
 */
function isCacheExpired(now) {
  if (!headlineCache || !cacheTimestamp) return true;
  return (now - cacheTimestamp) > STALE_MAX_MS;
}

router.get('/headlines', async (req, res) => {
  try {
    const now = Date.now();
    const saveData = res.locals.saveData;
    const forceRefresh = req.query.force === '1' || req.query.force === 'true';

    // ── Expire ancient cache ─────────────────────────────────────
    if (isCacheExpired(now)) {
      if (headlineCache) {
        log.warn(
          { ageMin: Math.round((now - cacheTimestamp) / 60000), failCount: consecutiveFailures },
          'News cache exceeded max staleness — discarding'
        );
      }
      headlineCache = null;
      cacheTimestamp = 0;
    }

    // ── Serve from cache if still fresh (and not force-refreshing) ──
    if (!forceRefresh && headlineCache && (now - cacheTimestamp) < CACHE_TTL_MS) {
      res.setHeader('X-News-Cache', 'HIT');
      const headlines = saveData ? trimHeadlines(headlineCache) : headlineCache;
      const ttlSec = Math.round((CACHE_TTL_MS - (now - cacheTimestamp)) / 1000);
      return conditionalOk(req, res, {
        headlines: headlines,
        cachedAt: new Date(cacheTimestamp).toISOString(),
        ttl: ttlSec,
      }, {
        etag: 'news-' + cacheTimestamp,
        lastModified: cacheTimestamp,
        maxAge: ttlSec,
      });
    }

    // ── Fetch fresh headlines ────────────────────────────────────
    const headlines = await fetchAllHeadlines();

    if (headlines.length > 0) {
      // Success — update cache and reset failure tracking
      headlineCache = headlines;
      cacheTimestamp = now;
      consecutiveFailures = 0;
      lastFailureTimestamp = 0;
      saveCacheToDB(headlines, now);
      log.info({ count: headlines.length }, 'News headlines refreshed');
    } else {
      // All providers returned nothing — track the failure
      consecutiveFailures++;
      lastFailureTimestamp = now;

      // Escalating log severity based on consecutive failures
      const meta = { failCount: consecutiveFailures, staleSinceMin: cacheTimestamp ? Math.round((now - cacheTimestamp) / 60000) : null };
      if (consecutiveFailures >= 10) {
        log.error(meta, 'News fetch failing persistently — all providers down');
      } else if (consecutiveFailures >= 3) {
        log.warn(meta, 'News fetch failed multiple times in a row');
      } else {
        log.info(meta, 'News fetch returned no results — serving stale cache');
      }
    }

    // ── Build response ───────────────────────────────────────────
    const result = headlineCache || [];
    const output = saveData ? trimHeadlines(result) : result;
    const isStale = headlines.length === 0 && headlineCache !== null;

    res.setHeader('X-News-Cache', headlines.length > 0 ? 'MISS' : (headlineCache ? 'STALE' : 'EMPTY'));

    const response = {
      headlines: output,
      cachedAt: cacheTimestamp ? new Date(cacheTimestamp).toISOString() : null,
      ttl: Math.round(CACHE_TTL_MS / 1000),
    };

    // Include staleness metadata so the client can display a warning
    if (isStale) {
      response.stale = true;
      response.staleSince = new Date(cacheTimestamp).toISOString();
      response.staleAgeSec = Math.round((now - cacheTimestamp) / 1000);
      response.failCount = consecutiveFailures;
    }

    conditionalOk(req, res, response, {
      etag: cacheTimestamp ? 'news-' + cacheTimestamp : null,
      lastModified: cacheTimestamp || null,
      maxAge: isStale ? 0 : Math.round(CACHE_TTL_MS / 1000),
    });
  } catch (err) {
    log.error({ err }, 'News headlines endpoint failed');
    // Return stale cache if available and not expired, empty array otherwise
    const now = Date.now();
    if (headlineCache && !isCacheExpired(now)) {
      ok(res, {
        headlines: headlineCache,
        cachedAt: new Date(cacheTimestamp).toISOString(),
        stale: true,
        staleSince: new Date(cacheTimestamp).toISOString(),
        staleAgeSec: Math.round((now - cacheTimestamp) / 1000),
        error: 'Fetch failed — serving cached data',
      });
    } else {
      fail(res, 502, 'Failed to fetch headlines');
    }
  }
});

module.exports = router;
