const express = require('express');
const https = require('https');
const http = require('http');
const log = require('../logger').child({ module: 'news' });

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

// In-memory cache (survives across requests, cleared on restart)
let headlineCache = null;
let cacheTimestamp = 0;

// ── Helpers ──────────────────────────────────────────────────────────

/**
 * HTTP GET with optional headers. Returns parsed JSON.
 * Any error message redacts query parameters to prevent key leakage in logs.
 */
function httpGet(url, headers) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const parsed = new URL(url);
    const safeUrl = parsed.origin + parsed.pathname; // strip querystring for logging
    const options = {
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      timeout: 10000,
      headers: headers || {},
    };
    const req = mod.get(options, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch (e) { reject(new Error('Invalid JSON from ' + safeUrl)); }
      });
    });
    req.on('error', (err) => reject(new Error(safeUrl + ': ' + err.message)));
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout: ' + safeUrl)); });
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
// Returns { headlines: [...], cachedAt, provider }
// Cached in memory for CACHE_TTL_MS to respect API rate limits.

// Save-Data: reduce headline count and trim fields for low-bandwidth clients
function trimHeadlines(headlines) {
  return headlines.slice(0, 8).map(h => ({
    title: h.title.slice(0, 100),
    source: h.source,
    publishedAt: h.publishedAt,
    // omit url to save bytes — titles are informational in the ticker
  }));
}
router.get('/headlines', async (req, res) => {
  try {
    const now = Date.now();
    const saveData = res.locals.saveData;

    // Serve from cache if still fresh
    if (headlineCache && (now - cacheTimestamp) < CACHE_TTL_MS) {
      res.setHeader('X-News-Cache', 'HIT');
      const headlines = saveData ? trimHeadlines(headlineCache) : headlineCache;
      return res.json({
        headlines: headlines,
        cachedAt: new Date(cacheTimestamp).toISOString(),
        ttl: Math.round((CACHE_TTL_MS - (now - cacheTimestamp)) / 1000),
      });
    }

    const headlines = await fetchAllHeadlines();

    // Only update cache if we got results (preserve stale cache on API failure)
    if (headlines.length > 0) {
      headlineCache = headlines;
      cacheTimestamp = now;
    }

    const result = headlineCache || [];
    const output = saveData ? trimHeadlines(result) : result;
    res.setHeader('X-News-Cache', headlines.length > 0 ? 'MISS' : 'STALE');
    res.json({
      headlines: output,
      cachedAt: new Date(cacheTimestamp || now).toISOString(),
      ttl: Math.round(CACHE_TTL_MS / 1000),
    });

    if (headlines.length > 0) {
      log.info({ count: headlines.length }, 'News headlines refreshed');
    }
  } catch (err) {
    log.error({ err }, 'News headlines endpoint failed');
    // Return stale cache if available, empty array otherwise
    res.status(headlineCache ? 200 : 502).json({
      headlines: headlineCache || [],
      error: 'Failed to fetch headlines',
    });
  }
});

module.exports = router;
