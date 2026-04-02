/**
 * Idempotency-Key middleware for mutation endpoints.
 *
 * Prevents duplicate side-effects (double password changes, double avatar
 * uploads, double alert creations, etc.) caused by network retries, user
 * double-clicks, or offline-sync replays.
 *
 * ── Protocol ────────────────────────────────────────────────────────────
 * Clients send an `Idempotency-Key` header (UUID or opaque string, max 256
 * chars) on POST / PUT / DELETE requests.  The middleware:
 *
 *   1. If no key is provided → pass through (backwards compatible).
 *   2. If the key was already used by the same user:
 *      a. Request is still in-flight → 409 Conflict (concurrent duplicate).
 *      b. Request completed          → replay the cached status + headers + body.
 *   3. If the key is new → execute the handler, cache the response, return it.
 *
 * Cached responses are stored in-memory with a configurable TTL (default 24h)
 * and a hard cap on total entries (default 10 000) with oldest-first eviction.
 *
 * ── Cache key ───────────────────────────────────────────────────────────
 * `${userId}:${idempotencyKey}` — scoped per user so keys from different
 * sessions never collide, and one user cannot probe another's keys.
 *
 * ── Usage ───────────────────────────────────────────────────────────────
 *   const { idempotent } = require('../utils/idempotency');
 *   router.post('/avatar', requireAuth, idempotent(), uploadHandler);
 *   router.put('/settings', requireAuth, idempotent(), settingsHandler);
 */

'use strict';

const log = require('./logger').child({ module: 'idempotency' });

// ── Configuration ────────────────────────────────────────────────────
const DEFAULT_TTL_MS    = 24 * 60 * 60 * 1000;  // 24 hours
const DEFAULT_MAX_ENTRIES = 10000;
const MAX_KEY_LENGTH    = 256;
const HEADER_NAME       = 'idempotency-key';

// ── In-memory store ──────────────────────────────────────────────────
// Map<compositeKey, { status, headers, body, createdAt, inFlight }>
const _store = new Map();

// Periodic cleanup: sweep expired entries every 10 minutes
const _sweepInterval = setInterval(() => {
  const now = Date.now();
  for (const [k, v] of _store) {
    if (now - v.createdAt > (v.ttl || DEFAULT_TTL_MS)) {
      _store.delete(k);
    }
  }
}, 10 * 60 * 1000);
if (_sweepInterval.unref) _sweepInterval.unref();

/**
 * Evict oldest entries when the store exceeds maxEntries.
 */
function _enforceLimit(maxEntries) {
  if (_store.size <= maxEntries) return;
  // Map iteration order is insertion order — delete from the front
  const excess = _store.size - maxEntries;
  let removed = 0;
  for (const key of _store.keys()) {
    if (removed >= excess) break;
    _store.delete(key);
    removed++;
  }
}

/**
 * Create the idempotency middleware.
 *
 * @param {object} [opts]
 * @param {number} [opts.ttlMs=86400000]       How long to cache responses (ms)
 * @param {number} [opts.maxEntries=10000]      Hard cap on cached entries
 * @returns {Function} Express middleware
 */
function idempotent(opts) {
  opts = opts || {};
  const ttlMs = opts.ttlMs || DEFAULT_TTL_MS;
  const maxEntries = opts.maxEntries || DEFAULT_MAX_ENTRIES;

  return function idempotencyMiddleware(req, res, next) {
    // Only apply to mutation methods
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
      return next();
    }

    const rawKey = req.headers[HEADER_NAME];

    // No key provided → pass through (backwards compatible)
    if (!rawKey) {
      return next();
    }

    // Validate key format
    if (typeof rawKey !== 'string' || rawKey.length === 0 || rawKey.length > MAX_KEY_LENGTH) {
      return res.status(400).json({
        ok: false,
        error: 'Invalid Idempotency-Key: must be a non-empty string of at most ' + MAX_KEY_LENGTH + ' characters.',
      });
    }

    // Require authentication — idempotency keys are scoped per user
    const userId = req.session && req.session.userId;
    if (!userId) {
      // If not authenticated, let the auth middleware downstream handle it
      return next();
    }

    const compositeKey = userId + ':' + rawKey;
    const existing = _store.get(compositeKey);

    if (existing) {
      // Check if expired
      if (Date.now() - existing.createdAt > ttlMs) {
        _store.delete(compositeKey);
        // Fall through to execute normally
      } else if (existing.inFlight) {
        // Concurrent duplicate — the original request is still being processed
        log.warn({ userId, idempotencyKey: rawKey }, 'Concurrent duplicate request rejected');
        return res.status(409).json({
          ok: false,
          error: 'A request with this Idempotency-Key is already being processed.',
        });
      } else {
        // Replay cached response
        log.info({ userId, idempotencyKey: rawKey }, 'Replaying cached idempotent response');
        res.setHeader('X-Idempotent-Replayed', 'true');
        // Restore original headers (content-type, etc.)
        if (existing.headers) {
          for (const [name, value] of Object.entries(existing.headers)) {
            // Skip headers that Express sets automatically
            if (name !== 'transfer-encoding' && name !== 'connection') {
              res.setHeader(name, value);
            }
          }
        }
        return res.status(existing.status).end(existing.body);
      }
    }

    // New key — mark as in-flight and intercept the response
    const entry = {
      inFlight: true,
      createdAt: Date.now(),
      ttl: ttlMs,
      status: null,
      headers: null,
      body: null,
    };
    _store.set(compositeKey, entry);
    _enforceLimit(maxEntries);

    // Intercept res.json() and res.end() to capture the response
    const originalJson = res.json.bind(res);
    const originalEnd = res.end.bind(res);

    function captureAndFinish(body) {
      entry.status = res.statusCode;
      // Capture relevant response headers
      const rawHeaders = res.getHeaders();
      const capturedHeaders = {};
      for (const [name, value] of Object.entries(rawHeaders)) {
        if (name === 'content-type' || name === 'x-sync-version' ||
            name === 'retry-after' || name === 'cache-control') {
          capturedHeaders[name] = value;
        }
      }
      entry.headers = capturedHeaders;
      entry.body = typeof body === 'string' ? body : (body ? JSON.stringify(body) : '');
      entry.inFlight = false;
    }

    res.json = function(obj) {
      captureAndFinish(obj);
      return originalJson(obj);
    };

    // Also intercept end() for non-JSON responses (e.g., 204 No Content)
    res.end = function(chunk, encoding) {
      if (entry.inFlight) {
        captureAndFinish(chunk || '');
      }
      return originalEnd(chunk, encoding);
    };

    // Safety net: if the request errors out and nothing is captured,
    // remove the in-flight marker so the key can be retried.
    res.on('close', () => {
      if (entry.inFlight) {
        _store.delete(compositeKey);
      }
    });

    next();
  };
}

/**
 * Shutdown hook — clear the store and cancel the sweep timer.
 * Called during graceful server shutdown.
 */
function shutdown() {
  clearInterval(_sweepInterval);
  _store.clear();
}

module.exports = { idempotent, shutdown, _store };
