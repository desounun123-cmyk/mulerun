/**
 * Safe Origin — prevent Host header injection
 *
 * Instead of trusting req.headers.host (which an attacker can set to any
 * domain), this module resolves the application's origin from a server-
 * configured allowlist.
 *
 * Set ALLOWED_ORIGIN in .env to your production URL:
 *   ALLOWED_ORIGIN=https://oil-benchmarks.com
 *
 * Multiple origins (e.g. staging + production) can be comma-separated:
 *   ALLOWED_ORIGIN=https://oil-benchmarks.com,https://staging.oil-benchmarks.com
 *
 * If ALLOWED_ORIGIN is not set, the module falls back to constructing the
 * origin from the request — but ONLY after validating the Host header against
 * a strict hostname regex (no paths, no fragments, no user-info).
 */

const log = require('../logger').child({ module: 'safe-origin' });

// Parse allowed origins from env (comma-separated list)
const allowedOrigins = (process.env.ALLOWED_ORIGIN || '')
  .split(',')
  .map(s => s.trim().replace(/\/+$/, ''))  // strip trailing slashes
  .filter(Boolean);

if (allowedOrigins.length > 0) {
  log.info({ allowedOrigins }, 'Host header injection protection: using configured ALLOWED_ORIGIN');
} else {
  log.warn('ALLOWED_ORIGIN not set — falling back to validated Host header. Set ALLOWED_ORIGIN in .env for production.');
}

// Strict pattern: hostname (or IP) with optional port, nothing else
const VALID_HOST_RE = /^[a-zA-Z0-9._-]+(:\d{1,5})?$/;

/**
 * Returns a safe origin string (e.g. "https://oil-benchmarks.com").
 *
 * Resolution order:
 *   1. First matching ALLOWED_ORIGIN (preferred — fully server-controlled)
 *   2. Validated Host header with req.protocol (fallback for dev)
 *   3. Hardcoded localhost default (last resort)
 */
function getSafeOrigin(req) {
  // 1. If ALLOWED_ORIGIN is configured, use the first one
  //    (multi-origin: pick the one matching the request host, or default to first)
  if (allowedOrigins.length > 0) {
    if (allowedOrigins.length === 1) {
      return allowedOrigins[0];
    }
    // Multi-origin: try to match request host to pick the right one
    const reqHost = (req.headers.host || '').toLowerCase().replace(/\/+$/, '');
    for (const origin of allowedOrigins) {
      try {
        const u = new URL(origin);
        if (u.host === reqHost) return origin;
      } catch (_) { /* skip malformed */ }
    }
    // No match — return the first (primary) origin
    return allowedOrigins[0];
  }

  // 2. Fallback: validate the Host header to block injection
  const rawHost = req.headers.host || '';
  const protocol = req.protocol || 'http';

  if (VALID_HOST_RE.test(rawHost)) {
    return `${protocol}://${rawHost}`;
  }

  // 3. Host header is suspicious — refuse to use it
  log.warn({ host: rawHost }, 'Rejected suspicious Host header — using localhost fallback');
  const port = process.env.PORT || '8080';
  return `${protocol}://localhost${port !== '80' && port !== '443' ? ':' + port : ''}`;
}

module.exports = { getSafeOrigin };
