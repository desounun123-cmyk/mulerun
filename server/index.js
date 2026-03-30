require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const pinoHttp = require('pino-http');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const http2 = require('http2');
const https = require('https');
const http = require('http');
const zlib = require('zlib');
const log = require('./utils/logger');

// Initialize database (runs migrations + seed)
const db = require('./db');

// Initialize PITR change-log triggers (must come after migrations, before traffic)
const { initPitrChangeLog, PITR_ENABLED } = require('./backup');
initPitrChangeLog(db);

// Session store — SQLite by default, PostgreSQL when DATABASE_URL is set
const isPgMode = !!process.env.DATABASE_URL;
let SessionStore;
if (isPgMode) {
  const ConnectPgSimple = require('connect-pg-simple');
  SessionStore = ConnectPgSimple(session);
} else {
  const BetterSqlite3SessionStore = require('better-sqlite3-session-store');
  SessionStore = BetterSqlite3SessionStore(session);
}

const app = express();
const PORT = parseInt(process.env.PORT, 10) || 8080;
const HTTP_PORT = parseInt(process.env.HTTP_PORT, 10) || 80;

// ── TLS configuration ───────────────────────────────────────────────
// Provide TLS_CERT_PATH and TLS_KEY_PATH to enable HTTPS directly in Node.
// When TLS is enabled:
//   - The main server listens on PORT over HTTPS
//   - A lightweight HTTP server on HTTP_PORT redirects all traffic to HTTPS
//   - Session & CSRF cookies use __Host- / __Secure- prefixes (require Secure flag)
// When TLS is NOT configured (dev mode):
//   - The server runs plain HTTP on PORT
//   - Cookies work without Secure flag
const tlsCertPath = process.env.TLS_CERT_PATH;
const tlsKeyPath  = process.env.TLS_KEY_PATH;
const tlsEnabled  = !!(tlsCertPath && tlsKeyPath);
let tlsOptions = null;

if (tlsEnabled) {
  try {
    tlsOptions = {
      cert: fs.readFileSync(path.resolve(tlsCertPath)),
      key:  fs.readFileSync(path.resolve(tlsKeyPath)),
    };
    // Optional CA chain (intermediate certificates)
    if (process.env.TLS_CA_PATH) {
      tlsOptions.ca = fs.readFileSync(path.resolve(process.env.TLS_CA_PATH));
    }
    log.info('TLS certificates loaded — HTTPS enabled');
  } catch (err) {
    log.fatal({ err }, 'Failed to load TLS certificates');
    process.exit(1);
  }
}

// isSecure is true when TLS is enabled natively OR when behind a trusted HTTPS proxy
const isSecure = tlsEnabled || process.env.COOKIE_SECURE === 'true';

// ── Trust proxy — correct IP detection behind reverse proxies ────
// Express uses this to resolve `req.ip`, `req.protocol`, and `req.hostname`
// from the X-Forwarded-* headers set by your reverse proxy (nginx, Cloudflare,
// AWS ALB, etc.).
//
// TRUST_PROXY accepts:
//   - A number: how many proxy hops to trust (e.g. "1" for a single nginx in front)
//   - A comma-separated list of trusted IPs/CIDRs (e.g. "10.0.0.0/8, 172.16.0.0/12")
//   - "true"  — trust any proxy (only safe in fully controlled networks)
//   - "false" — trust no proxy; req.ip = direct connection IP (default when not set)
//
// Common setups:
//   Single nginx/Caddy on same host       → TRUST_PROXY=1
//   AWS ALB + nginx                        → TRUST_PROXY=2
//   Cloudflare + nginx                     → TRUST_PROXY=2
//   Docker bridge network                  → TRUST_PROXY=172.17.0.0/16
//   Known proxy IPs                        → TRUST_PROXY=10.0.0.1,10.0.0.2
//
// WARNING: Setting this too permissively lets clients spoof their IP via
//          X-Forwarded-For, defeating rate limiting and IP-based security.
const trustProxyRaw = process.env.TRUST_PROXY;
let trustProxySetting;

if (trustProxyRaw === undefined || trustProxyRaw === '') {
  // Default: trust 1 hop (single reverse proxy — the most common deployment)
  trustProxySetting = 1;
} else if (trustProxyRaw === 'true') {
  trustProxySetting = true;
} else if (trustProxyRaw === 'false') {
  trustProxySetting = false;
} else if (/^\d+$/.test(trustProxyRaw)) {
  // Numeric hop count
  trustProxySetting = parseInt(trustProxyRaw, 10);
} else {
  // IP addresses or CIDR ranges (comma-separated → trimmed array)
  trustProxySetting = trustProxyRaw.split(',').map(s => s.trim()).filter(Boolean);
}

app.set('trust proxy', trustProxySetting);
log.info({ trustProxy: trustProxySetting }, 'Trust proxy configured');

// ── Per-request CSP nonce generation ─────────────────────────────
// Must run BEFORE helmet so the nonce is available for the CSP directive.
app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
  next();
});

// ── Helmet — HTTP security headers ──────────────────────────────
// Helmet sets a comprehensive suite of headers in a single middleware:
//   - Content-Security-Policy (with per-request nonce)
//   - Strict-Transport-Security (HSTS) — only when isSecure
//   - X-Content-Type-Options: nosniff
//   - X-DNS-Prefetch-Control: off
//   - X-Download-Options: noopen
//   - X-Frame-Options: DENY  (reinforces CSP frame-ancestors 'none')
//   - X-Permitted-Cross-Domain-Policies: none
//   - X-XSS-Protection: 0  (disabled — CSP is the modern replacement)
//   - Origin-Agent-Cluster: ?1
//   - Referrer-Policy: no-referrer
//   - Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, etc.
if (process.env.DISABLE_HELMET !== 'true') {
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        (req, res) => `'nonce-${res.locals.cspNonce}'`,
        "https://cdn.jsdelivr.net"
      ],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https://api.qrserver.com"],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      objectSrc: ["'none'"]
    }
  },
  // HSTS — only enable when running over HTTPS
  strictTransportSecurity: isSecure
    ? { maxAge: 31536000, includeSubDomains: true, preload: true }
    : false,
  frameguard: { action: 'deny' },
  // Referrer-Policy — strict default; loosen if analytics need origin
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));
} // end DISABLE_HELMET guard

// ── HTTP request logging via pino ────────────────────────────────
app.use(pinoHttp({
  logger: log.child({ module: 'http' }),
  // Don't log health-check / static asset noise in production
  autoLogging: {
    ignore: (req) => {
      const url = req.url || '';
      return url === '/health' || url.startsWith('/uploads/') || url.endsWith('.js') || url.endsWith('.css') ||
             url.endsWith('.png') || url.endsWith('.ico') || url.endsWith('.woff2');
    }
  },
  // Custom log level based on status code
  customLogLevel: function (req, res, err) {
    if (res.statusCode >= 500 || err) return 'error';
    if (res.statusCode >= 400) return 'warn';
    return 'info';
  },
  // Attach useful request metadata
  customProps: function (req) {
    return {
      userId: req.session && req.session.userId ? req.session.userId : undefined,
    };
  },
}));

// Gzip / Brotli compression for all responses above 1 KB
// Brotli is preferred when the client supports it (better ratio, ~20-30% smaller than gzip)
app.use(compression({
  level: 6,           // zlib compression level (1-9, 6 is a good speed/ratio balance)
  threshold: 512,     // compress responses larger than 512 bytes (lowered for low-bandwidth)
  // Prefer Brotli when the client accepts it — better compression ratio
  brotli: {
    enabled: true,
    zlib: {
      params: {
        [zlib.constants.BROTLI_PARAM_QUALITY]: 4,  // 0-11, 4 balances speed/ratio for dynamic content
      }
    }
  },
  filter: function(req, res) {
    // Skip already-compressed formats (images, video, etc.)
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  }
}));

// ── Save-Data & low-bandwidth detection middleware ──────────────
// Reads the Save-Data client hint and connection quality hints.
// Sets res.locals.saveData = true when the client signals low-bandwidth.
// Downstream routes can use this to trim payloads.
app.use((req, res, next) => {
  const saveData = req.headers['save-data'] === 'on';
  const downlink = parseFloat(req.headers['downlink']) || Infinity;
  const ect = req.headers['ect'] || '4g'; // effective connection type
  const slowConnection = ect === 'slow-2g' || ect === '2g' || ect === '3g' || downlink < 1.5;

  res.locals.saveData = saveData || slowConnection;
  res.locals.connectionQuality = slowConnection ? 'slow' : 'fast';

  // Add Vary header so caches distinguish between full and reduced payloads
  res.vary('Save-Data');
  res.vary('ECT');

  // Tell the client we accept these hints
  if (!res.headersSent) {
    res.setHeader('Accept-CH', 'Save-Data, ECT, Downlink');
  }
  next();
});

// Parse JSON bodies
app.use(express.json());

// Session configuration
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) {
  log.warn('SESSION_SECRET not set — using random secret. Sessions will not survive restarts.');
}
const cookieMaxAgeDays = parseInt(process.env.COOKIE_MAX_AGE_DAYS, 10) || 7;

// When running over HTTPS (TLS enabled or behind a secure proxy), use the __Host-
// cookie prefix for the session cookie. __Host- requires: Secure, Path=/, no Domain —
// this pins the cookie to the exact origin and prevents subdomain hijacking.
const sessionCookieName = isSecure ? '__Host-oil.sid' : 'oil.sid';

app.use(session({
  name: sessionCookieName,
  store: isPgMode
    ? new SessionStore({
        pool: db._pool,
        tableName: 'sessions',
        createTableIfMissing: true,
      })
    : new SessionStore({
        client: db,
        expired: {
          clear: false       // Disabled — cleanup handled by dedicated background job below
        }
      }),
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isSecure,
    maxAge: cookieMaxAgeDays * 24 * 60 * 60 * 1000,
    sameSite: 'lax',
    path: '/'          // required by __Host- prefix
    // domain is intentionally omitted — required by __Host- prefix
  }
}));

// Capture IP (hashed) and user-agent on every authenticated request
app.use((req, res, next) => {
  if (req.session && req.session.userId) {
    const ip = req.ip || req.connection.remoteAddress || '';
    const ipHash = crypto.createHash('sha256').update(ip).digest('hex').slice(0, 12);
    req.session.ipHash = ipHash;
    req.session.ua = (req.headers['user-agent'] || '').slice(0, 200);
    req.session.lastSeen = new Date().toISOString();
  }
  next();
});

// ── CSRF protection ──────────────────────────────────────────────
// Strategy: Synchronizer Token Pattern via session.
// 1) Every request gets a CSRF token generated (if not already in session)
//    and exposed via a readable `XSRF-TOKEN` cookie.
// 2) State-changing requests (POST/PUT/DELETE) to /api/* must include the
//    token in the `X-CSRF-Token` header. The middleware compares it to
//    the session value.
// 3) Exempt routes: login, register, forgot (no session yet), and
//    the analytics beacon (fire-and-forget from unauthenticated visitors).

// Generate / refresh the CSRF token cookie on every request
app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  // Set a JS-readable cookie so the frontend can read it
  // (NOT httpOnly — the browser JS needs to read this and send it as a header)
  // Use __Secure- prefix in production to guarantee the cookie is only sent over HTTPS.
  const csrfCookieName = isSecure ? '__Secure-XSRF-TOKEN' : 'XSRF-TOKEN';
  res.cookie(csrfCookieName, req.session.csrfToken, {
    httpOnly: false,
    secure: isSecure,
    sameSite: 'lax',
    path: '/'
  });
  next();
});

// Validate CSRF token on state-changing API requests
const CSRF_EXEMPT = [
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/forgot',
  '/api/auth/reset',
  '/api/analytics/pageview',
  '/api/analytics/event',
];

app.use('/api', (req, res, next) => {
  // Only enforce on state-changing methods
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return next();
  }
  // Skip exempt routes
  const fullPath = '/api' + req.path;
  if (CSRF_EXEMPT.some(p => fullPath === p || fullPath.startsWith(p + '/'))) {
    return next();
  }
  // Skip in test mode
  if (process.env.NODE_ENV === 'test') {
    return next();
  }
  const headerToken = req.headers['x-csrf-token'];
  if (!headerToken || !req.session.csrfToken || headerToken !== req.session.csrfToken) {
    return res.status(403).json({ error: 'Invalid or missing CSRF token.' });
  }
  next();
});

// ── Serve index.html with CSP nonce injection ──────────────────────
// Reads the static file and injects nonce attributes into <script> tags
// so the Content-Security-Policy header permits their execution.
const indexHtmlPath = path.join(__dirname, '..', 'index.html');
let indexHtmlCache = null;

// ── HTTP/2 Server Push — critical assets ───────────────────────────
// When the main page is requested over HTTP/2, proactively push resources
// the browser will need immediately. This eliminates the round-trip where
// the browser parses HTML, discovers <link>/<script> tags, and only then
// requests them. For HTTP/1.1 clients (or when behind a proxy that speaks
// HTTP/2 to the client), we fall back to Link preload headers.
const CRITICAL_PUSH_ASSETS = [
  { path: '/manifest.json',       as: 'manifest', type: 'application/manifest+json' },
  { path: '/icons/favicon.svg',   as: 'image',    type: 'image/svg+xml' },
  { path: '/sw.js',               as: 'script',   type: 'application/javascript' },
];

// Build the Link header value once (used as fallback for HTTP/1.1 and proxies)
const LINK_PRELOAD_HEADER = CRITICAL_PUSH_ASSETS
  .map(a => `<${a.path}>; rel=preload; as=${a.as}; type=${a.type}`)
  .join(', ');

// Push a single asset over an HTTP/2 stream
function pushAsset(res, asset) {
  // res.stream exists only on HTTP/2 connections (http2.Http2ServerResponse)
  if (!res.stream || typeof res.stream.pushStream !== 'function') return;

  res.stream.pushStream({ ':path': asset.path }, (err, pushStream) => {
    if (err) {
      // Client may have disabled push (SETTINGS_ENABLE_PUSH=0) or RST_STREAM'd
      log.debug({ err, path: asset.path }, 'HTTP/2 push rejected');
      return;
    }

    const filePath = path.join(__dirname, '..', asset.path);
    try {
      pushStream.respond({
        ':status': 200,
        'content-type': asset.type,
        'cache-control': asset.as === 'manifest'
          ? 'public, max-age=86400, must-revalidate'
          : 'public, max-age=604800, immutable',
      });
      const fileStream = fs.createReadStream(filePath);
      fileStream.pipe(pushStream);
      fileStream.on('error', () => pushStream.destroy());
    } catch (e) {
      pushStream.destroy();
    }
  });
}

app.get(['/', '/index.html'], (req, res) => {
  try {
    // Read and cache the raw HTML (invalidated on restart / re-deploy)
    if (!indexHtmlCache) {
      indexHtmlCache = fs.readFileSync(indexHtmlPath, 'utf8');
    }
    const nonce = res.locals.cspNonce;
    // Inject nonce into all <script> tags (both opening <script> and <script ...>)
    const html = indexHtmlCache
      .replace(/<script(?=[\s>])/gi, `<script nonce="${nonce}"`);

    // HTTP/2 Server Push: proactively send critical assets before the browser asks
    if (res.stream && typeof res.stream.pushStream === 'function') {
      for (const asset of CRITICAL_PUSH_ASSETS) {
        pushAsset(res, asset);
      }
    }

    // Link preload headers — picked up by HTTP/2-aware reverse proxies (nginx,
    // Cloudflare, AWS ALB) and used as resource hints by HTTP/1.1 browsers
    res.setHeader('Link', LINK_PRELOAD_HEADER);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, must-revalidate');
    res.send(html);
  } catch (err) {
    log.error({ err }, 'Failed to serve index.html with CSP nonce');
    res.status(500).send('Internal server error');
  }
});

// Serve static frontend files from parent directory
// ── Cache-Control strategy ──────────────────────────────────────────
// • HTML files:  no-cache (always revalidate, ETag still applies)
// • Icons/SVG:   7 days, immutable (fingerprinted by content via ETag)
// • JS/JSON:     1 day  (sw.js, manifest.json — revalidate daily)
// • Everything else: 1 hour
app.use(express.static(path.join(__dirname, '..'), {
  etag: true,                     // generate ETag from file content
  lastModified: true,             // send Last-Modified header
  setHeaders: function(res, filePath) {
    const ext = path.extname(filePath).toLowerCase();
    if (ext === '.html') {
      // HTML must always revalidate to pick up new deployments
      res.setHeader('Cache-Control', 'no-cache, must-revalidate');
    } else if (ext === '.svg' || ext === '.png' || ext === '.ico' || ext === '.webp' || ext === '.jpg' || ext === '.jpeg') {
      // Images/icons: long cache, immutable — ETag handles invalidation
      res.setHeader('Cache-Control', 'public, max-age=604800, immutable');
    } else if (ext === '.js' || ext === '.json') {
      // JS & JSON (service worker, manifest): cache 1 day, revalidate after
      res.setHeader('Cache-Control', 'public, max-age=86400, must-revalidate');
    } else if (ext === '.css' || ext === '.woff' || ext === '.woff2' || ext === '.ttf') {
      // Stylesheets & fonts: 7 days
      res.setHeader('Cache-Control', 'public, max-age=604800, immutable');
    } else {
      // Fallback: 1 hour
      res.setHeader('Cache-Control', 'public, max-age=3600');
    }
  }
}));

// Serve vendor scripts (Chart.js etc.) under /admin path so the service worker
// skips them (SW returns early for /admin* routes — network-only).
app.use('/admin/vendor', express.static(path.join(__dirname, 'public', 'vendor'), {
  etag: true,
  lastModified: true,
  setHeaders: function(res) {
    res.setHeader('Cache-Control', 'public, max-age=604800, immutable');
  }
}));

// Serve uploaded avatars — moderate cache, ETag for revalidation
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  etag: true,
  lastModified: true,
  setHeaders: function(res) {
    // Avatars can change when user uploads a new one; cache 1 day with revalidation
    res.setHeader('Cache-Control', 'public, max-age=86400, must-revalidate');
  }
}));

// API routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/user', require('./routes/user'));
app.use('/api/analytics', require('./routes/analytics'));
app.use('/api/oauth', require('./routes/oauth'));
app.use('/api/news', require('./routes/news'));
app.use('/api/admin', requireAdmin, require('./routes/admin'));

// ─── RESET PASSWORD PAGE ─────────────────────────────────────
app.get('/reset-password', (req, res) => {
  const token = req.query.token || '';
  const nonce = res.locals.cspNonce;
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Reset Password — OIL Benchmarks</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0c0c0e;color:#e8e4dc;font-family:'DM Mono',monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.card{background:#111;border:2px solid #444;border-radius:8px;width:400px;max-width:100%;padding:28px 24px;box-shadow:0 20px 60px rgba(0,0,0,0.8)}
.card h1{font-size:14px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:8px;color:#c9a84c}
.card p{font-size:10px;color:#888;line-height:1.5;margin-bottom:18px}
.field{margin-bottom:12px}
.field label{display:block;font-size:9px;font-weight:700;letter-spacing:0.5px;color:#888;margin-bottom:4px;text-transform:uppercase}
.field input{width:100%;padding:9px 10px;background:#1a1a1a;border:1px solid #333;border-radius:4px;color:#e8e4dc;font-family:'DM Mono',monospace;font-size:11px;transition:border-color 0.2s}
.field input:focus{outline:none;border-color:rgba(201,168,76,0.5)}
.btn{display:block;width:100%;padding:10px;background:linear-gradient(135deg,#85783c,#c9a84c);border:none;border-radius:4px;color:#0c0c0e;font-family:'DM Mono',monospace;font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;cursor:pointer;transition:filter 0.2s;margin-top:6px}
.btn:hover{filter:brightness(1.15)}
.btn:disabled{opacity:0.5;cursor:default}
.msg{font-size:10px;margin-top:12px;padding:8px 10px;border-radius:4px;display:none}
.msg.error{display:block;background:rgba(224,80,64,0.1);border:1px solid rgba(224,80,64,0.3);color:#e05040}
.msg.success{display:block;background:rgba(76,175,104,0.1);border:1px solid rgba(76,175,104,0.3);color:#4caf68}
.back{display:block;text-align:center;margin-top:16px;font-size:10px;color:rgba(201,168,76,0.7);text-decoration:none;letter-spacing:0.5px}
.back:hover{color:#c9a84c}
</style>
</head>
<body>
<div class="card">
  <h1>Reset Password</h1>
  <p>Enter your new password below.</p>
  <div class="field">
    <label>New Password</label>
    <input type="password" id="pw1" placeholder="Min. 8 characters" autocomplete="new-password">
  </div>
  <div class="field">
    <label>Confirm Password</label>
    <input type="password" id="pw2" placeholder="Re-enter password" autocomplete="new-password">
  </div>
  <button class="btn" id="submit-btn">Reset Password</button>
  <div style="position:absolute;left:-9999px;top:-9999px;opacity:0;height:0;overflow:hidden;" aria-hidden="true" tabindex="-1">
    <input type="text" name="website" id="hp-website" autocomplete="off" tabindex="-1">
    <input type="email" name="confirm_email" id="hp-confirm-email" autocomplete="off" tabindex="-1">
  </div>
  <div class="msg" id="msg"></div>
  <a href="/" class="back">&larr; Back to OIL Benchmarks</a>
</div>
<script nonce="${nonce}">
var token = ${JSON.stringify(token)};
var btn = document.getElementById('submit-btn');
var msg = document.getElementById('msg');
btn.addEventListener('click', function() {
  var pw1 = document.getElementById('pw1').value;
  var pw2 = document.getElementById('pw2').value;
  msg.className = 'msg'; msg.style.display = 'none';
  if (!pw1 || !pw2) { msg.textContent = 'Please fill in both fields.'; msg.className = 'msg error'; return; }
  if (pw1.length < 8) { msg.textContent = 'Password must be at least 8 characters.'; msg.className = 'msg error'; return; }
  if (pw1 !== pw2) { msg.textContent = 'Passwords do not match.'; msg.className = 'msg error'; return; }
  btn.disabled = true; btn.textContent = '...';
  fetch('/api/auth/reset', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: token, newPassword: pw1, website: document.getElementById('hp-website').value, confirm_email: document.getElementById('hp-confirm-email').value })
  })
  .then(function(r) { return r.json(); })
  .then(function(data) {
    btn.disabled = false; btn.textContent = 'Reset Password';
    if (data.error) { msg.textContent = data.error; msg.className = 'msg error'; }
    else { msg.textContent = 'Password reset! You can now sign in.'; msg.className = 'msg success'; btn.style.display = 'none'; }
  })
  .catch(function() { btn.disabled = false; btn.textContent = 'Reset Password'; msg.textContent = 'Something went wrong.'; msg.className = 'msg error'; });
});
</script>
</body>
</html>`);
});

// ─── VERIFY EMAIL PAGE ──────────────────────────────────────
app.get('/verify-email', (req, res) => {
  const token = req.query.token || '';
  const nonce = res.locals.cspNonce;
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verify Email — OIL Benchmarks</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0c0c0e;color:#e8e4dc;font-family:'DM Mono',monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.card{background:#111;border:2px solid #444;border-radius:8px;width:400px;max-width:100%;padding:28px 24px;box-shadow:0 20px 60px rgba(0,0,0,0.8);text-align:center}
.card h1{font-size:14px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:8px;color:#c9a84c}
.card p{font-size:10px;color:#888;line-height:1.5;margin-bottom:18px}
.spinner{display:inline-block;width:28px;height:28px;border:3px solid #333;border-top-color:#c9a84c;border-radius:50%;animation:spin 0.8s linear infinite;margin:16px 0}
@keyframes spin{to{transform:rotate(360deg)}}
.msg{font-size:11px;margin-top:12px;padding:10px 12px;border-radius:4px;display:none;line-height:1.5}
.msg.error{display:block;background:rgba(224,80,64,0.1);border:1px solid rgba(224,80,64,0.3);color:#e05040}
.msg.success{display:block;background:rgba(76,175,104,0.1);border:1px solid rgba(76,175,104,0.3);color:#4caf68}
.back{display:block;text-align:center;margin-top:16px;font-size:10px;color:rgba(201,168,76,0.7);text-decoration:none;letter-spacing:0.5px}
.back:hover{color:#c9a84c}
.icon{font-size:36px;margin-bottom:10px}
</style>
</head>
<body>
<div class="card">
  <h1>Email Verification</h1>
  <p id="status-text">Verifying your email address...</p>
  <div class="spinner" id="spinner"></div>
  <div class="msg" id="msg"></div>
  <a href="/" class="back">&larr; Back to OIL Benchmarks</a>
</div>
<script nonce="${nonce}">
var token = ${JSON.stringify(token)};
var msg = document.getElementById('msg');
var spinner = document.getElementById('spinner');
var statusText = document.getElementById('status-text');
if (!token) {
  spinner.style.display = 'none';
  statusText.textContent = '';
  msg.textContent = 'No verification token provided.';
  msg.className = 'msg error';
} else {
  fetch('/api/auth/verify?token=' + encodeURIComponent(token))
  .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
  .then(function(res) {
    spinner.style.display = 'none';
    if (res.ok || res.data.alreadyVerified) {
      statusText.innerHTML = '<span class="icon">&#10003;</span>';
      msg.textContent = res.data.alreadyVerified ? 'Your email is already verified.' : 'Your email has been verified successfully! You can now use all features.';
      msg.className = 'msg success';
    } else {
      statusText.innerHTML = '<span class="icon">&#10007;</span>';
      msg.textContent = res.data.error || 'Verification failed.';
      msg.className = 'msg error';
    }
  })
  .catch(function() {
    spinner.style.display = 'none';
    statusText.innerHTML = '<span class="icon">&#10007;</span>';
    msg.textContent = 'Something went wrong. Please try again.';
    msg.className = 'msg error';
  });
}
</script>
</body>
</html>`);
});

// ─── Admin authentication middleware ─────────────────────────────
function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).send('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Unauthorized</title><link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&display=swap" rel="stylesheet"><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0c0c0e;color:#e8e4dc;font-family:"DM Mono",monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}.card{background:#111;border:2px solid #444;border-radius:8px;width:360px;padding:28px 24px;text-align:center}.card h1{font-size:14px;color:#e03030;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:12px}.card p{font-size:11px;color:#888;line-height:1.6;margin-bottom:18px}.back{display:inline-block;padding:8px 16px;background:linear-gradient(135deg,#85783c,#c9a84c);border-radius:4px;color:#0c0c0e;font-weight:700;font-size:10px;letter-spacing:1px;text-decoration:none;text-transform:uppercase}.back:hover{filter:brightness(1.15)}</style></head><body><div class="card"><h1>401 — Unauthorized</h1><p>You must be logged in as an admin to access this page.</p><a class="back" href="/">Back to App</a></div></body></html>');
  }
  const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.plan !== 'Admin') {
    return res.status(403).send('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Forbidden</title><link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&display=swap" rel="stylesheet"><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0c0c0e;color:#e8e4dc;font-family:"DM Mono",monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}.card{background:#111;border:2px solid #444;border-radius:8px;width:360px;padding:28px 24px;text-align:center}.card h1{font-size:14px;color:#e03030;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:12px}.card p{font-size:11px;color:#888;line-height:1.6;margin-bottom:18px}.back{display:inline-block;padding:8px 16px;background:linear-gradient(135deg,#85783c,#c9a84c);border-radius:4px;color:#0c0c0e;font-weight:700;font-size:10px;letter-spacing:1px;text-decoration:none;text-transform:uppercase}.back:hover{filter:brightness(1.15)}</style></head><body><div class="card"><h1>403 — Forbidden</h1><p>Admin access required. Your account does not have permission to view this page.</p><a class="back" href="/">Back to App</a></div></body></html>');
  }
  next();
}

// ─── ADMIN PAGE (shell — data loaded via /api/admin endpoints) ──
app.get('/admin', requireAdmin, (req, res) => {
  const nonce = res.locals.cspNonce;
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin — Oil Benchmarks</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0c0c0e;color:#e8e4dc;font-family:'DM Mono',monospace;padding:24px;font-size:13px}
main{display:block}header,section,footer,article,nav,aside{display:block}
h1{font-size:18px;color:#c9a84c;letter-spacing:2px;text-transform:uppercase;margin-bottom:6px}
.subtitle{font-size:10px;color:#666;letter-spacing:1px;margin-bottom:24px}
.warn{background:rgba(224,48,48,0.1);border:1px solid rgba(224,48,48,0.3);border-radius:4px;padding:8px 14px;font-size:10px;color:#e03030;margin-bottom:20px;letter-spacing:0.5px}
.stats{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}
.stat{background:#141418;border:1px solid #333;border-radius:6px;padding:12px 18px;min-width:120px}
.stat-val{font-size:22px;font-weight:700;color:#c9a84c}
.stat-label{font-size:9px;color:#666;text-transform:uppercase;letter-spacing:1px;margin-top:4px}
h2{font-size:12px;color:#c9a84c;letter-spacing:1.5px;text-transform:uppercase;margin:20px 0 10px;border-bottom:1px solid #282828;padding-bottom:6px}
table{width:100%;border-collapse:collapse;margin-bottom:24px}
th{text-align:left;font-size:9px;color:#666;text-transform:uppercase;letter-spacing:1px;padding:8px 12px;border-bottom:2px solid #333;font-weight:700}
td{padding:8px 12px;border-bottom:1px solid #1e1e1e;font-size:12px}
tr:hover td{background:rgba(201,168,76,0.04)}
.tag{display:inline-block;padding:2px 8px;border-radius:3px;font-size:9px;font-weight:700;letter-spacing:0.5px}
.tag-on{background:rgba(93,220,120,0.12);color:#5ddc78;border:1px solid rgba(93,220,120,0.3)}
.tag-off{background:rgba(255,82,82,0.08);color:#ff5252;border:1px solid rgba(255,82,82,0.2)}
.tag-plan{background:rgba(201,168,76,0.1);color:#c9a84c;border:1px solid rgba(201,168,76,0.3)}
.tag-admin{background:rgba(201,168,76,0.2);color:#e8c84c;border:1px solid rgba(201,168,76,0.5)}
.sid{font-size:10px;color:#555;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.back{display:inline-block;margin-top:16px;padding:8px 16px;background:linear-gradient(135deg,#85783c,#c9a84c);border-radius:4px;color:#0c0c0e;font-weight:700;font-size:10px;letter-spacing:1px;text-decoration:none;text-transform:uppercase}
.back:hover{filter:brightness(1.15)}
.close-btn{position:fixed;top:16px;right:16px;width:32px;height:32px;border:1px solid #444;border-radius:50%;background:#1a1a1a;color:#aaa;font-size:16px;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:all 0.2s;text-decoration:none;z-index:100}
.close-btn:hover{background:#252525;color:#e8e4dc;border-color:#666}
.actions{margin-bottom:20px;display:flex;gap:8px}
.btn{padding:6px 14px;border:1px solid #444;border-radius:4px;background:#1a1a1a;color:#aaa;font-family:'DM Mono',monospace;font-size:10px;font-weight:700;cursor:pointer;text-decoration:none;letter-spacing:0.5px;transition:all 0.2s}
.btn:hover{background:#252525;color:#e8e4dc;border-color:#666}
.btn-danger{border-color:rgba(173,90,77,0.4);color:#ad5a4d}
.btn-danger:hover{background:rgba(173,90,77,0.1);color:#e05040;border-color:#ad5a4d}
.btn-sm{padding:3px 8px;font-size:9px}
.av-circle{width:22px;height:22px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:9px;font-weight:700;color:#0c0c0e;vertical-align:middle;overflow:hidden;border:1px solid #333}
.av-circle img{width:100%;height:100%;object-fit:cover;transition:filter 0.4s ease,transform 0.4s ease}
.av-circle img.prog-loading{filter:blur(2px);transform:scale(1.08)}
.av-circle img.prog-loaded{filter:blur(0);transform:scale(1)}
.av-none{color:#555;font-size:9px}
dialog{background:#141418;color:#e8e4dc;border:1px solid #444;border-radius:8px;padding:20px;font-family:'DM Mono',monospace;max-width:360px}
dialog::backdrop{background:rgba(0,0,0,0.7)}
dialog h3{font-size:13px;color:#e03030;margin-bottom:8px}
dialog p{font-size:11px;color:#aaa;margin-bottom:16px;line-height:1.5}
dialog .dialog-actions{display:flex;gap:8px;justify-content:flex-end}
dialog .user-detail{color:#c9a84c;font-weight:700}
.charts-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}
.chart-card{background:#141418;border:1px solid #282828;border-radius:6px;padding:16px}
.chart-card h3{font-size:10px;color:#c9a84c;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;font-weight:700}
.chart-card canvas{width:100%!important;max-height:220px}
.loading{color:#555;font-size:10px;letter-spacing:1px;text-transform:uppercase;animation:pulse 1.5s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:0.4}50%{opacity:1}}
@media(max-width:768px){.charts-grid{grid-template-columns:1fr}}
.anomaly-list{display:flex;flex-direction:column;gap:8px}
.anomaly-card{background:#141418;border-radius:6px;padding:12px 16px;border-left:3px solid #555;font-size:11px;line-height:1.5}
.anomaly-card.critical{border-left-color:#e03030;background:rgba(224,48,48,0.06)}
.anomaly-card.warning{border-left-color:#e8a832;background:rgba(232,168,50,0.06)}
.anomaly-card.info{border-left-color:#3b82f6;background:rgba(59,130,246,0.06)}
.anomaly-card .anomaly-type{font-size:9px;text-transform:uppercase;letter-spacing:1px;font-weight:700;margin-bottom:4px}
.anomaly-card.critical .anomaly-type{color:#e03030}
.anomaly-card.warning .anomaly-type{color:#e8a832}
.anomaly-card.info .anomaly-type{color:#3b82f6}
.anomaly-card .anomaly-msg{color:#bbb}
.anomaly-card .anomaly-time{font-size:9px;color:#555;margin-top:4px}
.anomaly-ok{color:#3ddc84;font-size:11px;padding:12px;background:#141418;border-radius:6px;border-left:3px solid #3ddc84}
#admin-lang-toggle{position:fixed;top:16px;right:56px;z-index:100;display:flex;gap:0;border:1px solid #c9a84c;border-radius:4px;overflow:hidden;background:rgba(12,12,14,0.95)}
#admin-lang-toggle button{background:transparent;color:#666;border:none;padding:3px 8px;font-family:'DM Mono',monospace;font-size:10px;font-weight:700;cursor:pointer;transition:all 0.2s}
#admin-lang-toggle button.active{background:#c9a84c;color:#0c0c0e}
#admin-lang-toggle button:not(.active):hover{color:#e8e4dc}
.toast-bar{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:9999;display:flex;flex-direction:column;gap:8px;align-items:center;pointer-events:none}
.undo-toast{pointer-events:auto;background:#1a1a1a;border:1px solid #c9a84c;border-radius:6px;padding:10px 16px;display:flex;align-items:center;gap:12px;font-size:11px;color:#e8e4dc;box-shadow:0 8px 30px rgba(0,0,0,0.6);animation:toastIn 0.3s ease}
.undo-toast .ut-msg{flex:1;white-space:nowrap}
.undo-toast .ut-btn{background:#c9a84c;color:#0c0c0e;border:none;border-radius:3px;padding:4px 12px;font-family:'DM Mono',monospace;font-size:10px;font-weight:700;cursor:pointer;letter-spacing:0.5px;text-transform:uppercase}
.undo-toast .ut-btn:hover{filter:brightness(1.15)}
.undo-toast .ut-bar{position:absolute;bottom:0;left:0;height:2px;background:#c9a84c;border-radius:0 0 6px 6px;animation:undoBar linear forwards}
@keyframes toastIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
@keyframes toastOut{to{opacity:0;transform:translateY(20px)}}
@keyframes undoBar{from{width:100%}to{width:0%}}
.status-toast{pointer-events:auto;border-radius:6px;padding:8px 16px;font-size:10px;font-weight:700;letter-spacing:0.5px;animation:toastIn 0.3s ease}
.status-toast.success{background:rgba(76,175,104,0.15);border:1px solid rgba(76,175,104,0.4);color:#4caf68}
.status-toast.error{background:rgba(224,80,64,0.15);border:1px solid rgba(224,80,64,0.4);color:#e05040}
.status-toast.info{background:rgba(100,149,237,0.15);border:1px solid rgba(100,149,237,0.4);color:#6495ed}
.backup-row .btn{opacity:0.6;transition:opacity 0.2s}
.backup-row:hover .btn{opacity:1}
.backup-tier{font-size:9px;padding:2px 6px;border-radius:3px;font-weight:700;letter-spacing:0.5px}
.backup-tier.hourly{background:rgba(59,130,246,0.12);color:#60a5fa;border:1px solid rgba(59,130,246,0.3)}
.backup-tier.daily{background:rgba(93,220,120,0.12);color:#5ddc78;border:1px solid rgba(93,220,120,0.3)}
.backup-tier.manual{background:rgba(201,168,76,0.1);color:#c9a84c;border:1px solid rgba(201,168,76,0.3)}
.backup-tier.pre-pitr{background:rgba(168,85,247,0.12);color:#a855f7;border:1px solid rgba(168,85,247,0.3)}
.verify-pass{color:#5ddc78;font-size:10px;font-weight:700}
.verify-fail{color:#e05040;font-size:10px;font-weight:700}
.verify-pending{color:#555;font-size:10px}
.pitr-box{background:#141418;border:1px solid #282828;border-radius:6px;padding:12px 16px;font-size:11px;display:flex;gap:24px;flex-wrap:wrap}
.pitr-box .pitr-item{display:flex;flex-direction:column;gap:2px}
.pitr-box .pitr-label{font-size:9px;color:#666;text-transform:uppercase;letter-spacing:1px}
.pitr-box .pitr-val{color:#c9a84c;font-weight:700;font-size:12px}
.wal-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}
.wal-card{background:#141418;border:1px solid #282828;border-radius:6px;padding:10px 14px}
.wal-card .wal-val{font-size:18px;font-weight:700;color:#c9a84c}
.wal-card .wal-label{font-size:9px;color:#666;text-transform:uppercase;letter-spacing:1px;margin-top:2px}
.wal-card.healthy .wal-val{color:#5ddc78}
.wal-card.warn .wal-val{color:#e8a832}
.wal-card.danger .wal-val{color:#e05040}
.wal-log-entry{background:#141418;border:1px solid #282828;border-radius:4px;padding:8px 12px;margin-bottom:6px;font-size:10px;display:flex;justify-content:space-between;align-items:center}
.wal-log-entry .wal-log-mode{font-weight:700;color:#c9a84c;text-transform:uppercase;letter-spacing:1px}
.wal-log-entry .wal-log-detail{color:#888}
.wal-log-entry .wal-log-time{color:#555;font-size:9px}
#admin-queue-bar{display:none;position:fixed;bottom:0;left:0;right:0;z-index:9998;background:#141418;border-top:1px solid rgba(201,168,76,0.3);padding:8px 16px;font-family:'DM Mono',monospace;font-size:10px;color:#c9a84c;letter-spacing:0.5px}
#admin-queue-bar.visible{display:flex;align-items:center;gap:12px}
#admin-queue-bar .aq-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
#admin-queue-bar .aq-dot.pending{background:#c9a84c;animation:pulse 1.5s ease-in-out infinite}
#admin-queue-bar .aq-dot.syncing{background:#6495ed;animation:pulse 0.6s ease-in-out infinite}
#admin-queue-bar .aq-dot.done{background:#5ddc78}
#admin-queue-bar .aq-dot.error{background:#e05040}
#admin-queue-bar .aq-label{flex:1}
#admin-queue-bar .aq-count{background:rgba(201,168,76,0.2);border:1px solid rgba(201,168,76,0.4);border-radius:10px;padding:1px 8px;font-weight:700;font-size:9px;min-width:18px;text-align:center}
#admin-queue-bar .aq-btn{background:rgba(201,168,76,0.15);border:1px solid rgba(201,168,76,0.4);color:#c9a84c;border-radius:3px;padding:3px 10px;font-family:'DM Mono',monospace;font-size:9px;font-weight:700;cursor:pointer;letter-spacing:0.5px}
#admin-queue-bar .aq-btn:hover{background:rgba(201,168,76,0.3)}
</style>
</head>
<body>
<nav id="admin-lang-toggle"><button id="admin-btn-en" class="active">EN</button><button id="admin-btn-pt">PT</button></nav>
<a class="close-btn" href="/" title="Back to App">&times;</a>

<main>
<header>
<h1>&#9881; <span data-i18n="title">Admin Panel</span></h1>
<p class="subtitle"><span data-i18n="subtitle">Oil Benchmarks &mdash; Database Inspector</span></p>
<aside class="warn">&#9888; <span data-i18n="warn">This route is for development only. Remove before deploying to production.</span></aside>
</header>

<div class="stats" id="stats-bar"><span class="loading" data-i18n="loading">Loading stats...</span></div>

<nav class="actions" aria-label="Admin actions">
  <a class="btn" href="/admin" title="Refresh">&#8635; <span data-i18n="refresh">Refresh</span></a>
  <a class="btn" href="/admin/report.pdf" title="Download PDF report">&#128196; <span data-i18n="exportPdf">Export PDF</span></a>
  <a class="btn" href="/api/admin/export?format=json" title="Export all data as JSON" download>&#128230; <span data-i18n="exportJson">Export JSON</span></a>
  <a class="btn" href="/api/admin/export?format=csv" title="Export all data as CSV" download>&#128203; <span data-i18n="exportCsv">Export CSV</span></a>
  <button class="btn btn-danger" id="admin-clear-sessions" title="Clear all sessions">&#10005; <span data-i18n="clearSessions">Clear Sessions</span></button>
</nav>

<section aria-labelledby="analytics-dash-heading">
<h2 id="analytics-dash-heading">&#9776; <span data-i18n="analyticsDash">Analytics Dashboard</span></h2>
<div class="charts-grid">
  <article class="chart-card"><h3 data-i18n="regTrends">Registration Trends (Daily)</h3><canvas id="regChart"></canvas></article>
  <article class="chart-card"><h3 data-i18n="cumUsers">Cumulative Users Over Time</h3><canvas id="cumChart"></canvas></article>
  <article class="chart-card"><h3 data-i18n="regWeek">Registrations by Week</h3><canvas id="weekChart"></canvas></article>
  <article class="chart-card"><h3 data-i18n="features">Most Used Features</h3><canvas id="featureChart"></canvas></article>
  <article class="chart-card"><h3 data-i18n="planDist">Plan Distribution</h3><canvas id="planChart"></canvas></article>
  <article class="chart-card"><h3 data-i18n="activeSessions">Active Sessions</h3><canvas id="sessionChart"></canvas></article>
  <article class="chart-card"><h3 data-i18n="topLogins">Top Users by Logins</h3><canvas id="loginActivityChart"></canvas></article>
  <article class="chart-card"><h3 data-i18n="loginDaily">Login Activity (Daily)</h3><canvas id="recentLoginsChart"></canvas></article>
</div>
</section>

<section aria-labelledby="site-analytics-heading">
<h2 id="site-analytics-heading">&#128202; <span data-i18n="siteAnalytics">Site Analytics</span></h2>
<div class="charts-grid">
  <article class="chart-card"><h3 data-i18n="pvDaily">Page Views &amp; Visitors (Daily)</h3><canvas id="viewsChart"></canvas></article>
  <article class="chart-card"><h3 data-i18n="browsers">Browser Distribution</h3><canvas id="browserChart"></canvas></article>
  <article class="chart-card"><h3 data-i18n="devices">Device Types</h3><canvas id="deviceChart"></canvas></article>
  <article class="chart-card"><h3 data-i18n="featureEvents">Feature Events</h3><canvas id="eventsChart"></canvas></article>
</div>
<div id="referrers-container"></div>
</section>

<section aria-labelledby="anomalies-heading">
<h2 id="anomalies-heading">&#9888; <span data-i18n="anomaliesH">Traffic Anomaly Detection</span></h2>
<div id="anomalies-container"><span class="loading" data-i18n="loadingAnomalies">Scanning for anomalies...</span></div>
</section>

<section aria-labelledby="backups-heading">
<h2 id="backups-heading">&#128190; <span data-i18n="backupsH">Backup &amp; Restore</span></h2>
<nav class="actions" style="margin-bottom:12px">
  <button class="btn" id="btn-create-backup" title="Create a new manual backup">&#43; <span data-i18n="createBackup">Create Backup</span></button>
  <button class="btn" id="btn-verify-all" title="Verify all backups">&#9989; <span data-i18n="verifyAll">Verify All</span></button>
  <button class="btn" id="btn-gfs-prune" title="Run GFS retention prune">&#9986; <span data-i18n="gfsPrune">GFS Prune</span></button>
</nav>
<div id="pitr-range" style="margin-bottom:12px"></div>
<div id="backups-table"><span class="loading" data-i18n="loadingBackups">Loading backups...</span></div>
</section>

<dialog id="restoreDialog">
  <h3>&#9888; <span data-i18n="restoreTitle">Restore Database</span></h3>
  <p><span data-i18n="restoreWarn">This will overwrite the current database with backup</span> <span class="user-detail" id="restore-file-info"></span>. <span data-i18n="restoreRestart">The server must be restarted after restore.</span></p>
  <div class="dialog-actions">
    <button class="btn" onclick="document.getElementById('restoreDialog').close()" data-i18n="cancel">Cancel</button>
    <button class="btn btn-danger" id="restore-confirm-btn">&#9888; <span data-i18n="restoreBtn">Restore Now</span></button>
  </div>
</dialog>

<section aria-labelledby="wal-heading">
<h2 id="wal-heading">&#9881; <span data-i18n="walH">WAL Checkpoint Management</span></h2>
<div id="wal-status"><span class="loading" data-i18n="loadingWal">Loading WAL status...</span></div>
<nav class="actions" style="margin-top:12px">
  <button class="btn" id="btn-wal-refresh" title="Refresh WAL status">&#8635; <span data-i18n="walRefresh">Refresh</span></button>
  <button class="btn" id="btn-wal-passive" title="PASSIVE: checkpoint without blocking writers">PASSIVE</button>
  <button class="btn" id="btn-wal-full" title="FULL: checkpoint and wait for readers to finish">FULL</button>
  <button class="btn" id="btn-wal-restart" title="RESTART: checkpoint, wait for readers, then restart WAL">RESTART</button>
  <button class="btn btn-danger" id="btn-wal-truncate" title="TRUNCATE: checkpoint and reset WAL file to zero size">TRUNCATE</button>
  <button class="btn" id="btn-integrity-check" title="Run PRAGMA integrity_check on the database">&#128270; <span data-i18n="integrityCheck">Integrity Check</span></button>
</nav>
<div id="wal-checkpoint-log" style="margin-top:10px"></div>
</section>

<section aria-labelledby="users-heading">
<h2 id="users-heading" data-i18n="usersH">Users</h2>
<div id="users-table"><span class="loading" data-i18n="loadingUsers">Loading users...</span></div>
<nav id="users-pagination" aria-label="Users pagination"></nav>
</section>

<section aria-labelledby="settings-heading">
<h2 id="settings-heading" data-i18n="settingsH">User Settings</h2>
<div id="settings-table"><span class="loading" data-i18n="loadingSettings">Loading settings...</span></div>
<nav id="settings-pagination" aria-label="Settings pagination"></nav>
</section>

<section aria-labelledby="activity-heading">
<h2 id="activity-heading">&#128337; <span data-i18n="activityH">User Activity Log</span></h2>
<div id="activity-table"><span class="loading" data-i18n="loadingActivity">Loading activity...</span></div>
</section>

<section aria-labelledby="sessions-heading">
<h2 id="sessions-heading" data-i18n="sessionsH">Sessions</h2>
<div id="sessions-table"><span class="loading" data-i18n="loadingSessions">Loading sessions...</span></div>
<nav id="sessions-pagination" aria-label="Sessions pagination"></nav>
</section>

<section aria-labelledby="tables-heading">
<h2 id="tables-heading" data-i18n="tablesH">Tables</h2>
<div id="tables-list"><span class="loading" data-i18n="loadingTables">Loading...</span></div>
</section>

<footer>
<a class="back" href="/">&#8592; <span data-i18n="backToApp">Back to App</span></a>
</footer>
</main>

<div id="admin-queue-bar">
  <span class="aq-dot pending" id="aq-dot"></span>
  <span class="aq-label" id="aq-label">Queued actions pending</span>
  <span class="aq-count" id="aq-count">0</span>
  <button class="aq-btn" id="aq-sync-btn" title="Sync now">SYNC NOW</button>
  <button class="aq-btn" id="aq-clear-btn" title="Clear queue" style="color:#e05040;border-color:rgba(224,80,64,0.4)">CLEAR</button>
</div>

<dialog id="deleteDialog">
  <h3>&#9888; <span data-i18n="deleteUser">Delete User</span></h3>
  <p><span data-i18n="deleteConfirm">Are you sure you want to permanently delete</span> <span class="user-detail" id="del-user-info"></span>? <span data-i18n="deleteWarn">This will remove all their data including settings and sessions.</span></p>
  <div class="dialog-actions">
    <button class="btn" onclick="document.getElementById('deleteDialog').close()" data-i18n="cancel">Cancel</button>
    <a class="btn btn-danger" id="del-confirm-link" href="#">&#10005; <span data-i18n="deleteBtn">Delete</span></a>
  </div>
</dialog>

<script nonce="${nonce}" src="/admin/vendor/chart.umd.min.js"><\/script>
<script nonce="${nonce}">
// ── Translation dictionary ───────────────────────────────────────
var T = {
  en: {
    title:'Admin Panel', subtitle:'Oil Benchmarks &mdash; Database Inspector',
    warn:'This route is for development only. Remove before deploying to production.',
    loading:'Loading stats...', refresh:'Refresh', exportPdf:'Export PDF', clearSessions:'Clear Sessions',
    analyticsDash:'Analytics Dashboard', regTrends:'Registration Trends (Daily)',
    cumUsers:'Cumulative Users Over Time', regWeek:'Registrations by Week',
    features:'Most Used Features', planDist:'Plan Distribution', activeSessions:'Active Sessions',
    topLogins:'Top Users by Logins', loginDaily:'Login Activity (Daily)',
    siteAnalytics:'Site Analytics', pvDaily:'Page Views &amp; Visitors (Daily)',
    browsers:'Browser Distribution', devices:'Device Types', featureEvents:'Feature Events',
    usersH:'Users', settingsH:'User Settings', activityH:'User Activity Log', anomaliesH:'Traffic Anomaly Detection', loadingAnomalies:'Scanning for anomalies...',
    sessionsH:'Sessions', tablesH:'Tables', backToApp:'Back to App',
    deleteUser:'Delete User', deleteConfirm:'Are you sure you want to permanently delete',
    deleteWarn:'This will remove all their data including settings and sessions.',
    cancel:'Cancel', deleteBtn:'Delete',
    loadingUsers:'Loading users...', loadingSettings:'Loading settings...',
    loadingActivity:'Loading activity...', loadingSessions:'Loading sessions...',
    loadingTables:'Loading...',
    statUsers:'Users', statSessions:'Active Sessions', statTables:'Tables', statDbSize:'DB Size',
    thTableName:'Table Name',
    thId:'ID', thAvatar:'Avatar', thName:'Name', thEmail:'Email', thPlan:'Plan',
    thAvatarBg:'Avatar BG', thCreated:'Created', thLastLogin:'Last Login',
    thLoginCount:'Login Count', thLastSettings:'Last Settings Change', thAccountAge:'Account Age',
    thAlerts:'Price Alerts', thNewsletter:'Newsletter', thDarkMode:'Dark Mode',
    thSid:'SID', thUser:'User', thIpHash:'IP (hash)', thUserAgent:'User Agent',
    thLastSeen:'Last Seen', thExpires:'Expires', thStatus:'Status',
    never:'never', today:'today', anonymous:'anonymous', protected:'protected',
    active:'active', expired:'expired',
    saLast30:'last 30 days', saViews:'views', saVisitors:'unique visitors',
    topReferrers:'Top Referrers', thSource:'Source', thVisits:'Visits',
    activeNow:'Active Now', deleteCol:'Delete',
    logins:'Logins',
    prev:'Prev', next:'Next', page:'Page', total:'total',
    backupsH:'Backup & Restore', createBackup:'Create Backup', verifyAll:'Verify All',
    gfsPrune:'GFS Prune', loadingBackups:'Loading backups...',
    restoreTitle:'Restore Database',
    restoreWarn:'This will overwrite the current database with backup',
    restoreRestart:'The server must be restarted after restore.',
    restoreBtn:'Restore Now',
    bkThFile:'Filename', bkThTier:'Tier', bkThSize:'Size', bkThDate:'Created',
    bkThVerify:'Integrity', bkThActions:'Actions',
    pitrEarliest:'Earliest Recovery', pitrLatest:'Latest Recovery',
    pitrBackups:'Total Backups', pitrChangelog:'Changelog Entries',
    walH:'WAL Checkpoint Management', loadingWal:'Loading WAL status...',
    walRefresh:'Refresh', integrityCheck:'Integrity Check',
    walJournal:'Journal Mode', walFileSize:'WAL File', walDbSize:'DB Size',
    walAutoCP:'Auto-Checkpoint', walPageSize:'Page Size', walPages:'Pages',
    walFreelist:'Freelist', walBusyTimeout:'Busy Timeout'
  },
  pt: {
    title:'Painel Admin', subtitle:'Oil Benchmarks &mdash; Inspetor de Base de Dados',
    warn:'Esta rota destina-se apenas ao desenvolvimento. Remover antes de publicar em produ\\u00e7\\u00e3o.',
    loading:'A carregar estat\\u00edsticas...', refresh:'Atualizar', exportPdf:'Exportar PDF', clearSessions:'Limpar Sess\\u00f5es',
    analyticsDash:'Painel Anal\\u00edtico', regTrends:'Tend\\u00eancias de Registo (Di\\u00e1rio)',
    cumUsers:'Utilizadores Acumulados', regWeek:'Registos por Semana',
    features:'Funcionalidades Mais Usadas', planDist:'Distribui\\u00e7\\u00e3o de Planos', activeSessions:'Sess\\u00f5es Ativas',
    topLogins:'Utilizadores com Mais Logins', loginDaily:'Atividade de Login (Di\\u00e1rio)',
    siteAnalytics:'Anal\\u00edtica do Site', pvDaily:'Visualiza\\u00e7\\u00f5es e Visitantes (Di\\u00e1rio)',
    browsers:'Distribui\\u00e7\\u00e3o de Browsers', devices:'Tipos de Dispositivo', featureEvents:'Eventos de Funcionalidades',
    usersH:'Utilizadores', settingsH:'Defini\\u00e7\\u00f5es', activityH:'Registo de Atividade',
    sessionsH:'Sess\\u00f5es', tablesH:'Tabelas', backToApp:'Voltar \\u00e0 App',
    deleteUser:'Eliminar Utilizador', deleteConfirm:'Tem a certeza que deseja eliminar permanentemente',
    deleteWarn:'Isto remover\\u00e1 todos os dados incluindo defini\\u00e7\\u00f5es e sess\\u00f5es.',
    cancel:'Cancelar', deleteBtn:'Eliminar',
    loadingUsers:'A carregar utilizadores...', loadingSettings:'A carregar defini\\u00e7\\u00f5es...',
    loadingActivity:'A carregar atividade...', loadingSessions:'A carregar sess\\u00f5es...',
    loadingTables:'A carregar...',
    statUsers:'Utilizadores', statSessions:'Sess\\u00f5es Ativas', statTables:'Tabelas', statDbSize:'Tamanho BD',
    thTableName:'Nome da Tabela',
    thId:'ID', thAvatar:'Avatar', thName:'Nome', thEmail:'Email', thPlan:'Plano',
    thAvatarBg:'Fundo Avatar', thCreated:'Criado', thLastLogin:'\\u00daltimo Login',
    thLoginCount:'N\\u00ba Logins', thLastSettings:'\\u00dalt. Altera\\u00e7\\u00e3o Def.', thAccountAge:'Idade da Conta',
    thAlerts:'Alertas de Pre\\u00e7o', thNewsletter:'Newsletter', thDarkMode:'Modo Escuro',
    thSid:'SID', thUser:'Utilizador', thIpHash:'IP (hash)', thUserAgent:'Agente',
    thLastSeen:'\\u00daltima Vis.', thExpires:'Expira', thStatus:'Estado',
    never:'nunca', today:'hoje', anonymous:'an\\u00f3nimo', protected:'protegido',
    active:'ativo', expired:'expirado',
    saLast30:'\\u00faltimos 30 dias', saViews:'visualiza\\u00e7\\u00f5es', saVisitors:'visitantes \\u00fanicos',
    topReferrers:'Principais Refer\\u00eancias', thSource:'Fonte', thVisits:'Visitas',
    activeNow:'Ativas Agora', deleteCol:'Eliminar',
    logins:'Logins',
    prev:'Ant.', next:'Seg.', page:'P\\u00e1gina', total:'total',
    backupsH:'C\\u00f3pias de Seguran\\u00e7a', createBackup:'Criar C\\u00f3pia', verifyAll:'Verificar Todas',
    gfsPrune:'Limpeza GFS', loadingBackups:'A carregar c\\u00f3pias...',
    restoreTitle:'Restaurar Base de Dados',
    restoreWarn:'Isto ir\\u00e1 substituir a base de dados atual pela c\\u00f3pia',
    restoreRestart:'O servidor deve ser reiniciado ap\\u00f3s a restaura\\u00e7\\u00e3o.',
    restoreBtn:'Restaurar Agora',
    bkThFile:'Ficheiro', bkThTier:'Tier', bkThSize:'Tamanho', bkThDate:'Criado',
    bkThVerify:'Integridade', bkThActions:'A\\u00e7\\u00f5es',
    pitrEarliest:'Recupera\\u00e7\\u00e3o Mais Antiga', pitrLatest:'Recupera\\u00e7\\u00e3o Mais Recente',
    pitrBackups:'Total de C\\u00f3pias', pitrChangelog:'Entradas Changelog',
    walH:'Gest\\u00e3o de Checkpoint WAL', loadingWal:'A carregar estado WAL...',
    walRefresh:'Atualizar', integrityCheck:'Verifica\\u00e7\\u00e3o de Integridade',
    walJournal:'Modo Journal', walFileSize:'Ficheiro WAL', walDbSize:'Tamanho BD',
    walAutoCP:'Auto-Checkpoint', walPageSize:'Tamanho P\\u00e1g.', walPages:'P\\u00e1ginas',
    walFreelist:'Livres', walBusyTimeout:'Timeout Ocupado'
  }
};
var currentLang = localStorage.getItem('adminLang') || 'en';
function t(key) { return T[currentLang][key] || T.en[key] || key; }

// ── AdminCache — persist last admin state for offline viewing ────
// Stores API responses in localStorage so the admin panel can render
// its last-known state when the network is unavailable.
var AdminCache = (function() {
  var PREFIX = 'admin_cache_';
  function get(key) {
    try {
      var raw = localStorage.getItem(PREFIX + key);
      if (!raw) return null;
      return JSON.parse(raw);
    } catch(e) { return null; }
  }
  function set(key, data) {
    try {
      localStorage.setItem(PREFIX + key, JSON.stringify({ ts: Date.now(), data: data }));
    } catch(e) { /* quota exceeded — skip */ }
  }
  function getAge(key) {
    try {
      var raw = localStorage.getItem(PREFIX + key);
      if (!raw) return null;
      var entry = JSON.parse(raw);
      return Date.now() - entry.ts;
    } catch(e) { return null; }
  }
  function getData(key) {
    var entry = get(key);
    return entry ? entry.data : null;
  }
  // Wrapped fetch: tries network, caches on success, falls back to cache on failure
  function cachedFetch(url, cacheKey) {
    return fetch(url).then(function(r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json().then(function(data) {
        set(cacheKey, data);
        hideOfflineBanner();
        return { data: data, fromCache: false };
      });
    }).catch(function(err) {
      var cached = getData(cacheKey);
      if (cached) {
        showOfflineBanner(cacheKey);
        return { data: cached, fromCache: true };
      }
      throw err;
    });
  }
  return { get: get, set: set, getAge: getAge, getData: getData, cachedFetch: cachedFetch };
})();

var _offlineBannerVisible = false;
function showOfflineBanner(key) {
  if (_offlineBannerVisible) return;
  _offlineBannerVisible = true;
  var age = AdminCache.getAge(key);
  var ageStr = '';
  if (age) {
    var m = Math.floor(age / 60000);
    if (m < 1) ageStr = 'just now';
    else if (m < 60) ageStr = m + 'm ago';
    else { var h = Math.floor(m / 60); ageStr = h < 24 ? h + 'h ago' : Math.floor(h/24) + 'd ago'; }
  }
  var el = document.getElementById('admin-offline-banner');
  if (!el) {
    el = document.createElement('div');
    el.id = 'admin-offline-banner';
    el.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9999;background:rgba(201,168,76,0.15);border-bottom:1px solid rgba(201,168,76,0.3);color:#c9a84c;font-size:10px;text-align:center;padding:6px 12px;font-family:DM Mono,monospace;letter-spacing:0.5px;display:flex;align-items:center;justify-content:center;gap:8px;';
    document.body.prepend(el);
  }
  el.innerHTML = '&#9888; OFFLINE MODE &mdash; showing cached data' + (ageStr ? ' (last updated ' + ageStr + ')' : '') + ' <button onclick="this.parentElement.remove();window._offlineBannerVisible=false" style="background:none;border:1px solid rgba(201,168,76,0.4);color:#c9a84c;border-radius:3px;padding:1px 6px;font-size:9px;cursor:pointer;font-family:DM Mono,monospace">&times;</button>';
  el.style.display = 'flex';
  // Disable mutation buttons when offline
  document.querySelectorAll('#admin-clear-sessions,.admin-del-btn,#btn-create-backup,#btn-gfs-prune,.backup-restore-btn').forEach(function(b) { b.disabled = true; b.style.opacity = '0.3'; });
}
function hideOfflineBanner() {
  _offlineBannerVisible = false;
  var el = document.getElementById('admin-offline-banner');
  if (el) el.style.display = 'none';
  document.querySelectorAll('#admin-clear-sessions,.admin-del-btn,#btn-create-backup,#btn-gfs-prune,.backup-restore-btn').forEach(function(b) { b.disabled = false; b.style.opacity = ''; });
}

// ── AdminActionQueue — queue mutations offline, replay on reconnect ──
var AdminActionQueue = (function() {
  var QUEUE_KEY = 'admin_action_queue';
  var _syncing = false;

  function getQueue() {
    try { return JSON.parse(localStorage.getItem(QUEUE_KEY)) || []; }
    catch(e) { return []; }
  }
  function saveQueue(q) {
    try { localStorage.setItem(QUEUE_KEY, JSON.stringify(q)); }
    catch(e) {}
    updateQueueUI();
  }
  function enqueue(entry) {
    var q = getQueue();
    q.push({
      id: Date.now() + '_' + Math.random().toString(36).slice(2,8),
      url: entry.url,
      method: entry.method || 'POST',
      headers: entry.headers || { 'Content-Type': 'application/json' },
      body: entry.body || null,
      label: entry.label || entry.url,
      ts: Date.now()
    });
    saveQueue(q);
    showAdminToast('Action queued — will sync when online: ' + (entry.label || ''), 'info');
  }

  function updateQueueUI() {
    var q = getQueue();
    var bar = document.getElementById('admin-queue-bar');
    var dot = document.getElementById('aq-dot');
    var label = document.getElementById('aq-label');
    var count = document.getElementById('aq-count');
    if (!bar) return;
    if (q.length === 0 && !_syncing) {
      bar.classList.remove('visible');
      return;
    }
    bar.classList.add('visible');
    count.textContent = q.length;
    if (_syncing) {
      dot.className = 'aq-dot syncing';
      label.textContent = 'Syncing queued actions...';
    } else {
      dot.className = 'aq-dot pending';
      label.textContent = q.length + ' action' + (q.length !== 1 ? 's' : '') + ' queued — waiting for connection';
    }
  }

  function flush() {
    var q = getQueue();
    if (!q.length || _syncing) return;
    if (!navigator.onLine) return;
    _syncing = true;
    saveQueue(q); // triggers UI update to show syncing state
    var failed = [];
    var succeeded = 0;
    var i = 0;

    function next() {
      if (i >= q.length) {
        _syncing = false;
        if (failed.length) {
          saveQueue(failed);
          showAdminToast(succeeded + ' synced, ' + failed.length + ' failed — will retry', 'error');
        } else {
          saveQueue([]);
          // Show success
          var bar = document.getElementById('admin-queue-bar');
          var dot = document.getElementById('aq-dot');
          var label = document.getElementById('aq-label');
          if (bar) {
            dot.className = 'aq-dot done';
            label.textContent = 'All ' + succeeded + ' action' + (succeeded !== 1 ? 's' : '') + ' synced successfully';
            setTimeout(function() { bar.classList.remove('visible'); }, 3000);
          }
          showAdminToast('All queued actions synced successfully', 'success');
          // Refresh all admin data
          refreshAllAdminData();
        }
        return;
      }
      var entry = q[i++];
      var opts = {
        method: entry.method,
        headers: entry.headers,
        credentials: 'same-origin'
      };
      if (entry.body) opts.body = entry.body;

      fetch(entry.url, opts).then(function(r) {
        if (r.ok || (r.status >= 200 && r.status < 500)) {
          succeeded++;
        } else {
          failed.push(entry);
        }
        next();
      }).catch(function() {
        failed.push(entry);
        next();
      });
    }
    next();
  }

  function clearQueue() {
    saveQueue([]);
    showAdminToast('Action queue cleared', 'info');
  }

  // Auto-flush on reconnect
  window.addEventListener('online', function() {
    setTimeout(flush, 1000);
  });
  // Flush on load if queue has items
  if (navigator.onLine) { setTimeout(flush, 2000); }

  // Bind queue bar buttons
  document.getElementById('aq-sync-btn').addEventListener('click', function() { flush(); });
  document.getElementById('aq-clear-btn').addEventListener('click', function() { clearQueue(); });

  // Initial UI update
  updateQueueUI();

  return { enqueue: enqueue, flush: flush, getQueue: getQueue, clearQueue: clearQueue };
})();

// Centralized admin action executor: online → fetch, offline → queue
function adminAction(url, options, label, onSuccess, onError) {
  var opts = Object.assign({ method: 'POST', headers: { 'Content-Type': 'application/json' } }, options || {});
  if (navigator.onLine) {
    return fetch(url, opts).then(function(r) { return r.json(); }).then(function(d) {
      if (onSuccess) onSuccess(d);
    }).catch(function(err) {
      // Network failed mid-request — queue it
      AdminActionQueue.enqueue({ url: url, method: opts.method, headers: opts.headers, body: opts.body, label: label });
      if (onError) onError(err);
    });
  } else {
    AdminActionQueue.enqueue({ url: url, method: opts.method, headers: opts.headers, body: opts.body, label: label });
    return Promise.resolve();
  }
}

function refreshAllAdminData() {
  AdminCache.cachedFetch('/api/admin/summary', 'summary').then(function(res){
    window._adminData.summary = res.data;
    renderSummary(res.data);
    renderTables(res.data.tables);
  }).catch(function(){});
  fetchAdminUsers(window._adminPage.users);
  fetchAdminSettings(window._adminPage.settings);
  fetchAdminSessions(window._adminPage.sessions);
  fetchBackups();
  fetchPitrRange();
  fetchWALStatus();
}

// ── Render helpers (called on fetch AND on language change) ──────
window._adminData = {};

function renderSummary(d) {
  document.getElementById('stats-bar').innerHTML =
    '<div class="stat"><div class="stat-val">'+d.userCount+'</div><div class="stat-label">'+t('statUsers')+'</div></div>'+
    '<div class="stat"><div class="stat-val">'+d.sessionCount+'</div><div class="stat-label">'+t('statSessions')+'</div></div>'+
    '<div class="stat"><div class="stat-val">'+d.tableCount+'</div><div class="stat-label">'+t('statTables')+'</div></div>'+
    '<div class="stat"><div class="stat-val">'+d.dbSizeKB+' KB</div><div class="stat-label">'+t('statDbSize')+'</div></div>';
}
function renderTables(tables) {
  document.getElementById('tables-list').innerHTML =
    '<table><tr><th>'+t('thTableName')+'</th></tr>'+tables.map(function(tbl){return '<tr><td>'+esc(tbl)+'</td></tr>'}).join('')+'</table>';
}
function renderAnalyticsHeading(SA) {
  document.getElementById('site-analytics-heading').innerHTML = '&#128202; '+t('siteAnalytics')+' <span style="font-size:10px;color:#666;font-weight:400">('+t('saLast30')+' &mdash; '+SA.totalViews+' '+t('saViews')+', '+SA.uniqueVisitors+' '+t('saVisitors')+')</span>';
}
function renderReferrers(refs) {
  if(refs.length>0){document.getElementById('referrers-container').innerHTML='<div class="chart-card" style="margin-bottom:24px"><h3>'+t('topReferrers')+'</h3><table style="width:100%"><tr><th style="text-align:left">'+t('thSource')+'</th><th>'+t('thVisits')+'</th></tr>'+refs.map(function(r){return '<tr><td style="font-size:10px;color:#aaa;word-break:break-all">'+esc(r.referrer)+'</td><td style="text-align:center;color:#c9a84c">'+r.count+'</td></tr>'}).join('')+'</table></div>';}
}
// ── Pagination state & helpers ───────────────────────────────────
window._adminPage = { users: 1, settings: 1, sessions: 1 };
function renderPaginationControls(containerId, meta, fetchFn) {
  var el = document.getElementById(containerId);
  if (!el) return;
  if (!meta || meta.totalPages <= 1) { el.innerHTML = ''; return; }
  var html = '<div style="display:flex;align-items:center;justify-content:center;gap:8px;margin:10px 0;font-size:11px;color:#999">';
  html += '<button class="btn btn-sm" style="padding:2px 10px"'+(meta.page<=1?' disabled':'')+' data-pg="'+(meta.page-1)+'">&#9664; '+t('prev')+'</button>';
  html += '<span>'+t('page')+' '+meta.page+' / '+meta.totalPages+' ('+meta.total+' '+t('total')+')</span>';
  html += '<button class="btn btn-sm" style="padding:2px 10px"'+(meta.page>=meta.totalPages?' disabled':'')+' data-pg="'+(meta.page+1)+'">'+t('next')+' &#9654;</button>';
  html += '</div>';
  el.innerHTML = html;
  el.querySelectorAll('button[data-pg]').forEach(function(btn) {
    btn.addEventListener('click', function() { fetchFn(parseInt(btn.dataset.pg, 10)); });
  });
}
function fetchAdminUsers(page) {
  window._adminPage.users = page || 1;
  AdminCache.cachedFetch('/api/admin/users?page='+window._adminPage.users+'&limit=50', 'users_p'+window._adminPage.users).then(function(res){
    var d = res.data;
    window._adminData.users = d.users;
    window._adminData.usersMeta = { page: d.page, limit: d.limit, total: d.total, totalPages: d.totalPages };
    renderUsers(d.users);
    renderPaginationControls('users-pagination', window._adminData.usersMeta, fetchAdminUsers);
  }).catch(function(){});
}
function fetchAdminSettings(page) {
  window._adminPage.settings = page || 1;
  AdminCache.cachedFetch('/api/admin/settings?page='+window._adminPage.settings+'&limit=50', 'settings_p'+window._adminPage.settings).then(function(res){
    var d = res.data;
    window._adminData.settings = d.settings;
    window._adminData.settingsMeta = { page: d.page, limit: d.limit, total: d.total, totalPages: d.totalPages };
    renderSettings(d.settings);
    renderPaginationControls('settings-pagination', window._adminData.settingsMeta, fetchAdminSettings);
  }).catch(function(){});
}
function fetchAdminSessions(page) {
  window._adminPage.sessions = page || 1;
  AdminCache.cachedFetch('/api/admin/sessions?page='+window._adminPage.sessions+'&limit=50', 'sessions_p'+window._adminPage.sessions).then(function(res){
    var d = res.data;
    window._adminData.sessions = d.sessions;
    window._adminData.sessionsMeta = { page: d.page, limit: d.limit, total: d.total, totalPages: d.totalPages };
    renderSessions(d.sessions);
    renderPaginationControls('sessions-pagination', window._adminData.sessionsMeta, fetchAdminSessions);
  }).catch(function(){});
}
function renderUsers(users) {
  var html = '<table><tr><th>'+t('thId')+'</th><th>'+t('thAvatar')+'</th><th>'+t('thName')+'</th><th>'+t('thEmail')+'</th><th>'+t('thPlan')+'</th><th>'+t('thAvatarBg')+'</th><th>'+t('thCreated')+'</th><th></th></tr>';
  users.forEach(function(u){
    var av = u.avatar
      ? '<div class="av-circle" style="background:'+escCss(u.avatar_bg||'linear-gradient(135deg,#85783c,#c9a84c)')+'"><img src="/uploads/'+esc(u.avatar.replace('.webp','_thumb.webp'))+'" class="prog-loading" data-prog-src="/uploads/'+esc(u.avatar)+'" onload="this.classList.remove(\'prog-loading\');this.classList.add(\'prog-loaded\')" onerror="this.classList.remove(\'prog-loading\');this.classList.add(\'prog-loaded\')"></div>'
      : '<div class="av-circle" style="background:'+escCss(u.avatar_bg||'linear-gradient(135deg,#85783c,#c9a84c)') +'">'+esc(u.name?u.name[0].toUpperCase():'?')+'</div>';
    var planClass = u.plan==='Admin'?'tag-admin':'tag-plan';
    var bgLabel = u.avatar_bg ? '<span style="font-size:9px;color:#888">'+esc(u.avatar_bg.replace(/linear-gradient\\(135deg,/,'').replace(/\\)/,''))+'</span>' : '<span class="av-none">default</span>';
    var delBtn = u.email==='siteadmin@oil.com' ? '<span style="font-size:9px;color:#333">'+t('protected')+'</span>' : '<button class="btn btn-danger btn-sm admin-del-btn" data-uid="'+u.id+'" data-uname="'+escAttr(u.name)+'" data-uemail="'+escAttr(u.email)+'">&#10005; '+t('deleteCol')+'</button>';
    html += '<tr><td>'+u.id+'</td><td>'+av+'</td><td>'+esc(u.name)+'</td><td>'+esc(u.email)+'</td><td><span class="tag '+planClass+'">'+esc(u.plan)+'</span></td><td>'+bgLabel+'</td><td>'+esc(u.created_at)+'</td><td>'+delBtn+'</td></tr>';
  });
  html += '</table>';
  document.getElementById('users-table').innerHTML = html;
  // Progressive image loading: upgrade thumb → full-res for visible avatars
  upgradeProgImages(document.getElementById('users-table'));
  // Delegate click on delete buttons — avoids inline onclick with user data
  document.getElementById('users-table').addEventListener('click', function(e) {
    var btn = e.target.closest('.admin-del-btn');
    if (!btn) return;
    confirmDelete(btn.dataset.uid, btn.dataset.uname, btn.dataset.uemail);
  });
  // Activity table
  var act = '<table><tr><th>'+t('thId')+'</th><th>'+t('thName')+'</th><th>'+t('thEmail')+'</th><th>'+t('thLastLogin')+'</th><th>'+t('thLoginCount')+'</th><th>'+t('thLastSettings')+'</th><th>'+t('thAccountAge')+'</th></tr>';
  users.forEach(function(u){
    var ll = u.last_login ? esc(u.last_login) : '<span style="color:#555">'+t('never')+'</span>';
    var lc = u.login_count || 0;
    var ls = u.last_settings_change ? esc(u.last_settings_change) : '<span style="color:#555">'+t('never')+'</span>';
    var days = Math.floor((Date.now()-new Date(u.created_at).getTime())/(86400000));
    var age = days<1?t('today'):days+'d';
    var cc = lc>=10?'tag-on':lc>=1?'tag-plan':'tag-off';
    act += '<tr><td>'+u.id+'</td><td>'+esc(u.name)+'</td><td>'+esc(u.email)+'</td><td style="font-size:10px">'+ll+'</td><td><span class="tag '+cc+'">'+lc+'</span></td><td style="font-size:10px">'+ls+'</td><td style="font-size:10px;color:#888">'+age+'</td></tr>';
  });
  act += '</table>';
  document.getElementById('activity-table').innerHTML = act;
}
function renderSettings(settings) {
  var html = '<table><tr><th>'+t('thId')+'</th><th>'+t('thName')+'</th><th>'+t('thEmail')+'</th><th>'+t('thAlerts')+'</th><th>'+t('thNewsletter')+'</th><th>'+t('thDarkMode')+'</th></tr>';
  settings.forEach(function(s){
    html += '<tr><td>'+s.id+'</td><td>'+esc(s.name)+'</td><td>'+esc(s.email)+'</td><td><span class="tag '+(s.price_alerts?'tag-on">ON':'tag-off">OFF')+'</span></td><td><span class="tag '+(s.weekly_newsletter?'tag-on">ON':'tag-off">OFF')+'</span></td><td><span class="tag '+(s.dark_mode?'tag-on">ON':'tag-off">OFF')+'</span></td></tr>';
  });
  html += '</table>';
  document.getElementById('settings-table').innerHTML = html;
}
function renderSessions(sessions) {
  var html = '<table><tr><th>'+t('thSid')+'</th><th>'+t('thUser')+'</th><th>'+t('thIpHash')+'</th><th>'+t('thUserAgent')+'</th><th>'+t('thLastSeen')+'</th><th>'+t('thExpires')+'</th><th>'+t('thStatus')+'</th></tr>';
  sessions.forEach(function(s){
    var sid = esc(s.sid.slice(0,12))+'...';
    var usr = s.userName ? '<span style="color:#c9a84c;font-weight:700">'+esc(s.userName)+'</span><br><span style="font-size:9px;color:#666">'+esc(s.userEmail||'')+'</span>' : '<span style="color:#555;font-size:9px">'+t('anonymous')+'</span>';
    var ip = s.ipHash ? '<span style="font-size:10px;color:#888;font-family:monospace">'+esc(s.ipHash)+'</span>' : '<span style="color:#555;font-size:9px">&mdash;</span>';
    var ua = s.ua ? '<span style="font-size:9px;color:#777;max-width:180px;display:inline-block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(s.ua)+'">'+esc(s.ua.slice(0,60))+(s.ua.length>60?'...':'')+'</span>' : '<span style="color:#555;font-size:9px">&mdash;</span>';
    var ls = s.lastSeen ? '<span style="font-size:10px">'+esc(s.lastSeen.replace('T',' ').slice(0,19))+'</span>' : '<span style="color:#555;font-size:9px">&mdash;</span>';
    var exp = s.expire ? new Date(s.expire) : null;
    var tag = (exp && exp<new Date()) ? '<span class="tag tag-off">'+t('expired')+'</span>' : '<span class="tag tag-on">'+t('active')+'</span>';
    html += '<tr><td class="sid">'+sid+'</td><td>'+usr+'</td><td>'+ip+'</td><td>'+ua+'</td><td>'+ls+'</td><td style="font-size:10px">'+(s.expire ? esc(s.expire) : '&mdash;')+'</td><td>'+tag+'</td></tr>';
  });
  html += '</table>';
  document.getElementById('sessions-table').innerHTML = html;
}

function setLang(lang) {
  currentLang = lang;
  localStorage.setItem('adminLang', lang);
  document.getElementById('admin-btn-en').className = lang==='en'?'active':'';
  document.getElementById('admin-btn-pt').className = lang==='pt'?'active':'';
  var els = document.querySelectorAll('[data-i18n]');
  for (var i = 0; i < els.length; i++) {
    var key = els[i].getAttribute('data-i18n');
    if (T[lang][key] !== undefined) els[i].innerHTML = T[lang][key];
  }
  if (window._adminData.summary) renderSummary(window._adminData.summary);
  if (window._adminData.users) renderUsers(window._adminData.users);
  if (window._adminData.usersMeta) renderPaginationControls('users-pagination', window._adminData.usersMeta, fetchAdminUsers);
  if (window._adminData.settings) renderSettings(window._adminData.settings);
  if (window._adminData.settingsMeta) renderPaginationControls('settings-pagination', window._adminData.settingsMeta, fetchAdminSettings);
  if (window._adminData.sessions) renderSessions(window._adminData.sessions);
  if (window._adminData.sessionsMeta) renderPaginationControls('sessions-pagination', window._adminData.sessionsMeta, fetchAdminSessions);
  if (window._adminData.tables) renderTables(window._adminData.tables);
  if (window._adminData.analytics) renderAnalyticsHeading(window._adminData.analytics);
  if (window._adminData.referrers) renderReferrers(window._adminData.referrers);
}
document.getElementById('admin-btn-en').addEventListener('click', function(){setLang('en');});
document.getElementById('admin-btn-pt').addEventListener('click', function(){setLang('pt');});
if (currentLang !== 'en') setLang(currentLang);
function confirmDelete(id, name, email) {
  document.getElementById('del-user-info').textContent = name + ' (' + email + ')';
  document.getElementById('del-confirm-link').href = '/admin/delete-user/' + id;
  document.getElementById('deleteDialog').showModal();
}
function esc(s) { if (s == null) return ''; var d = document.createElement('div'); d.textContent = String(s); return d.innerHTML; }
function escAttr(s) { return esc(s).replace(/'/g,'&#39;').replace(/"/g,'&quot;'); }
// CSS value sanitizer — whitelist approach: only allow safe characters for
// gradient/color values (hex, rgb, named colors, deg, commas, spaces, dots, %)
function escCss(s) { if (!s) return ''; return s.replace(/[^a-zA-Z0-9#%,.()\s\-]/g, ''); }

// Progressive image loading — upgrades img[data-prog-src] from thumbnail to full-res
function upgradeProgImages(root) {
  if (!root) return;
  var imgs = root.querySelectorAll('img[data-prog-src]');
  imgs.forEach(function(el) {
    var fullSrc = el.getAttribute('data-prog-src');
    if (!fullSrc) return;
    var full = new Image();
    full.onload = function() {
      el.src = fullSrc;
      el.classList.remove('prog-loading');
      el.classList.add('prog-loaded');
    };
    full.onerror = function() {
      el.classList.remove('prog-loading');
      el.classList.add('prog-loaded');
    };
    full.src = fullSrc;
  });
}

var gridColor = 'rgba(255,255,255,0.06)';
var tickColor = '#666';
var defOpts = {responsive:true,animation:{duration:600},plugins:{legend:{display:false}},scales:{x:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor}},y:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor},beginAtZero:true}}};
var legendOpts = {responsive:true,animation:{duration:600},plugins:{legend:{position:'bottom',labels:{color:tickColor,font:{size:9},padding:10}}}};

// ── Fetch summary stats ─────────────────────────────────────────
AdminCache.cachedFetch('/api/admin/summary', 'summary').then(function(res){
  var d = res.data;
  window._adminData.summary = d;
  window._adminData.tables = d.tables;
  renderSummary(d);
  renderTables(d.tables);
}).catch(function(){});

// ── Fetch user chart data ───────────────────────────────────────
var _chartInstances = {};
function renderUserCharts(CD) {
  // Destroy previous chart instances to allow re-rendering from cache
  ['regChart','cumChart','weekChart','featureChart','planChart','sessionChart','loginActivityChart','recentLoginsChart'].forEach(function(id) {
    if (_chartInstances[id]) { _chartInstances[id].destroy(); _chartInstances[id] = null; }
  });
  window._adminData.charts = CD;
  _chartInstances.regChart = new Chart(document.getElementById('regChart'),{type:'bar',data:{labels:CD.regTrends.map(function(r){return r.day}),datasets:[{data:CD.regTrends.map(function(r){return r.count}),backgroundColor:'rgba(201,168,76,0.6)',borderColor:'#c9a84c',borderWidth:1,borderRadius:3}]},options:Object.assign({},defOpts)});
  _chartInstances.cumChart = new Chart(document.getElementById('cumChart'),{type:'line',data:{labels:CD.cumulativeData.map(function(r){return r.day}),datasets:[{data:CD.cumulativeData.map(function(r){return r.total}),borderColor:'#5ddc78',backgroundColor:'rgba(93,220,120,0.1)',fill:true,tension:0.3,pointRadius:3,pointBackgroundColor:'#5ddc78'}]},options:Object.assign({},defOpts)});
  _chartInstances.weekChart = new Chart(document.getElementById('weekChart'),{type:'bar',data:{labels:CD.regWeekly.map(function(r){return r.week}),datasets:[{data:CD.regWeekly.map(function(r){return r.count}),backgroundColor:'rgba(173,90,77,0.6)',borderColor:'#ad5a4d',borderWidth:1,borderRadius:3}]},options:Object.assign({},defOpts)});
  _chartInstances.featureChart = new Chart(document.getElementById('featureChart'),{type:'doughnut',data:{labels:['Price Alerts','Newsletter','Dark Mode','Unused'],datasets:[{data:[CD.featureUsage.priceAlerts,CD.featureUsage.newsletter,CD.featureUsage.darkMode,Math.max(0,CD.featureUsage.total-CD.featureUsage.priceAlerts)],backgroundColor:['rgba(201,168,76,0.7)','rgba(93,220,120,0.7)','rgba(100,149,237,0.7)','rgba(60,60,60,0.5)'],borderColor:'#141418',borderWidth:2}]},options:legendOpts});
  _chartInstances.planChart = new Chart(document.getElementById('planChart'),{type:'pie',data:{labels:CD.planDist.map(function(p){return p.plan}),datasets:[{data:CD.planDist.map(function(p){return p.count}),backgroundColor:['rgba(201,168,76,0.7)','rgba(93,220,120,0.7)','rgba(173,90,77,0.7)','rgba(100,149,237,0.7)','rgba(200,200,200,0.4)'],borderColor:'#141418',borderWidth:2}]},options:legendOpts});
  _chartInstances.sessionChart = new Chart(document.getElementById('sessionChart'),{type:'bar',data:{labels:['Active Now'],datasets:[{data:[CD.activeSessions],backgroundColor:'rgba(93,220,120,0.6)',borderColor:'#5ddc78',borderWidth:1,borderRadius:6,barThickness:60}]},options:{responsive:true,animation:{duration:600},indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor},beginAtZero:true},y:{ticks:{color:tickColor,font:{size:10,weight:'bold'}},grid:{display:false}}}}});
  if(CD.loginActivity.length>0){_chartInstances.loginActivityChart = new Chart(document.getElementById('loginActivityChart'),{type:'bar',data:{labels:CD.loginActivity.map(function(u){return u.name}),datasets:[{data:CD.loginActivity.map(function(u){return u.login_count}),backgroundColor:'rgba(201,168,76,0.6)',borderColor:'#c9a84c',borderWidth:1,borderRadius:3}]},options:{responsive:true,indexAxis:'y',animation:{duration:600},plugins:{legend:{display:false}},scales:{x:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor},beginAtZero:true},y:{ticks:{color:tickColor,font:{size:9}},grid:{display:false}}}}});}
  if(CD.recentLogins.length>0){_chartInstances.recentLoginsChart = new Chart(document.getElementById('recentLoginsChart'),{type:'line',data:{labels:CD.recentLogins.map(function(r){return r.day}),datasets:[{label:'Logins',data:CD.recentLogins.map(function(r){return r.count}),borderColor:'#6495ed',backgroundColor:'rgba(100,149,237,0.1)',fill:true,tension:0.3,pointRadius:3,pointBackgroundColor:'#6495ed'}]},options:Object.assign({},defOpts)});}
}
AdminCache.cachedFetch('/api/admin/charts/users', 'charts_users').then(function(res){
  renderUserCharts(res.data);
}).catch(function(){});

// ── Fetch site analytics ────────────────────────────────────────
function renderSiteAnalytics(SA) {
  ['viewsChart','browserChart','deviceChart','eventsChart'].forEach(function(id) {
    if (_chartInstances[id]) { _chartInstances[id].destroy(); _chartInstances[id] = null; }
  });
  window._adminData.analytics = SA;
  window._adminData.referrers = SA.referrers;
  renderAnalyticsHeading(SA);
  if(SA.viewsPerDay.length>0){_chartInstances.viewsChart = new Chart(document.getElementById('viewsChart'),{type:'line',data:{labels:SA.viewsPerDay.map(function(r){return r.day}),datasets:[{label:'Views',data:SA.viewsPerDay.map(function(r){return r.views}),borderColor:'#c9a84c',backgroundColor:'rgba(201,168,76,0.1)',fill:true,tension:0.3,pointRadius:3,pointBackgroundColor:'#c9a84c'},{label:'Visitors',data:SA.viewsPerDay.map(function(r){return r.visitors}),borderColor:'#5ddc78',backgroundColor:'rgba(93,220,120,0.05)',fill:true,tension:0.3,pointRadius:3,pointBackgroundColor:'#5ddc78'}]},options:{responsive:true,animation:{duration:600},plugins:{legend:{position:'top',labels:{color:tickColor,font:{size:9}}}},scales:{x:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor}},y:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor},beginAtZero:true}}}});}
  if(SA.browsers.length>0){_chartInstances.browserChart = new Chart(document.getElementById('browserChart'),{type:'doughnut',data:{labels:SA.browsers.map(function(b){return b.name}),datasets:[{data:SA.browsers.map(function(b){return b.count}),backgroundColor:['rgba(201,168,76,0.7)','rgba(93,220,120,0.7)','rgba(100,149,237,0.7)','rgba(173,90,77,0.7)','rgba(200,200,200,0.4)','rgba(160,120,200,0.7)'],borderColor:'#141418',borderWidth:2}]},options:legendOpts});}
  if(SA.devices.length>0){_chartInstances.deviceChart = new Chart(document.getElementById('deviceChart'),{type:'pie',data:{labels:SA.devices.map(function(d){return d.name}),datasets:[{data:SA.devices.map(function(d){return d.count}),backgroundColor:['rgba(100,149,237,0.7)','rgba(201,168,76,0.7)','rgba(93,220,120,0.7)'],borderColor:'#141418',borderWidth:2}]},options:legendOpts});}
  if(SA.events.length>0){_chartInstances.eventsChart = new Chart(document.getElementById('eventsChart'),{type:'bar',data:{labels:SA.events.map(function(e){return e.event}),datasets:[{data:SA.events.map(function(e){return e.count}),backgroundColor:'rgba(100,149,237,0.6)',borderColor:'#6495ed',borderWidth:1,borderRadius:3}]},options:{responsive:true,indexAxis:'y',animation:{duration:600},plugins:{legend:{display:false}},scales:{x:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor},beginAtZero:true},y:{ticks:{color:tickColor,font:{size:8}},grid:{display:false}}}}});}
  renderReferrers(SA.referrers);
}
AdminCache.cachedFetch('/api/admin/charts/analytics', 'charts_analytics').then(function(res){
  renderSiteAnalytics(res.data);
}).catch(function(){});

// ── Fetch traffic anomalies ──────────────────────────────────────
function renderAnomalies(data) {
  var container = document.getElementById('anomalies-container');
  if (!container) return;
  if (!data.anomalies || data.anomalies.length === 0) {
    container.innerHTML = '<div class="anomaly-ok">&#10003; No anomalies detected. Traffic patterns are normal. (Z-score threshold: ' + (data.config ? data.config.zScoreThreshold : '2.5') + ', baseline: ' + (data.config ? data.config.baselineDays : '14') + ' days)</div>';
    return;
  }
  var html = '<div class="anomaly-list">';
  data.anomalies.forEach(function(a) {
    var sev = a.severity || 'info';
    var icon = sev === 'critical' ? '&#128680;' : sev === 'warning' ? '&#9888;' : '&#8505;';
    var typeLabel = (a.type || '').replace(/_/g, ' ');
    html += '<div class="anomaly-card ' + sev + '">';
    html += '<div class="anomaly-type">' + icon + ' ' + typeLabel + ' (' + sev + ')</div>';
    html += '<div class="anomaly-msg">' + (a.message || '').replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</div>';
    if (a.detectedAt) html += '<div class="anomaly-time">Detected: ' + new Date(a.detectedAt).toLocaleString() + '</div>';
    html += '</div>';
  });
  html += '</div>';
  container.innerHTML = html;
}
AdminCache.cachedFetch('/admin/anomalies', 'anomalies').then(function(res){
  renderAnomalies(res.data);
}).catch(function(){
  var container = document.getElementById('anomalies-container');
  if (container) container.innerHTML = '<div class="anomaly-card warning"><div class="anomaly-type">&#9888; Error</div><div class="anomaly-msg">Could not load anomaly data.</div></div>';
});

// ── Fetch users table (paginated) ────────────────────────────────
fetchAdminUsers(1);

// ── Fetch settings table (paginated) ─────────────────────────────
fetchAdminSettings(1);

// ── Fetch sessions table (paginated) ─────────────────────────────
fetchAdminSessions(1);

// ── Undo toast system ────────────────────────────────────────
var toastBar = document.createElement('div');
toastBar.className = 'toast-bar';
document.body.appendChild(toastBar);

function showAdminToast(msg, type) {
  var el = document.createElement('div');
  el.className = 'status-toast ' + (type || 'info');
  el.textContent = msg;
  toastBar.appendChild(el);
  setTimeout(function(){ el.style.animation = 'toastOut 0.3s ease forwards'; setTimeout(function(){ el.remove(); }, 350); }, 3000);
}

function showUndoToast(message, durationMs, onConfirm, onUndo) {
  durationMs = durationMs || 5000;
  var cancelled = false;
  var el = document.createElement('div');
  el.className = 'undo-toast';
  el.innerHTML = '<span class="ut-msg"></span><button class="ut-btn">Undo</button><div class="ut-bar" style="animation-duration:' + (durationMs/1000) + 's"></div>';
  el.querySelector('.ut-msg').textContent = message;
  el.querySelector('.ut-btn').addEventListener('click', function() {
    if (cancelled) return;
    cancelled = true;
    clearTimeout(timer);
    el.remove();
    if (typeof onUndo === 'function') onUndo();
  });
  toastBar.appendChild(el);
  var timer = setTimeout(function() {
    if (cancelled) return;
    cancelled = true;
    el.style.animation = 'toastOut 0.3s ease forwards';
    setTimeout(function(){ el.remove(); }, 350);
    if (typeof onConfirm === 'function') onConfirm();
  }, durationMs);
  return { cancel: function() { if (!cancelled) { cancelled = true; clearTimeout(timer); el.remove(); } } };
}

// ── Clear sessions with undo ─────────────────────────────────
document.getElementById('admin-clear-sessions').addEventListener('click', function() {
  showUndoToast(t('clearSessions') + ' — undo within 5 seconds', 5000, function onConfirm() {
    adminAction('/admin/clear-sessions', {}, 'Clear Sessions',
      function(d) {
        showAdminToast(d.message || 'Sessions cleared', 'success');
        fetchAdminSessions(window._adminPage.sessions);
        AdminCache.cachedFetch('/api/admin/summary', 'summary').then(function(res){
          window._adminData.summary = res.data;
          renderSummary(res.data);
        }).catch(function(){});
      },
      function() { showAdminToast('Failed to clear sessions', 'error'); }
    );
  }, function onUndo() {
    showAdminToast('Clear sessions cancelled', 'info');
  });
});

// ── Delete user with undo (override confirmDelete) ───────────
var pendingDeleteId = null;
window.confirmDelete = function(id, name, email) {
  document.getElementById('del-user-info').textContent = name + ' (' + email + ')';
  var dlg = document.getElementById('deleteDialog');
  var confirmLink = document.getElementById('del-confirm-link');
  // Replace the <a> with a click handler
  confirmLink.href = '#';
  confirmLink.onclick = function(e) {
    e.preventDefault();
    dlg.close();
    pendingDeleteId = id;
    showUndoToast(t('deleteUser') + ': ' + name + ' — undo within 5 seconds', 5000, function onConfirm() {
      adminAction('/admin/delete-user/' + pendingDeleteId, {}, 'Delete user: ' + name,
        function(d) {
          if (d.error) { showAdminToast(d.error, 'error'); return; }
          showAdminToast(d.message || 'User deleted', 'success');
          fetchAdminUsers(window._adminPage.users);
          fetchAdminSettings(window._adminPage.settings);
          AdminCache.cachedFetch('/api/admin/summary', 'summary').then(function(res){
            window._adminData.summary = res.data;
            window._adminData.tables = res.data.tables;
            renderSummary(res.data);
            renderTables(res.data.tables);
          }).catch(function(){});
        },
        function() { showAdminToast('Failed to delete user', 'error'); }
      );
    }, function onUndo() {
      showAdminToast(t('deleteUser') + ' cancelled', 'info');
    });
    return false;
  };
  dlg.showModal();
};

// ── Backup & Restore panel ───────────────────────────────────
window._backupVerifyCache = {};

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

function detectTier(filename) {
  if (filename.indexOf('-hourly-') !== -1) return 'hourly';
  if (filename.indexOf('-daily-') !== -1) return 'daily';
  if (filename.indexOf('-pre-pitr-') !== -1) return 'pre-pitr';
  return 'manual';
}

function formatDate(d) {
  try { return new Date(d).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }); }
  catch(e) { return String(d); }
}

function renderBackupsTable(backups) {
  var el = document.getElementById('backups-table');
  if (!backups || backups.length === 0) {
    el.innerHTML = '<p style="color:#555;font-size:11px">No backups found.</p>';
    return;
  }
  var html = '<table><tr>' +
    '<th>' + t('bkThFile') + '</th>' +
    '<th>' + t('bkThTier') + '</th>' +
    '<th>' + t('bkThSize') + '</th>' +
    '<th>' + t('bkThDate') + '</th>' +
    '<th>' + t('bkThVerify') + '</th>' +
    '<th>' + t('bkThActions') + '</th></tr>';
  for (var i = 0; i < backups.length; i++) {
    var b = backups[i];
    var tier = detectTier(b.filename);
    var vStatus = window._backupVerifyCache[b.filename];
    var vHtml = vStatus === true ? '<span class="verify-pass">PASS</span>'
              : vStatus === false ? '<span class="verify-fail">FAIL</span>'
              : '<span class="verify-pending">&mdash;</span>';
    html += '<tr class="backup-row">' +
      '<td style="font-size:10px;color:#aaa;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(b.filename) + '">' + esc(b.filename) + '</td>' +
      '<td><span class="backup-tier ' + tier + '">' + tier.toUpperCase() + '</span></td>' +
      '<td style="color:#888">' + formatBytes(b.size) + '</td>' +
      '<td style="font-size:10px;color:#888">' + formatDate(b.created) + '</td>' +
      '<td>' + vHtml + '</td>' +
      '<td style="white-space:nowrap">' +
        '<button class="btn btn-sm" onclick="verifyOneBackup(\'' + esc(b.filename) + '\')" title="Verify integrity">&#128270;</button> ' +
        '<button class="btn btn-sm btn-danger" onclick="confirmRestore(\'' + esc(b.filename) + '\')" title="Restore from this backup">&#9888; Restore</button>' +
      '</td></tr>';
  }
  html += '</table>';
  el.innerHTML = html;
}

function fetchBackups() {
  AdminCache.cachedFetch('/admin/backups', 'backups').then(function(res) {
    window._adminData.backups = res.data.backups;
    renderBackupsTable(res.data.backups);
  }).catch(function() {
    document.getElementById('backups-table').innerHTML = '<p style="color:#e05040;font-size:11px">Failed to load backups.</p>';
  });
}

function fetchPitrRange() {
  AdminCache.cachedFetch('/admin/pitr/range', 'pitr_range').then(function(res) {
    var d = res.data;
    var el = document.getElementById('pitr-range');
    if (!d.earliest && !d.latest) { el.innerHTML = ''; return; }
    el.innerHTML = '<div class="pitr-box">' +
      '<div class="pitr-item"><span class="pitr-label">' + t('pitrEarliest') + '</span><span class="pitr-val">' + (d.earliest ? formatDate(d.earliest) : '—') + '</span></div>' +
      '<div class="pitr-item"><span class="pitr-label">' + t('pitrLatest') + '</span><span class="pitr-val">' + (d.latest ? formatDate(d.latest) : '—') + '</span></div>' +
      '<div class="pitr-item"><span class="pitr-label">' + t('pitrBackups') + '</span><span class="pitr-val">' + d.backups + '</span></div>' +
      '<div class="pitr-item"><span class="pitr-label">' + t('pitrChangelog') + '</span><span class="pitr-val">' + (d.changelogEntries || 0).toLocaleString() + '</span></div>' +
    '</div>';
  }).catch(function() {});
}

// ── Create backup button ─────────────────────────────────────
document.getElementById('btn-create-backup').addEventListener('click', function() {
  var btn = this;
  btn.disabled = true;
  btn.style.opacity = '0.5';
  adminAction('/admin/backup', {}, 'Create Backup',
    function(d) {
      if (d.error) { showAdminToast(d.error, 'error'); return; }
      showAdminToast(d.message || 'Backup created', 'success');
      fetchBackups();
      fetchPitrRange();
    },
    function() { showAdminToast('Backup creation failed', 'error'); }
  ).finally(function() { btn.disabled = false; btn.style.opacity = ''; });
});

// ── Verify all button ────────────────────────────────────────
document.getElementById('btn-verify-all').addEventListener('click', function() {
  var btn = this;
  btn.disabled = true;
  btn.style.opacity = '0.5';
  adminAction('/admin/backup/verify-all', { body: '{}' }, 'Verify All Backups',
    function(d) {
      if (d.results) {
        for (var i = 0; i < d.results.length; i++) {
          window._backupVerifyCache[d.results[i].filename] = d.results[i].ok;
        }
      }
      showAdminToast('Verified ' + d.total + ': ' + d.passed + ' passed, ' + d.failed + ' failed', d.failed > 0 ? 'error' : 'success');
      renderBackupsTable(window._adminData.backups);
    },
    function() { showAdminToast('Verification failed', 'error'); }
  ).finally(function() { btn.disabled = false; btn.style.opacity = ''; });
});

// ── GFS prune button ─────────────────────────────────────────
document.getElementById('btn-gfs-prune').addEventListener('click', function() {
  var btn = this;
  btn.disabled = true;
  btn.style.opacity = '0.5';
  adminAction('/admin/backup/gfs-prune', { body: '{"tier":"daily"}' }, 'GFS Prune',
    function(d) {
      if (d.error) { showAdminToast(d.error, 'error'); return; }
      showAdminToast(d.message || 'GFS prune complete', 'success');
      fetchBackups();
    },
    function() { showAdminToast('GFS prune failed', 'error'); }
  ).finally(function() { btn.disabled = false; btn.style.opacity = ''; });
});

// ── Verify single backup ─────────────────────────────────────
window.verifyOneBackup = function(filename) {
  adminAction('/admin/backup/verify', { body: JSON.stringify({ filename: filename }) }, 'Verify: ' + filename,
    function(d) {
      window._backupVerifyCache[filename] = d.ok;
      renderBackupsTable(window._adminData.backups);
      showAdminToast(filename + ': ' + (d.ok ? 'PASS' : 'FAIL') + ' (' + d.durationMs + 'ms)', d.ok ? 'success' : 'error');
    },
    function() { showAdminToast('Verification failed for ' + filename, 'error'); }
  );
};

// ── One-click restore (with confirmation dialog) ─────────────
var pendingRestoreFile = null;
window.confirmRestore = function(filename) {
  pendingRestoreFile = filename;
  document.getElementById('restore-file-info').textContent = filename;
  document.getElementById('restoreDialog').showModal();
};

document.getElementById('restore-confirm-btn').addEventListener('click', function() {
  document.getElementById('restoreDialog').close();
  if (!pendingRestoreFile) return;
  var filename = pendingRestoreFile;
  pendingRestoreFile = null;

  showUndoToast('Restoring ' + filename + ' — undo within 5 seconds', 5000, function onConfirm() {
    showAdminToast('Restoring database from ' + filename + '...', 'info');
    fetch('/admin/backup/restore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: filename })
    })
      .then(function(r) { return r.json(); })
      .then(function(d) {
        if (d.error) { showAdminToast(d.error, 'error'); return; }
        showAdminToast(d.message || 'Database restored. Restart the server.', 'success');
      })
      .catch(function() { showAdminToast('Restore failed', 'error'); });
  }, function onUndo() {
    showAdminToast('Restore cancelled', 'info');
  });
});

// ── WAL Checkpoint Management ────────────────────────────────
var walCheckpointLog = [];

function renderWALStatus(d) {
  var el = document.getElementById('wal-status');
  var walClass = d.walFileSizeKB > 10240 ? 'danger' : d.walFileSizeKB > 1024 ? 'warn' : 'healthy';
  var journalClass = d.journalMode === 'wal' ? 'healthy' : 'warn';
  var freelistClass = d.freelistCount > 100 ? 'warn' : 'healthy';
  var autoCP = d.autoCheckpoint === 0 ? 'OFF' : d.autoCheckpoint + ' pg';

  el.innerHTML = '<div class="wal-grid">' +
    '<div class="wal-card ' + journalClass + '"><div class="wal-val">' + esc(d.journalMode).toUpperCase() + '</div><div class="wal-label">' + t('walJournal') + '</div></div>' +
    '<div class="wal-card ' + walClass + '"><div class="wal-val">' + formatBytes(d.walFileSize) + '</div><div class="wal-label">' + t('walFileSize') + '</div></div>' +
    '<div class="wal-card"><div class="wal-val">' + formatBytes(d.dbFileSize) + '</div><div class="wal-label">' + t('walDbSize') + '</div></div>' +
    '<div class="wal-card"><div class="wal-val">' + autoCP + '</div><div class="wal-label">' + t('walAutoCP') + '</div></div>' +
    '<div class="wal-card"><div class="wal-val">' + d.pageSize + ' B</div><div class="wal-label">' + t('walPageSize') + '</div></div>' +
    '<div class="wal-card"><div class="wal-val">' + d.pageCount.toLocaleString() + '</div><div class="wal-label">' + t('walPages') + '</div></div>' +
    '<div class="wal-card ' + freelistClass + '"><div class="wal-val">' + d.freelistCount + '</div><div class="wal-label">' + t('walFreelist') + '</div></div>' +
    '<div class="wal-card"><div class="wal-val">' + d.busyTimeout + 'ms</div><div class="wal-label">' + t('walBusyTimeout') + '</div></div>' +
  '</div>';
}

function renderCheckpointLog() {
  var el = document.getElementById('wal-checkpoint-log');
  if (walCheckpointLog.length === 0) { el.innerHTML = ''; return; }
  var html = '';
  for (var i = walCheckpointLog.length - 1; i >= Math.max(0, walCheckpointLog.length - 10); i--) {
    var e = walCheckpointLog[i];
    html += '<div class="wal-log-entry">' +
      '<span class="wal-log-mode">' + esc(e.mode) + '</span>' +
      '<span class="wal-log-detail">log: ' + e.log + ', checkpointed: ' + e.checkpointed + ', busy: ' + e.busy +
        (e.walFileSizeKB != null ? ' | WAL: ' + e.walFileSizeKB + ' KB after' : '') + '</span>' +
      '<span class="wal-log-time">' + e.time + '</span>' +
    '</div>';
  }
  el.innerHTML = html;
}

function fetchWALStatus() {
  AdminCache.cachedFetch('/admin/db/wal', 'wal_status').then(function(res) {
    renderWALStatus(res.data);
  }).catch(function() {
    document.getElementById('wal-status').innerHTML = '<p style="color:#e05040;font-size:11px">Failed to load WAL status.</p>';
  });
}

function doCheckpoint(mode) {
  var btns = document.querySelectorAll('[id^=btn-wal-]');
  btns.forEach(function(b) { b.disabled = true; b.style.opacity = '0.5'; });

  adminAction('/admin/db/checkpoint', { body: JSON.stringify({ mode: mode }) }, mode + ' Checkpoint',
    function(d) {
      if (d.error) { showAdminToast(d.error, 'error'); return; }
      walCheckpointLog.push({
        mode: mode,
        log: d.log != null ? d.log : '?',
        checkpointed: d.checkpointed != null ? d.checkpointed : '?',
        busy: d.busy != null ? d.busy : '?',
        walFileSizeKB: d.walFileSizeKB,
        time: new Date().toLocaleTimeString()
      });
      renderCheckpointLog();
      showAdminToast(d.message || (mode + ' checkpoint complete'), 'success');
      fetchWALStatus();
    },
    function() { showAdminToast(mode + ' checkpoint failed', 'error'); }
  ).finally(function() { btns.forEach(function(b) { b.disabled = false; b.style.opacity = ''; }); });
}

document.getElementById('btn-wal-refresh').addEventListener('click', fetchWALStatus);
document.getElementById('btn-wal-passive').addEventListener('click', function() { doCheckpoint('PASSIVE'); });
document.getElementById('btn-wal-full').addEventListener('click', function() { doCheckpoint('FULL'); });
document.getElementById('btn-wal-restart').addEventListener('click', function() { doCheckpoint('RESTART'); });
document.getElementById('btn-wal-truncate').addEventListener('click', function() {
  showUndoToast('TRUNCATE checkpoint — undo within 3 seconds', 3000, function() {
    doCheckpoint('TRUNCATE');
  }, function() {
    showAdminToast('TRUNCATE cancelled', 'info');
  });
});

document.getElementById('btn-integrity-check').addEventListener('click', function() {
  var btn = this;
  btn.disabled = true;
  btn.style.opacity = '0.5';
  fetch('/admin/db/health').then(function(r) { return r.json(); }).then(function(d) {
    if (d.error) { showAdminToast(d.error, 'error'); return; }
    if (d.healthy) {
      showAdminToast('Integrity check PASSED — database is healthy', 'success');
    } else {
      var errCount = Array.isArray(d.integrityCheck) ? d.integrityCheck.length : 0;
      showAdminToast('Integrity check FAILED — ' + errCount + ' error(s) found', 'error');
    }
    renderWALStatus(d);
  })
  .catch(function() { showAdminToast('Integrity check failed', 'error'); })
  .finally(function() { btn.disabled = false; btn.style.opacity = ''; });
});

// ── Initial load ─────────────────────────────────────────────
fetchBackups();
fetchPitrRange();
fetchWALStatus();
<\/script>
</body></html>`;
  res.send(html);
});

app.post('/admin/clear-sessions', requireAdmin, (req, res) => {
  const count = db.prepare('SELECT COUNT(*) as c FROM sessions').get().c;
  db.prepare('DELETE FROM sessions').run();
  res.json({ message: `${count} session(s) cleared.`, count });
});

app.post('/admin/delete-user/:id', requireAdmin, (req, res) => {
  const userId = parseInt(req.params.id, 10);
  if (isNaN(userId)) return res.status(400).json({ error: 'Invalid user ID.' });

  // Protect the siteadmin account
  const user = db.prepare('SELECT email, avatar, name FROM users WHERE id = ?').get(userId);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  if (user.email === 'siteadmin@oil.com') return res.status(403).json({ error: 'Cannot delete the admin account.' });

  // Delete avatar files (full + thumbnail) if they exist
  if (user.avatar) {
    const avatarPath = require('path').join(__dirname, 'uploads', user.avatar);
    const thumbPath = require('path').join(__dirname, 'uploads', user.avatar.replace('.webp', '_thumb.webp'));
    if (require('fs').existsSync(avatarPath)) require('fs').unlinkSync(avatarPath);
    if (require('fs').existsSync(thumbPath)) require('fs').unlinkSync(thumbPath);
  }

  // ── Complete data erasure across all user-related tables ────
  const eraseUser = db.transaction((uid) => {
    db.prepare('DELETE FROM notifications WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM push_subscriptions WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM price_alert_rules WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM email_verification_tokens WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM password_reset_tokens WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM user_settings WHERE user_id = ?').run(uid);
    // Purge all sessions belonging to this user from the session store
    db.prepare("DELETE FROM sessions WHERE json_extract(sess, '$.userId') = ?").run(uid);
    // Finally delete the user row itself
    db.prepare('DELETE FROM users WHERE id = ?').run(uid);
  });
  eraseUser(userId);

  log.info({ userId, email: user.email }, 'Admin: complete account data erasure performed');
  res.json({ message: `User "${user.name}" (${user.email}) deleted.` });
});

// ─── ADMIN PDF REPORT ────────────────────────────────────────────
app.get('/admin/report.pdf', requireAdmin, (req, res) => {
  try {
    const { generateReport } = require('./scripts/admin-report');
    const timestamp = new Date().toISOString().slice(0, 10);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="oil-benchmarks-admin-${timestamp}.pdf"`);
    const stream = generateReport();
    stream.pipe(res);
  } catch (err) {
    log.error({ err }, 'PDF report generation failed');
    res.status(500).json({ error: 'Report generation failed.' });
  }
});

// ─── BACKUP API ROUTES (admin-only) ────────────────────────────
const backup = require('./backup');

// POST /admin/backup — trigger a manual backup
app.post('/admin/backup', requireAdmin, async (req, res) => {
  try {
    const result = await backup.createBackup();
    const pruned = backup.pruneBackups();
    res.json({
      message: 'Backup created successfully.',
      backup: result,
      pruned: pruned.length > 0 ? pruned : null
    });
  } catch (err) {
    log.error({ err }, 'Manual backup failed');
    res.status(500).json({ error: 'Backup failed: ' + err.message });
  }
});

// GET /admin/backups — list all backups
app.get('/admin/backups', requireAdmin, (req, res) => {
  const backups = backup.listBackups();
  res.json({
    backups,
    retainCount: parseInt(process.env.BACKUP_RETAIN_COUNT, 10) || 10,
    gfsEnabled: backup.GFS_ENABLED,
  });
});

// POST /admin/backup/gfs-prune — run GFS retention prune on daily backups
app.post('/admin/backup/gfs-prune', requireAdmin, (req, res) => {
  try {
    const { tier } = req.body || {};
    const result = backup.pruneGFS({ tier: tier || 'daily' });
    res.json({
      message: `GFS prune complete: kept ${result.kept.length}, deleted ${result.deleted.length}.`,
      ...result,
    });
  } catch (err) {
    log.error({ err }, 'GFS prune failed');
    res.status(500).json({ error: 'GFS prune failed: ' + err.message });
  }
});

// POST /admin/backup/verify — verify a single backup's integrity
app.post('/admin/backup/verify', requireAdmin, (req, res) => {
  try {
    const { filename } = req.body;
    if (!filename) return res.status(400).json({ error: 'filename is required.' });

    const result = backup.verifyBackup(filename);
    res.json(result);
  } catch (err) {
    log.error({ err }, 'Backup verification failed');
    res.status(500).json({ error: 'Verification failed: ' + err.message });
  }
});

// POST /admin/backup/verify-all — verify all backups (optionally filtered by tier)
app.post('/admin/backup/verify-all', requireAdmin, (req, res) => {
  try {
    const { tier } = req.body || {};
    const summary = backup.verifyAllBackups(tier);
    res.json(summary);
  } catch (err) {
    log.error({ err }, 'Batch backup verification failed');
    res.status(500).json({ error: 'Batch verification failed: ' + err.message });
  }
});

// GET /admin/db/health — on-demand database health check (WAL + integrity)
app.get('/admin/db/health', requireAdmin, (req, res) => {
  try {
    const checkpoint = db.checkpointWAL('PASSIVE');
    const integrity = db.runIntegrityCheck();
    const walStatus = db.getWALStatus();
    res.json({
      healthy: integrity.ok,
      ...walStatus,
      walCheckpoint: checkpoint,
      integrityCheck: integrity.ok ? 'ok' : integrity.errors.slice(0, 50),
    });
  } catch (err) {
    log.error({ err }, 'Health check endpoint failed');
    res.status(500).json({ error: 'Health check failed: ' + err.message });
  }
});

// GET /admin/db/wal — detailed WAL status without running a checkpoint
app.get('/admin/db/wal', requireAdmin, (req, res) => {
  try {
    const walStatus = db.getWALStatus();
    res.json(walStatus);
  } catch (err) {
    log.error({ err }, 'WAL status query failed');
    res.status(500).json({ error: 'WAL status failed: ' + err.message });
  }
});

// POST /admin/db/checkpoint — trigger a manual WAL checkpoint
// Accepts { mode: 'PASSIVE' | 'FULL' | 'RESTART' | 'TRUNCATE' } (default: TRUNCATE)
app.post('/admin/db/checkpoint', requireAdmin, (req, res) => {
  try {
    const mode = (req.body && req.body.mode) || 'TRUNCATE';
    const result = db.checkpointWAL(mode);
    const walStatus = db.getWALStatus();
    log.info({ result, mode }, 'Manual WAL checkpoint');
    res.json({
      message: `WAL ${mode} checkpoint complete.`,
      mode,
      ...result,
      walFileSizeKB: walStatus.walFileSizeKB,
    });
  } catch (err) {
    log.error({ err }, 'Manual WAL checkpoint failed');
    res.status(500).json({ error: 'Checkpoint failed: ' + err.message });
  }
});

// GET /admin/anomalies — traffic anomaly detection results
app.get('/admin/anomalies', requireAdmin, (req, res) => {
  try {
    const detector = require('./utils/anomaly-detector');
    const forceRefresh = req.query.refresh === '1';
    const anomalies = forceRefresh ? detector.runAllDetectors() : detector.runAllDetectors();
    res.json({
      anomalies,
      count: anomalies.length,
      checkedAt: new Date().toISOString(),
      config: {
        zScoreThreshold: parseFloat(process.env.ANOMALY_ZSCORE_THRESHOLD) || 2.5,
        baselineDays: parseInt(process.env.ANOMALY_BASELINE_DAYS, 10) || 14,
      },
    });
  } catch (err) {
    log.error({ err }, 'Anomaly detection endpoint failed');
    res.status(500).json({ error: 'Anomaly detection failed: ' + err.message });
  }
});

// POST /admin/backup/restore — restore from a named backup file
app.post('/admin/backup/restore', requireAdmin, async (req, res) => {
  try {
    const { filename } = req.body;
    if (!filename) return res.status(400).json({ error: 'filename is required.' });

    const filePath = path.join(backup.BACKUP_DIR, filename);
    const result = await backup.restoreBackup(filePath);
    res.json({ message: 'Database restored. Restart the server to apply.', result });
  } catch (err) {
    log.error({ err }, 'Backup restore failed');
    res.status(500).json({ error: 'Restore failed: ' + err.message });
  }
});

// ─── POINT-IN-TIME RECOVERY API ROUTES (admin-only) ────────────

// GET /admin/pitr/range — show the recoverable time window
app.get('/admin/pitr/range', requireAdmin, (req, res) => {
  try {
    const range = backup.getPitrRange(db);
    res.json({
      enabled: PITR_ENABLED,
      ...range,
    });
  } catch (err) {
    log.error({ err }, 'PITR range query failed');
    res.status(500).json({ error: 'Failed to determine PITR range: ' + err.message });
  }
});

// GET /admin/pitr/changelog — browse recent changelog entries (paginated)
app.get('/admin/pitr/changelog', requireAdmin, (req, res) => {
  try {
    if (!PITR_ENABLED) {
      return res.status(400).json({ error: 'PITR is not enabled (set PITR_ENABLED=true).' });
    }
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 50));
    const offset = (page - 1) * limit;

    const total = db.prepare('SELECT COUNT(*) AS cnt FROM _pitr_changelog').get().cnt;
    const entries = db.prepare(
      'SELECT id, ts, tbl, op, row_id FROM _pitr_changelog ORDER BY id DESC LIMIT ? OFFSET ?'
    ).all(limit, offset);

    res.json({ page, limit, total, entries });
  } catch (err) {
    log.error({ err }, 'PITR changelog query failed');
    res.status(500).json({ error: 'Failed to read changelog: ' + err.message });
  }
});

// POST /admin/pitr/restore — perform point-in-time recovery
app.post('/admin/pitr/restore', requireAdmin, async (req, res) => {
  try {
    if (!PITR_ENABLED) {
      return res.status(400).json({ error: 'PITR is not enabled (set PITR_ENABLED=true).' });
    }
    const { timestamp } = req.body;
    if (!timestamp) {
      return res.status(400).json({ error: 'timestamp (ISO 8601) is required.' });
    }

    // Validate the timestamp is within the recoverable range
    const range = backup.getPitrRange(db);
    if (!range.earliest) {
      return res.status(400).json({ error: 'No backups available for recovery.' });
    }

    const target = new Date(timestamp);
    if (isNaN(target.getTime())) {
      return res.status(400).json({ error: 'Invalid timestamp format. Use ISO 8601.' });
    }
    if (target < new Date(range.earliest)) {
      return res.status(400).json({
        error: 'Target is before the oldest available backup.',
        earliest: range.earliest,
      });
    }
    if (range.latest && target > new Date(range.latest)) {
      return res.status(400).json({
        error: 'Target is after the latest recorded change.',
        latest: range.latest,
      });
    }

    // Take a pre-recovery safety snapshot
    try {
      const snap = await backup.createBackup('pre-pitr');
      log.info({ filename: snap.filename }, 'Pre-PITR safety snapshot saved');
    } catch (snapErr) {
      log.warn({ err: snapErr }, 'Pre-PITR safety snapshot failed (continuing anyway)');
    }

    const result = await backup.restoreToPointInTime(timestamp, db);
    res.json({
      message: 'Point-in-time recovery complete. Restart the server to load the recovered database.',
      ...result,
    });
  } catch (err) {
    log.error({ err }, 'PITR restore failed');
    res.status(500).json({ error: 'PITR failed: ' + err.message });
  }
});

// ── Health check endpoint for uptime monitoring ─────────────────────
// Lightweight endpoint that returns HTTP 200 when the server is running
// and the database is reachable. Designed for load-balancer health probes,
// container orchestrators (Docker / Kubernetes), and external uptime monitors.
app.get('/health', (req, res) => {
  try {
    // Verify database connectivity with a trivial query
    db.prepare('SELECT 1').get();
    res.status(200).json({
      status: 'ok',
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    log.error({ err }, 'Health check failed — database unreachable');
    res.status(503).json({
      status: 'error',
      error: 'Database unreachable',
      timestamp: new Date().toISOString(),
    });
  }
});

// Fallback: serve index.html for any non-API route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

if (require.main === module) {
  // ── Create server (HTTP/2 + HTTPS when TLS is configured, HTTP/1.1 otherwise) ──
  let server;
  let redirectServer = null;

  // ── Connection tracking for graceful drain ────────────────────
  // Track all open sockets so we can destroy idle ones at shutdown
  // instead of waiting for keep-alive timeouts to expire.
  const openConnections = new Set();

  function trackConnections(srv) {
    srv.on('connection', (socket) => {
      openConnections.add(socket);
      socket.once('close', () => openConnections.delete(socket));
    });
  }

  if (tlsEnabled) {
    // HTTP/2 with TLS — enables server push for critical assets.
    // allowHTTP1: true lets HTTP/1.1 clients (curl, older browsers) still connect.
    server = http2.createSecureServer(
      { ...tlsOptions, allowHTTP1: true },
      app
    );
    trackConnections(server);
    server.listen(PORT, () => {
      log.info({ port: PORT, protocol: 'h2' }, `HTTP/2 server running on https://localhost:${PORT}`);
    });

    // HTTP → HTTPS redirect server (plain HTTP/1.1 — redirect only, no push needed)
    const redirectApp = express();
    redirectApp.use((req, res) => {
      const host = (req.headers.host || '').replace(/:.*$/, '');
      const target = `https://${host}${PORT === 443 ? '' : ':' + PORT}${req.url}`;
      res.redirect(301, target);
    });
    redirectServer = http.createServer(redirectApp);
    trackConnections(redirectServer);
    redirectServer.listen(HTTP_PORT, () => {
      log.info({ port: HTTP_PORT }, `HTTP redirect server listening — all traffic redirected to HTTPS`);
    });
  } else {
    // Plain HTTP/1.1 for development (HTTP/2 requires TLS in browsers)
    server = http.createServer(app);
    trackConnections(server);
    server.listen(PORT, () => {
      log.info({ port: PORT, protocol: 'h1' }, `Server running on http://localhost:${PORT} (TLS not configured — set TLS_CERT_PATH & TLS_KEY_PATH for HTTP/2)`);
    });
  }

  // ── Scheduled backups (hourly + daily) ──────────────────────
  let backupScheduleHandle = null;
  if (process.env.BACKUP_DISABLED !== 'true') {
    const backupModule = require('./backup');
    backupScheduleHandle = backupModule.startSchedule(db);
  }

  // ── Server-side price checker (email alerts) ─────────────────
  let priceChecker = null;
  if (process.env.PRICE_CHECK_DISABLED !== 'true') {
    priceChecker = require('./utils/price-checker');
    const checkIntervalMin = parseInt(process.env.PRICE_CHECK_INTERVAL_MIN, 10) || 15;
    priceChecker.start(checkIntervalMin);
  }

  // ── Background cleanup: expired sessions & tokens ──────────────
  // Replaces the session store's built-in `expired.clear` interval with a
  // single job that also purges stale password-reset and email-verification
  // tokens, keeping the database lean.
  const CLEANUP_INTERVAL_MIN = parseInt(process.env.CLEANUP_INTERVAL_MIN, 10) || 15;

  const cleanupExpired = () => {
    try {
      const now = new Date().toISOString();

      // 1. Expired sessions — the session store uses column `expire` (not `expired`)
      const sessResult = db.prepare(
        "DELETE FROM sessions WHERE expire < datetime('now')"
      ).run();

      // 2. Expired password-reset tokens
      const prtResult = db.prepare(
        "DELETE FROM password_reset_tokens WHERE expires_at < ? OR used = 1"
      ).run(now);

      // 3. Expired email-verification tokens
      const evtResult = db.prepare(
        "DELETE FROM email_verification_tokens WHERE expires_at < ? OR used = 1"
      ).run(now);

      const total = sessResult.changes + prtResult.changes + evtResult.changes;
      if (total > 0) {
        log.info({
          expiredSessions: sessResult.changes,
          expiredResetTokens: prtResult.changes,
          expiredVerifyTokens: evtResult.changes,
        }, 'Cleanup: removed expired sessions and tokens');
      }
    } catch (err) {
      log.error({ err }, 'Cleanup job failed');
    }
  };

  // Run once on startup, then on a recurring interval
  cleanupExpired();
  const cleanupTimer = setInterval(cleanupExpired, CLEANUP_INTERVAL_MIN * 60 * 1000);
  cleanupTimer.unref();   // don't block graceful shutdown
  log.info({ intervalMin: CLEANUP_INTERVAL_MIN }, 'Background cleanup job enabled (sessions + tokens)');

  // ── Database health monitor: WAL checkpoint + integrity checks ──
  // Periodic PASSIVE WAL checkpoints keep the WAL file small and ensure
  // data durability. Hourly integrity checks detect corruption early;
  // if corruption is found the monitor auto-restores from the newest
  // valid backup (created by the scheduled backup job above).
  const backupModule = process.env.BACKUP_DISABLED !== 'true' ? require('./backup') : null;
  const dbHealthMonitor = db.startHealthMonitor(log, backupModule);

  // ── Traffic anomaly detection ──────────────────────────────────
  // Background job that periodically scans page_views and analytics_events
  // for unusual patterns (spikes, drops, bot activity, referrer surges).
  const anomalyDetector = require('./utils/anomaly-detector').startMonitor();

  // ── SIGHUP: hot-reload TLS certificates without downtime ────────
  // After Let's Encrypt renewal (via scripts/renew-certs.sh), send SIGHUP
  // to the Node process. The handler re-reads cert files from disk and calls
  // server.setSecureContext() so new connections use the fresh certificate
  // while existing connections finish uninterrupted.
  if (tlsEnabled) {
    process.on('SIGHUP', () => {
      log.info('SIGHUP received — reloading TLS certificates');
      try {
        const newCert = fs.readFileSync(path.resolve(tlsCertPath));
        const newKey  = fs.readFileSync(path.resolve(tlsKeyPath));
        const newCtx  = { cert: newCert, key: newKey };

        if (process.env.TLS_CA_PATH) {
          newCtx.ca = fs.readFileSync(path.resolve(process.env.TLS_CA_PATH));
        }

        server.setSecureContext(newCtx);

        // Update tlsOptions so the health-check or any other code referencing
        // them sees the current state
        tlsOptions.cert = newCert;
        tlsOptions.key  = newKey;
        if (newCtx.ca) tlsOptions.ca = newCtx.ca;

        // Log the new certificate's expiry for verification
        const { X509Certificate } = require('crypto');
        if (X509Certificate) {
          const x509 = new X509Certificate(newCert);
          log.info({
            subject: x509.subject,
            validTo: x509.validTo,
            issuer: x509.issuer,
          }, 'TLS certificates reloaded successfully');
        } else {
          log.info('TLS certificates reloaded successfully');
        }
      } catch (err) {
        log.error({ err }, 'Failed to reload TLS certificates — continuing with previous certs');
      }
    });
    log.info('SIGHUP handler registered for zero-downtime TLS certificate reload');
  }

  // ── Graceful shutdown ──────────────────────────────────────────
  // Handles SIGTERM (Docker/systemd stop), SIGINT (Ctrl-C), and
  // uncaught errors. Drains in-flight requests, stops all background
  // jobs, checkpoints WAL, and closes the SQLite connection before
  // exiting.
  const SHUTDOWN_TIMEOUT_MS = parseInt(process.env.SHUTDOWN_TIMEOUT_MS, 10) || 10000;
  let shuttingDown = false;

  function gracefulShutdown(signal) {
    if (shuttingDown) return;           // prevent re-entry from duplicate signals
    shuttingDown = true;
    log.info({ signal }, 'Shutting down gracefully');

    // Force-kill safety net: if draining takes too long, exit hard
    const forceTimer = setTimeout(() => {
      log.fatal('Shutdown timed out waiting for connections to drain — forcing exit');
      process.exit(1);
    }, SHUTDOWN_TIMEOUT_MS);
    forceTimer.unref();                 // don't let this timer keep the event loop alive

    // 1. Stop all background timers immediately so they don't fire during teardown
    if (dbHealthMonitor) dbHealthMonitor.stop();
    if (anomalyDetector) anomalyDetector.stop();
    if (priceChecker && typeof priceChecker.stop === 'function') priceChecker.stop();
    clearInterval(cleanupTimer);
    if (backupScheduleHandle) backupScheduleHandle.stop();

    // 2. Destroy idle keep-alive sockets so server.close() resolves promptly.
    //    Sockets with in-flight requests will finish naturally.
    for (const socket of openConnections) {
      // Mark the socket so HTTP keep-alive connections are closed after
      // the current response finishes (Connection: close header).
      socket.setTimeout(1);
    }

    // 3. Close the redirect server (HTTP→HTTPS) if it exists
    const closeRedirect = new Promise((resolve) => {
      if (redirectServer) {
        redirectServer.close(() => {
          log.info('HTTP redirect server closed');
          resolve();
        });
      } else {
        resolve();
      }
    });

    // 4. Stop accepting new connections and wait for in-flight requests to finish
    const closeMain = new Promise((resolve) => {
      server.close(() => {
        log.info('HTTP server closed — no more connections');
        resolve();
      });
    });

    Promise.all([closeMain, closeRedirect]).then(() => {
      // 5. Destroy any remaining sockets that haven't closed yet
      for (const socket of openConnections) {
        socket.destroy();
      }
      openConnections.clear();
      log.info('All connections drained');

      // 6. Checkpoint WAL so all data is flushed to the main database file
      try {
        db.pragma('wal_checkpoint(TRUNCATE)');
        log.info('WAL checkpoint complete');
      } catch (err) {
        log.error({ err }, 'WAL checkpoint failed during shutdown');
      }

      // 7. Close the database connection
      try {
        db.close();
        log.info('Database connection closed');
      } catch (err) {
        log.error({ err }, 'Database close failed during shutdown');
      }

      log.info('Clean exit');
      process.exit(0);
    });
  }

  // ── Last-resort exit handler ──────────────────────────────────
  // If something bypasses gracefulShutdown (e.g. process.exit() from a
  // dependency), attempt to close the DB synchronously. This is a
  // safety net — the primary path above is preferred.
  process.on('exit', () => {
    try { if (db.open) db.close(); } catch (_) { /* best effort */ }
  });

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT',  () => gracefulShutdown('SIGINT'));

  // Catch fatal errors — log and attempt a clean shutdown
  process.on('uncaughtException', (err) => {
    log.fatal({ err }, 'Uncaught exception');
    gracefulShutdown('uncaughtException');
  });
  process.on('unhandledRejection', (reason) => {
    log.fatal({ err: reason }, 'Unhandled rejection');
    gracefulShutdown('unhandledRejection');
  });
}

module.exports = app;
