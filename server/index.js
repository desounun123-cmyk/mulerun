require('dotenv').config();
const express = require('express');
const compression = require('compression');
const pinoHttp = require('pino-http');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');
const log = require('./logger');

// Initialize database (runs migrations + seed)
const db = require('./db');

// Session store backed by SQLite
const BetterSqlite3SessionStore = require('better-sqlite3-session-store');
const SqliteStore = BetterSqlite3SessionStore(session);

const app = express();
const PORT = parseInt(process.env.PORT, 10) || 8080;

// Trust first proxy (needed for correct req.ip behind nginx/load balancer & rate limiting)
app.set('trust proxy', 1);

// ── HTTP request logging via pino ────────────────────────────────
app.use(pinoHttp({
  logger: log.child({ module: 'http' }),
  // Don't log health-check / static asset noise in production
  autoLogging: {
    ignore: (req) => {
      const url = req.url || '';
      return url.startsWith('/uploads/') || url.endsWith('.js') || url.endsWith('.css') ||
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
app.use(compression({
  level: 6,           // zlib compression level (1-9, 6 is a good speed/ratio balance)
  threshold: 1024,    // only compress responses larger than 1 KB
  filter: function(req, res) {
    // Fall back to the default filter (compresses text/html, application/json, etc.)
    // but skip already-compressed formats like images
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  }
}));

// Parse JSON bodies
app.use(express.json());

// Session configuration
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) {
  log.warn('SESSION_SECRET not set — using random secret. Sessions will not survive restarts.');
}
const cookieMaxAgeDays = parseInt(process.env.COOKIE_MAX_AGE_DAYS, 10) || 7;
app.use(session({
  store: new SqliteStore({
    client: db,
    expired: {
      clear: true,
      intervalMs: 900000 // 15 minutes
    }
  }),
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE === 'true',
    maxAge: cookieMaxAgeDays * 24 * 60 * 60 * 1000,
    sameSite: 'lax'
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
  res.cookie('XSRF-TOKEN', req.session.csrfToken, {
    httpOnly: false,
    secure: process.env.COOKIE_SECURE === 'true',
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
app.use('/api/admin', requireAdmin, require('./routes/admin'));

// ─── RESET PASSWORD PAGE ─────────────────────────────────────
app.get('/reset-password', (req, res) => {
  const token = req.query.token || '';
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
    <input type="password" id="pw1" placeholder="Min. 4 characters" autocomplete="new-password">
  </div>
  <div class="field">
    <label>Confirm Password</label>
    <input type="password" id="pw2" placeholder="Re-enter password" autocomplete="new-password">
  </div>
  <button class="btn" id="submit-btn">Reset Password</button>
  <div class="msg" id="msg"></div>
  <a href="/" class="back">&larr; Back to OIL Benchmarks</a>
</div>
<script>
var token = ${JSON.stringify(token)};
var btn = document.getElementById('submit-btn');
var msg = document.getElementById('msg');
btn.addEventListener('click', function() {
  var pw1 = document.getElementById('pw1').value;
  var pw2 = document.getElementById('pw2').value;
  msg.className = 'msg'; msg.style.display = 'none';
  if (!pw1 || !pw2) { msg.textContent = 'Please fill in both fields.'; msg.className = 'msg error'; return; }
  if (pw1.length < 4) { msg.textContent = 'Password must be at least 4 characters.'; msg.className = 'msg error'; return; }
  if (pw1 !== pw2) { msg.textContent = 'Passwords do not match.'; msg.className = 'msg error'; return; }
  btn.disabled = true; btn.textContent = '...';
  fetch('/api/auth/reset', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: token, newPassword: pw1 })
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
<script>
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
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin — Oil Benchmarks</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0c0c0e;color:#e8e4dc;font-family:'DM Mono',monospace;padding:24px;font-size:13px}
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
.av-circle img{width:100%;height:100%;object-fit:cover}
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
</style>
</head>
<body>
<a class="close-btn" href="/" title="Back to App">&times;</a>
<div id="admin-lang-toggle"><button id="admin-btn-en" class="active">EN</button><button id="admin-btn-pt">PT</button></div>
<h1>&#9881; <span data-i18n="title">Admin Panel</span></h1>
<p class="subtitle"><span data-i18n="subtitle">Oil Benchmarks &mdash; Database Inspector</span></p>
<div class="warn">&#9888; <span data-i18n="warn">This route is for development only. Remove before deploying to production.</span></div>

<div class="stats" id="stats-bar"><span class="loading" data-i18n="loading">Loading stats...</span></div>

<div class="actions">
  <a class="btn" href="/admin" title="Refresh">&#8635; <span data-i18n="refresh">Refresh</span></a>
  <a class="btn" href="/admin/report.pdf" title="Download PDF report">&#128196; <span data-i18n="exportPdf">Export PDF</span></a>
  <button class="btn btn-danger" id="admin-clear-sessions" title="Clear all sessions">&#10005; <span data-i18n="clearSessions">Clear Sessions</span></button>
</div>

<h2>&#9776; <span data-i18n="analyticsDash">Analytics Dashboard</span></h2>
<div class="charts-grid">
  <div class="chart-card"><h3 data-i18n="regTrends">Registration Trends (Daily)</h3><canvas id="regChart"></canvas></div>
  <div class="chart-card"><h3 data-i18n="cumUsers">Cumulative Users Over Time</h3><canvas id="cumChart"></canvas></div>
  <div class="chart-card"><h3 data-i18n="regWeek">Registrations by Week</h3><canvas id="weekChart"></canvas></div>
  <div class="chart-card"><h3 data-i18n="features">Most Used Features</h3><canvas id="featureChart"></canvas></div>
  <div class="chart-card"><h3 data-i18n="planDist">Plan Distribution</h3><canvas id="planChart"></canvas></div>
  <div class="chart-card"><h3 data-i18n="activeSessions">Active Sessions</h3><canvas id="sessionChart"></canvas></div>
  <div class="chart-card"><h3 data-i18n="topLogins">Top Users by Logins</h3><canvas id="loginActivityChart"></canvas></div>
  <div class="chart-card"><h3 data-i18n="loginDaily">Login Activity (Daily)</h3><canvas id="recentLoginsChart"></canvas></div>
</div>

<h2 id="site-analytics-heading">&#128202; <span data-i18n="siteAnalytics">Site Analytics</span></h2>
<div class="charts-grid">
  <div class="chart-card"><h3 data-i18n="pvDaily">Page Views &amp; Visitors (Daily)</h3><canvas id="viewsChart"></canvas></div>
  <div class="chart-card"><h3 data-i18n="browsers">Browser Distribution</h3><canvas id="browserChart"></canvas></div>
  <div class="chart-card"><h3 data-i18n="devices">Device Types</h3><canvas id="deviceChart"></canvas></div>
  <div class="chart-card"><h3 data-i18n="featureEvents">Feature Events</h3><canvas id="eventsChart"></canvas></div>
</div>
<div id="referrers-container"></div>

<h2 data-i18n="usersH">Users</h2>
<div id="users-table"><span class="loading" data-i18n="loadingUsers">Loading users...</span></div>

<h2 data-i18n="settingsH">User Settings</h2>
<div id="settings-table"><span class="loading" data-i18n="loadingSettings">Loading settings...</span></div>

<h2>&#128337; <span data-i18n="activityH">User Activity Log</span></h2>
<div id="activity-table"><span class="loading" data-i18n="loadingActivity">Loading activity...</span></div>

<h2 data-i18n="sessionsH">Sessions</h2>
<div id="sessions-table"><span class="loading" data-i18n="loadingSessions">Loading sessions...</span></div>

<h2 data-i18n="tablesH">Tables</h2>
<div id="tables-list"><span class="loading" data-i18n="loadingTables">Loading...</span></div>

<a class="back" href="/">&#8592; <span data-i18n="backToApp">Back to App</span></a>

<dialog id="deleteDialog">
  <h3>&#9888; <span data-i18n="deleteUser">Delete User</span></h3>
  <p><span data-i18n="deleteConfirm">Are you sure you want to permanently delete</span> <span class="user-detail" id="del-user-info"></span>? <span data-i18n="deleteWarn">This will remove all their data including settings and sessions.</span></p>
  <div class="dialog-actions">
    <button class="btn" onclick="document.getElementById('deleteDialog').close()" data-i18n="cancel">Cancel</button>
    <a class="btn btn-danger" id="del-confirm-link" href="#">&#10005; <span data-i18n="deleteBtn">Delete</span></a>
  </div>
</dialog>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"><\/script>
<script>
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
    usersH:'Users', settingsH:'User Settings', activityH:'User Activity Log',
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
    logins:'Logins'
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
    logins:'Logins'
  }
};
var currentLang = localStorage.getItem('adminLang') || 'en';
function t(key) { return T[currentLang][key] || T.en[key] || key; }

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
function renderUsers(users) {
  var html = '<table><tr><th>'+t('thId')+'</th><th>'+t('thAvatar')+'</th><th>'+t('thName')+'</th><th>'+t('thEmail')+'</th><th>'+t('thPlan')+'</th><th>'+t('thAvatarBg')+'</th><th>'+t('thCreated')+'</th><th></th></tr>';
  users.forEach(function(u){
    var av = u.avatar
      ? '<div class="av-circle" style="background:'+escCss(u.avatar_bg||'linear-gradient(135deg,#85783c,#c9a84c)')+'"><img src="/uploads/'+esc(u.avatar)+'"></div>'
      : '<div class="av-circle" style="background:'+escCss(u.avatar_bg||'linear-gradient(135deg,#85783c,#c9a84c)') +'">'+esc(u.name?u.name[0].toUpperCase():'?')+'</div>';
    var planClass = u.plan==='Admin'?'tag-admin':'tag-plan';
    var bgLabel = u.avatar_bg ? '<span style="font-size:9px;color:#888">'+esc(u.avatar_bg.replace(/linear-gradient\\(135deg,/,'').replace(/\\)/,''))+'</span>' : '<span class="av-none">default</span>';
    var delBtn = u.email==='siteadmin@oil.com' ? '<span style="font-size:9px;color:#333">'+t('protected')+'</span>' : '<button class="btn btn-danger btn-sm" onclick="confirmDelete('+u.id+',\\''+esc(u.name).replace(/'/g,"\\\\'")+'\\''+',\\''+esc(u.email).replace(/'/g,"\\\\'")+'\\''+')">&#10005; '+t('deleteCol')+'</button>';
    html += '<tr><td>'+u.id+'</td><td>'+av+'</td><td>'+esc(u.name)+'</td><td>'+esc(u.email)+'</td><td><span class="tag '+planClass+'">'+esc(u.plan)+'</span></td><td>'+bgLabel+'</td><td>'+esc(u.created_at)+'</td><td>'+delBtn+'</td></tr>';
  });
  html += '</table>';
  document.getElementById('users-table').innerHTML = html;
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
  if (window._adminData.settings) renderSettings(window._adminData.settings);
  if (window._adminData.sessions) renderSessions(window._adminData.sessions);
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
function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function escAttr(s) { return esc(s).replace(/'/g,'&#39;').replace(/"/g,'&quot;'); }
function escCss(s) { return s ? s.replace(/[;}{<>"'()\\\\]/g,'').replace(/url/gi,'').replace(/expression/gi,'') : ''; }

var gridColor = 'rgba(255,255,255,0.06)';
var tickColor = '#666';
var defOpts = {responsive:true,animation:{duration:600},plugins:{legend:{display:false}},scales:{x:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor}},y:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor},beginAtZero:true}}};
var legendOpts = {responsive:true,animation:{duration:600},plugins:{legend:{position:'bottom',labels:{color:tickColor,font:{size:9},padding:10}}}};

// ── Fetch summary stats ─────────────────────────────────────────
fetch('/api/admin/summary').then(function(r){return r.json()}).then(function(d){
  window._adminData.summary = d;
  window._adminData.tables = d.tables;
  renderSummary(d);
  renderTables(d.tables);
});

// ── Fetch user chart data ───────────────────────────────────────
fetch('/api/admin/charts/users').then(function(r){return r.json()}).then(function(CD){
  new Chart(document.getElementById('regChart'),{type:'bar',data:{labels:CD.regTrends.map(function(r){return r.day}),datasets:[{data:CD.regTrends.map(function(r){return r.count}),backgroundColor:'rgba(201,168,76,0.6)',borderColor:'#c9a84c',borderWidth:1,borderRadius:3}]},options:Object.assign({},defOpts)});
  new Chart(document.getElementById('cumChart'),{type:'line',data:{labels:CD.cumulativeData.map(function(r){return r.day}),datasets:[{data:CD.cumulativeData.map(function(r){return r.total}),borderColor:'#5ddc78',backgroundColor:'rgba(93,220,120,0.1)',fill:true,tension:0.3,pointRadius:3,pointBackgroundColor:'#5ddc78'}]},options:Object.assign({},defOpts)});
  new Chart(document.getElementById('weekChart'),{type:'bar',data:{labels:CD.regWeekly.map(function(r){return r.week}),datasets:[{data:CD.regWeekly.map(function(r){return r.count}),backgroundColor:'rgba(173,90,77,0.6)',borderColor:'#ad5a4d',borderWidth:1,borderRadius:3}]},options:Object.assign({},defOpts)});
  new Chart(document.getElementById('featureChart'),{type:'doughnut',data:{labels:['Price Alerts','Newsletter','Dark Mode','Unused'],datasets:[{data:[CD.featureUsage.priceAlerts,CD.featureUsage.newsletter,CD.featureUsage.darkMode,Math.max(0,CD.featureUsage.total-CD.featureUsage.priceAlerts)],backgroundColor:['rgba(201,168,76,0.7)','rgba(93,220,120,0.7)','rgba(100,149,237,0.7)','rgba(60,60,60,0.5)'],borderColor:'#141418',borderWidth:2}]},options:legendOpts});
  new Chart(document.getElementById('planChart'),{type:'pie',data:{labels:CD.planDist.map(function(p){return p.plan}),datasets:[{data:CD.planDist.map(function(p){return p.count}),backgroundColor:['rgba(201,168,76,0.7)','rgba(93,220,120,0.7)','rgba(173,90,77,0.7)','rgba(100,149,237,0.7)','rgba(200,200,200,0.4)'],borderColor:'#141418',borderWidth:2}]},options:legendOpts});
  new Chart(document.getElementById('sessionChart'),{type:'bar',data:{labels:['Active Now'],datasets:[{data:[CD.activeSessions],backgroundColor:'rgba(93,220,120,0.6)',borderColor:'#5ddc78',borderWidth:1,borderRadius:6,barThickness:60}]},options:{responsive:true,animation:{duration:600},indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor},beginAtZero:true},y:{ticks:{color:tickColor,font:{size:10,weight:'bold'}},grid:{display:false}}}}});
  if(CD.loginActivity.length>0){new Chart(document.getElementById('loginActivityChart'),{type:'bar',data:{labels:CD.loginActivity.map(function(u){return u.name}),datasets:[{data:CD.loginActivity.map(function(u){return u.login_count}),backgroundColor:'rgba(201,168,76,0.6)',borderColor:'#c9a84c',borderWidth:1,borderRadius:3}]},options:{responsive:true,indexAxis:'y',animation:{duration:600},plugins:{legend:{display:false}},scales:{x:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor},beginAtZero:true},y:{ticks:{color:tickColor,font:{size:9}},grid:{display:false}}}}});}
  if(CD.recentLogins.length>0){new Chart(document.getElementById('recentLoginsChart'),{type:'line',data:{labels:CD.recentLogins.map(function(r){return r.day}),datasets:[{label:'Logins',data:CD.recentLogins.map(function(r){return r.count}),borderColor:'#6495ed',backgroundColor:'rgba(100,149,237,0.1)',fill:true,tension:0.3,pointRadius:3,pointBackgroundColor:'#6495ed'}]},options:Object.assign({},defOpts)});}
});

// ── Fetch site analytics ────────────────────────────────────────
fetch('/api/admin/charts/analytics').then(function(r){return r.json()}).then(function(SA){
  window._adminData.analytics = SA;
  window._adminData.referrers = SA.referrers;
  renderAnalyticsHeading(SA);
  if(SA.viewsPerDay.length>0){new Chart(document.getElementById('viewsChart'),{type:'line',data:{labels:SA.viewsPerDay.map(function(r){return r.day}),datasets:[{label:'Views',data:SA.viewsPerDay.map(function(r){return r.views}),borderColor:'#c9a84c',backgroundColor:'rgba(201,168,76,0.1)',fill:true,tension:0.3,pointRadius:3,pointBackgroundColor:'#c9a84c'},{label:'Visitors',data:SA.viewsPerDay.map(function(r){return r.visitors}),borderColor:'#5ddc78',backgroundColor:'rgba(93,220,120,0.05)',fill:true,tension:0.3,pointRadius:3,pointBackgroundColor:'#5ddc78'}]},options:{responsive:true,animation:{duration:600},plugins:{legend:{position:'top',labels:{color:tickColor,font:{size:9}}}},scales:{x:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor}},y:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor},beginAtZero:true}}}});}
  if(SA.browsers.length>0){new Chart(document.getElementById('browserChart'),{type:'doughnut',data:{labels:SA.browsers.map(function(b){return b.name}),datasets:[{data:SA.browsers.map(function(b){return b.count}),backgroundColor:['rgba(201,168,76,0.7)','rgba(93,220,120,0.7)','rgba(100,149,237,0.7)','rgba(173,90,77,0.7)','rgba(200,200,200,0.4)','rgba(160,120,200,0.7)'],borderColor:'#141418',borderWidth:2}]},options:legendOpts});}
  if(SA.devices.length>0){new Chart(document.getElementById('deviceChart'),{type:'pie',data:{labels:SA.devices.map(function(d){return d.name}),datasets:[{data:SA.devices.map(function(d){return d.count}),backgroundColor:['rgba(100,149,237,0.7)','rgba(201,168,76,0.7)','rgba(93,220,120,0.7)'],borderColor:'#141418',borderWidth:2}]},options:legendOpts});}
  if(SA.events.length>0){new Chart(document.getElementById('eventsChart'),{type:'bar',data:{labels:SA.events.map(function(e){return e.event}),datasets:[{data:SA.events.map(function(e){return e.count}),backgroundColor:'rgba(100,149,237,0.6)',borderColor:'#6495ed',borderWidth:1,borderRadius:3}]},options:{responsive:true,indexAxis:'y',animation:{duration:600},plugins:{legend:{display:false}},scales:{x:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor},beginAtZero:true},y:{ticks:{color:tickColor,font:{size:8}},grid:{display:false}}}}});}
  renderReferrers(SA.referrers);
});

// ── Fetch users table ───────────────────────────────────────────
fetch('/api/admin/users').then(function(r){return r.json()}).then(function(d){
  window._adminData.users = d.users;
  renderUsers(d.users);
});

// ── Fetch settings table ────────────────────────────────────────
fetch('/api/admin/settings').then(function(r){return r.json()}).then(function(d){
  window._adminData.settings = d.settings;
  renderSettings(d.settings);
});

// ── Fetch sessions table ────────────────────────────────────────
fetch('/api/admin/sessions').then(function(r){return r.json()}).then(function(d){
  window._adminData.sessions = d.sessions;
  renderSessions(d.sessions);
});

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
    fetch('/admin/clear-sessions', { method: 'POST', headers: { 'Content-Type': 'application/json' } })
      .then(function(r) { return r.json(); })
      .then(function(d) {
        showAdminToast(d.message || 'Sessions cleared', 'success');
        // Refresh sessions table
        fetch('/api/admin/sessions').then(function(r){return r.json()}).then(function(d){
          window._adminData.sessions = d.sessions;
          renderSessions(d.sessions);
        });
        // Refresh summary
        fetch('/api/admin/summary').then(function(r){return r.json()}).then(function(d){
          window._adminData.summary = d;
          renderSummary(d);
        });
      })
      .catch(function() { showAdminToast('Failed to clear sessions', 'error'); });
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
      fetch('/admin/delete-user/' + pendingDeleteId, { method: 'POST', headers: { 'Content-Type': 'application/json' } })
        .then(function(r) { return r.json(); })
        .then(function(d) {
          if (d.error) { showAdminToast(d.error, 'error'); return; }
          showAdminToast(d.message || 'User deleted', 'success');
          // Refresh users table
          fetch('/api/admin/users').then(function(r){return r.json()}).then(function(d){
            window._adminData.users = d.users;
            renderUsers(d.users);
          });
          fetch('/api/admin/settings').then(function(r){return r.json()}).then(function(d){
            window._adminData.settings = d.settings;
            renderSettings(d.settings);
          });
          fetch('/api/admin/summary').then(function(r){return r.json()}).then(function(d){
            window._adminData.summary = d;
            window._adminData.tables = d.tables;
            renderSummary(d);
            renderTables(d.tables);
          });
        })
        .catch(function() { showAdminToast('Failed to delete user', 'error'); });
    }, function onUndo() {
      showAdminToast(t('deleteUser') + ' cancelled', 'info');
    });
    return false;
  };
  dlg.showModal();
};
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

  // Delete avatar file if exists
  if (user.avatar) {
    const avatarPath = require('path').join(__dirname, 'uploads', user.avatar);
    if (require('fs').existsSync(avatarPath)) require('fs').unlinkSync(avatarPath);
  }

  // Delete user data (settings, then user)
  db.prepare('DELETE FROM user_settings WHERE user_id = ?').run(userId);
  db.prepare('DELETE FROM email_verification_tokens WHERE user_id = ?').run(userId);
  db.prepare('DELETE FROM password_reset_tokens WHERE user_id = ?').run(userId);
  db.prepare('DELETE FROM price_alert_rules WHERE user_id = ?').run(userId);
  db.prepare('DELETE FROM users WHERE id = ?').run(userId);

  res.json({ message: `User "${user.name}" (${user.email}) deleted.` });
});

// ─── ADMIN PDF REPORT ────────────────────────────────────────────
app.get('/admin/report.pdf', requireAdmin, (req, res) => {
  try {
    const { generateReport } = require('./admin-report');
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
  res.json({ backups, retainCount: parseInt(process.env.BACKUP_RETAIN_COUNT, 10) || 10 });
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

// Fallback: serve index.html for any non-API route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

if (require.main === module) {
  const server = app.listen(PORT, () => {
    log.info({ port: PORT }, `Server running on http://localhost:${PORT}`);

    // ── Scheduled backups ───────────────────────────────────────
    const backupIntervalHours = parseInt(process.env.BACKUP_INTERVAL_HOURS, 10) || 6;
    if (process.env.BACKUP_DISABLED !== 'true') {
      const backupModule = require('./backup');
      const runScheduledBackup = async () => {
        try {
          const result = await backupModule.createBackup();
          const pruned = backupModule.pruneBackups();
          log.info({ filename: result.filename, sizeKB: +(result.size / 1024).toFixed(1), pruned: pruned.length },
            'Scheduled backup complete');
        } catch (err) {
          log.error({ err }, 'Scheduled backup failed');
        }
      };
      // Initial backup on startup, then on interval
      runScheduledBackup();
      setInterval(runScheduledBackup, backupIntervalHours * 60 * 60 * 1000);
      log.info({ intervalHours: backupIntervalHours }, 'Auto-backup enabled');
    }

    // ── Server-side price checker (email alerts) ─────────────────
    if (process.env.PRICE_CHECK_DISABLED !== 'true') {
      const priceChecker = require('./price-checker');
      const checkIntervalMin = parseInt(process.env.PRICE_CHECK_INTERVAL_MIN, 10) || 15;
      priceChecker.start(checkIntervalMin);
    }
  });

  // ── Graceful shutdown ──────────────────────────────────────────
  // Handles SIGTERM (Docker/systemd stop), SIGINT (Ctrl-C), and
  // uncaught errors. Drains in-flight requests, checkpoints WAL,
  // and closes the SQLite connection before exiting.
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

    // 1. Stop accepting new connections and wait for in-flight requests to finish
    server.close(() => {
      log.info('HTTP server closed — no more connections');

      // 2. Checkpoint WAL so all data is flushed to the main database file
      try {
        db.pragma('wal_checkpoint(TRUNCATE)');
        log.info('WAL checkpoint complete');
      } catch (err) {
        log.error({ err }, 'WAL checkpoint failed during shutdown');
      }

      // 3. Close the database connection
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
