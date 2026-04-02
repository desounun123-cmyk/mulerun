/**
 * server/utils/prometheus.js
 *
 * Prometheus-compatible metrics for Grafana / Datadog / VictoriaMetrics / etc.
 *
 * Exposes a GET /metrics endpoint in OpenMetrics (Prometheus text) format.
 * Uses prom-client which is the de-facto Node.js Prometheus library.
 *
 * Design decisions:
 *   1. No-op when METRICS_ENABLED !== 'true' — zero overhead in dev.
 *   2. Collects default Node.js metrics (GC, event loop lag, memory, handles).
 *   3. Custom app-level metrics:
 *        - http_requests_total            (counter)   — by method, route, status
 *        - http_request_duration_seconds   (histogram) — latency percentiles
 *        - http_request_size_bytes         (histogram) — inbound payload sizes
 *        - http_response_size_bytes        (histogram) — outbound payload sizes
 *        - app_active_sessions_total       (gauge)     — current session count
 *        - app_registered_users_total      (gauge)     — total registered users
 *        - app_db_query_duration_seconds   (histogram) — DB query latency
 *        - app_push_sends_total            (counter)   — web push attempts
 *        - app_push_errors_total           (counter)   — web push failures
 *        - app_background_job_runs_total   (counter)   — background job executions
 *        - app_background_job_errors_total (counter)   — background job failures
 *        - app_login_attempts_total        (counter)   — by outcome (success/fail/locked)
 *        - app_rate_limit_hits_total       (counter)   — by endpoint
 *   4. /metrics endpoint is behind optional basic auth (METRICS_USER/METRICS_PASS)
 *      to prevent information leakage if accidentally exposed.
 *   5. /metrics is excluded from its own instrumentation to avoid feedback loops.
 *
 * Environment variables:
 *   METRICS_ENABLED   – 'true' to activate. Default: disabled.
 *   METRICS_USER      – Basic auth username for /metrics. Optional.
 *   METRICS_PASS      – Basic auth password for /metrics. Optional.
 *   METRICS_PREFIX     – Prefix for all metric names. Default: 'oil_'.
 *   METRICS_PATH       – Endpoint path. Default: '/metrics'.
 *   METRICS_BUCKETS    – Comma-separated histogram buckets for HTTP duration.
 *                        Default: '0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2.5,5,10'
 *
 * Usage in index.js:
 *
 *   const metrics = require('./utils/prometheus');
 *
 *   // BEFORE routes — installs collection middleware + /metrics endpoint:
 *   metrics.install(app);
 *
 *   // In route handlers or background jobs:
 *   metrics.loginAttempts.inc({ outcome: 'success' });
 *   metrics.pushSends.inc();
 *   metrics.dbQueryDuration.observe({ query: 'getUserById' }, 0.003);
 *   metrics.backgroundJobRuns.inc({ job: 'session-cleanup' });
 *   metrics.rateLimitHits.inc({ endpoint: '/api/auth/login' });
 *
 *   // Periodic gauge refresh (call from existing background jobs):
 *   metrics.refreshGauges(db);
 */

'use strict';

const log = require('./logger');

// ── Configuration ──────────────────────────────────────────────────
const ENABLED      = process.env.METRICS_ENABLED === 'true';
const METRICS_USER = process.env.METRICS_USER || '';
const METRICS_PASS = process.env.METRICS_PASS || '';
const PREFIX       = process.env.METRICS_PREFIX || 'oil_';
const METRICS_PATH = process.env.METRICS_PATH || '/metrics';
const BUCKETS      = (process.env.METRICS_BUCKETS || '0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2.5,5,10')
  .split(',')
  .map(Number);

// ── Lazy-loaded prom-client reference ──────────────────────────────
let client = null;

// ── Metric instances (populated by init()) ─────────────────────────
let httpRequestsTotal      = null;
let httpRequestDuration    = null;
let httpRequestSize        = null;
let httpResponseSize       = null;
let activeSessions         = null;
let registeredUsers        = null;
let dbQueryDuration        = null;
let pushSends              = null;
let pushErrors             = null;
let backgroundJobRuns      = null;
let backgroundJobErrors    = null;
let loginAttempts          = null;
let rateLimitHits          = null;

/**
 * Initialise prom-client and register all metrics.
 * Idempotent — safe to call multiple times.
 */
function init() {
  if (client) return; // already initialised

  try {
    client = require('prom-client');
  } catch (_err) {
    log.warn('prom-client not installed — run: npm install prom-client');
    return;
  }

  // Collect default Node.js metrics (GC, event loop, memory, active handles)
  client.collectDefaultMetrics({ prefix: PREFIX });

  // ── HTTP metrics ─────────────────────────────────────────────────
  httpRequestsTotal = new client.Counter({
    name: PREFIX + 'http_requests_total',
    help: 'Total HTTP requests',
    labelNames: ['method', 'route', 'status_code'],
  });

  httpRequestDuration = new client.Histogram({
    name: PREFIX + 'http_request_duration_seconds',
    help: 'HTTP request latency in seconds',
    labelNames: ['method', 'route', 'status_code'],
    buckets: BUCKETS,
  });

  httpRequestSize = new client.Histogram({
    name: PREFIX + 'http_request_size_bytes',
    help: 'HTTP request payload size in bytes',
    labelNames: ['method', 'route'],
    buckets: [100, 1000, 5000, 10000, 50000, 100000, 500000, 1000000],
  });

  httpResponseSize = new client.Histogram({
    name: PREFIX + 'http_response_size_bytes',
    help: 'HTTP response payload size in bytes',
    labelNames: ['method', 'route'],
    buckets: [100, 1000, 5000, 10000, 50000, 100000, 500000, 1000000, 5000000],
  });

  // ── Application metrics ──────────────────────────────────────────
  activeSessions = new client.Gauge({
    name: PREFIX + 'app_active_sessions_total',
    help: 'Number of active sessions in the session store',
  });

  registeredUsers = new client.Gauge({
    name: PREFIX + 'app_registered_users_total',
    help: 'Total registered user accounts',
  });

  dbQueryDuration = new client.Histogram({
    name: PREFIX + 'app_db_query_duration_seconds',
    help: 'Database query latency in seconds',
    labelNames: ['query'],
    buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1],
  });

  pushSends = new client.Counter({
    name: PREFIX + 'app_push_sends_total',
    help: 'Total web push notification send attempts',
  });

  pushErrors = new client.Counter({
    name: PREFIX + 'app_push_errors_total',
    help: 'Total web push notification send failures',
  });

  backgroundJobRuns = new client.Counter({
    name: PREFIX + 'app_background_job_runs_total',
    help: 'Total background job executions',
    labelNames: ['job'],
  });

  backgroundJobErrors = new client.Counter({
    name: PREFIX + 'app_background_job_errors_total',
    help: 'Total background job failures',
    labelNames: ['job'],
  });

  loginAttempts = new client.Counter({
    name: PREFIX + 'app_login_attempts_total',
    help: 'Login attempts by outcome',
    labelNames: ['outcome'],
  });

  rateLimitHits = new client.Counter({
    name: PREFIX + 'app_rate_limit_hits_total',
    help: 'Requests rejected by rate limiter',
    labelNames: ['endpoint'],
  });

  log.info({ path: METRICS_PATH, prefix: PREFIX }, 'Prometheus metrics initialised');
}

// ── Route normalisation ────────────────────────────────────────────
// Collapse dynamic path segments to avoid high-cardinality label explosion.
// /api/admin/users/42 → /api/admin/users/:id
// /uploads/avatar-abc123.png → /uploads/:file
const ROUTE_PATTERNS = [
  [/\/\d+/g, '/:id'],
  [/\/[0-9a-f]{8,}/gi, '/:id'],
  [/\/uploads\/[^/]+/g, '/uploads/:file'],
];

function normaliseRoute(url) {
  // Strip query string
  var route = url.split('?')[0];
  for (var i = 0; i < ROUTE_PATTERNS.length; i++) {
    route = route.replace(ROUTE_PATTERNS[i][0], ROUTE_PATTERNS[i][1]);
  }
  return route;
}

// ── Basic auth check ───────────────────────────────────────────────
function checkMetricsAuth(req, res) {
  if (!METRICS_USER && !METRICS_PASS) return true; // no auth configured

  var auth = req.headers.authorization || '';
  if (!auth.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="Metrics"');
    res.status(401).end('Unauthorized');
    return false;
  }

  var decoded = Buffer.from(auth.slice(6), 'base64').toString();
  var idx = decoded.indexOf(':');
  var user = idx >= 0 ? decoded.slice(0, idx) : decoded;
  var pass = idx >= 0 ? decoded.slice(idx + 1) : '';

  // Constant-time comparison to prevent timing attacks
  var crypto = require('crypto');
  var userOk = crypto.timingSafeEqual(
    Buffer.from(user.padEnd(256)),
    Buffer.from(METRICS_USER.padEnd(256))
  );
  var passOk = crypto.timingSafeEqual(
    Buffer.from(pass.padEnd(256)),
    Buffer.from(METRICS_PASS.padEnd(256))
  );

  if (!userOk || !passOk) {
    res.set('WWW-Authenticate', 'Basic realm="Metrics"');
    res.status(401).end('Unauthorized');
    return false;
  }

  return true;
}

// ── Public API ─────────────────────────────────────────────────────

/**
 * Install metrics collection middleware and the /metrics endpoint.
 * Call this BEFORE your routes.
 *
 * @param {import('express').Application} app
 */
function install(app) {
  if (!ENABLED) {
    log.info('Prometheus metrics disabled — set METRICS_ENABLED=true to activate');
    return;
  }

  init();
  if (!client) return; // prom-client not available

  // ── Collection middleware ───────────────────────────────────────
  app.use(function metricsCollector(req, res, next) {
    // Skip the metrics endpoint itself to avoid feedback loops
    if (req.path === METRICS_PATH) return next();

    var start = process.hrtime.bigint();

    // Capture request size
    var reqSize = parseInt(req.headers['content-length'], 10) || 0;

    // Hook into response finish
    res.once('finish', function () {
      var route = normaliseRoute(req.originalUrl || req.url);
      var method = req.method;
      var statusCode = String(res.statusCode);
      var durationNs = Number(process.hrtime.bigint() - start);
      var durationSec = durationNs / 1e9;

      httpRequestsTotal.inc({ method: method, route: route, status_code: statusCode });
      httpRequestDuration.observe({ method: method, route: route, status_code: statusCode }, durationSec);

      if (reqSize > 0) {
        httpRequestSize.observe({ method: method, route: route }, reqSize);
      }

      var resSize = parseInt(res.getHeader('content-length'), 10) || 0;
      if (resSize > 0) {
        httpResponseSize.observe({ method: method, route: route }, resSize);
      }
    });

    next();
  });

  // ── /metrics endpoint ──────────────────────────────────────────
  app.get(METRICS_PATH, async function (req, res) {
    if (!checkMetricsAuth(req, res)) return;

    try {
      var metricsOutput = await client.register.metrics();
      res.set('Content-Type', client.register.contentType);
      res.end(metricsOutput);
    } catch (err) {
      log.error({ err }, 'Failed to generate metrics');
      res.status(500).end('Internal error generating metrics');
    }
  });

  log.info({ path: METRICS_PATH }, 'Prometheus /metrics endpoint registered');
}

/**
 * Refresh application gauges that require a database query.
 * Call this from an existing background job (e.g. the session-cleanup interval)
 * to keep gauge values current without adding a new timer.
 *
 * @param {import('better-sqlite3').Database} db
 */
function refreshGauges(db) {
  if (!client || !activeSessions) return;

  try {
    var sessRow = db.prepare(
      "SELECT COUNT(*) AS cnt FROM sessions WHERE expired IS NULL OR expired > datetime('now')"
    ).get();
    activeSessions.set(sessRow ? sessRow.cnt : 0);
  } catch (_e) {
    // sessions table might not exist yet or use a different schema
    try {
      var sessRow2 = db.prepare('SELECT COUNT(*) AS cnt FROM sessions').get();
      activeSessions.set(sessRow2 ? sessRow2.cnt : 0);
    } catch (_e2) { /* ignore */ }
  }

  try {
    var userRow = db.prepare('SELECT COUNT(*) AS cnt FROM users').get();
    registeredUsers.set(userRow ? userRow.cnt : 0);
  } catch (_e) { /* ignore */ }
}

// ── No-op helpers when disabled ────────────────────────────────────
// These stubs allow call sites to use metrics.loginAttempts.inc()
// unconditionally without checking whether metrics are enabled.
var NOOP_COUNTER   = { inc: function () {} };
var NOOP_HISTOGRAM = { observe: function () {} };
var NOOP_GAUGE     = { set: function () {}, inc: function () {}, dec: function () {} };

module.exports = {
  /** Whether metrics collection is active */
  get enabled() { return ENABLED && !!client; },

  /** Install middleware + /metrics endpoint on Express app */
  install: install,

  /** Refresh DB-backed gauges (call from background job) */
  refreshGauges: refreshGauges,

  // ── Metric accessors (return no-op stubs when disabled) ────────
  /** Counter: total HTTP requests (auto-collected by middleware) */
  get httpRequestsTotal()      { return httpRequestsTotal      || NOOP_COUNTER; },
  /** Histogram: HTTP request latency (auto-collected by middleware) */
  get httpRequestDuration()    { return httpRequestDuration    || NOOP_HISTOGRAM; },
  /** Histogram: HTTP request payload size (auto-collected) */
  get httpRequestSize()        { return httpRequestSize        || NOOP_HISTOGRAM; },
  /** Histogram: HTTP response payload size (auto-collected) */
  get httpResponseSize()       { return httpResponseSize       || NOOP_HISTOGRAM; },
  /** Gauge: active sessions */
  get activeSessions()         { return activeSessions         || NOOP_GAUGE; },
  /** Gauge: registered users */
  get registeredUsers()        { return registeredUsers        || NOOP_GAUGE; },
  /** Histogram: DB query latency — observe({ query: 'name' }, seconds) */
  get dbQueryDuration()        { return dbQueryDuration        || NOOP_HISTOGRAM; },
  /** Counter: web push sends — inc() */
  get pushSends()              { return pushSends              || NOOP_COUNTER; },
  /** Counter: web push errors — inc() */
  get pushErrors()             { return pushErrors             || NOOP_COUNTER; },
  /** Counter: background job runs — inc({ job: 'name' }) */
  get backgroundJobRuns()      { return backgroundJobRuns      || NOOP_COUNTER; },
  /** Counter: background job errors — inc({ job: 'name' }) */
  get backgroundJobErrors()    { return backgroundJobErrors    || NOOP_COUNTER; },
  /** Counter: login attempts — inc({ outcome: 'success'|'fail'|'locked' }) */
  get loginAttempts()          { return loginAttempts          || NOOP_COUNTER; },
  /** Counter: rate limit rejections — inc({ endpoint: '/path' }) */
  get rateLimitHits()          { return rateLimitHits          || NOOP_COUNTER; },

  /** Normalise a URL path to a low-cardinality route label (exported for testing) */
  _normaliseRoute: normaliseRoute,
};
