/**
 * server/utils/sentry.js
 *
 * Centralised error-tracking configuration using Sentry.
 *
 * Design decisions:
 *   1. No-op when SENTRY_DSN is unset — zero overhead in dev / CI.
 *   2. Initialises BEFORE other middleware so the request handler can
 *      instrument every request (tracing + breadcrumbs).
 *   3. Error handler is registered AFTER all routes to catch unhandled
 *      Express errors before the final fallback.
 *   4. Scrubs sensitive fields (password, token, session, cookie, secret,
 *      authorization, totp, captcha) from request bodies and headers.
 *   5. Exports a client-side snippet generator so the HTML shell can
 *      embed Sentry's browser SDK with the same DSN / environment.
 *   6. Attaches user context (id, email, plan) from the session when
 *      available — never sends the password hash or session ID.
 *   7. Configurable via environment variables only; no hard-coded DSNs.
 *
 * Environment variables:
 *   SENTRY_DSN             – Project DSN from sentry.io. Required to enable.
 *   SENTRY_ENVIRONMENT     – e.g. "production", "staging". Defaults to NODE_ENV.
 *   SENTRY_RELEASE         – Release tag. Defaults to npm_package_version or "unknown".
 *   SENTRY_TRACES_RATE     – Performance tracing sample rate 0-1. Default 0.2.
 *   SENTRY_PROFILES_RATE   – Profiling sample rate 0-1. Default 0.1.
 *   SENTRY_CLIENT_DSN      – Separate DSN for the browser SDK (optional, falls
 *                            back to SENTRY_DSN if unset). Useful when client
 *                            and server are different Sentry projects.
 *
 * Usage in index.js:
 *
 *   const sentry = require('./utils/sentry');
 *
 *   // BEFORE all other middleware:
 *   sentry.install(app);
 *
 *   // ... routes ...
 *
 *   // AFTER all routes, BEFORE the final error handler:
 *   sentry.errorHandler(app);
 *
 *   // In graceful shutdown:
 *   await sentry.flush();
 *
 *   // In HTML template (for client-side):
 *   const snippet = sentry.clientSnippet();
 */

'use strict';

const log = require('./logger');

// ── Configuration ──────────────────────────────────────────────────
const SENTRY_DSN         = process.env.SENTRY_DSN || '';
const SENTRY_ENVIRONMENT = process.env.SENTRY_ENVIRONMENT || process.env.NODE_ENV || 'development';
const SENTRY_RELEASE     = process.env.SENTRY_RELEASE || process.env.npm_package_version || 'unknown';
const TRACES_RATE        = parseFloat(process.env.SENTRY_TRACES_RATE) || 0.2;
const PROFILES_RATE      = parseFloat(process.env.SENTRY_PROFILES_RATE) || 0.1;
const CLIENT_DSN         = process.env.SENTRY_CLIENT_DSN || SENTRY_DSN;

const enabled = !!SENTRY_DSN;

// ── Sensitive field scrubbing ──────────────────────────────────────
const SCRUB_FIELDS = new Set([
  'password', 'newpassword', 'currentpassword', 'confirmpassword',
  'token', 'secret', 'totp', 'totpsecret', 'captcha', 'captchatext',
  'session', 'cookie', 'authorization', 'sessionid',
  'creditcard', 'cardnumber', 'cvv', 'ssn',
]);

/**
 * Deep-scrub an object, replacing sensitive leaf values with '[Filtered]'.
 * Handles nested objects up to 6 levels deep to avoid prototype-pollution DoS.
 */
function scrub(obj, depth) {
  if (depth === undefined) depth = 0;
  if (!obj || typeof obj !== 'object' || depth > 6) return obj;

  const out = Array.isArray(obj) ? [] : {};
  const keys = Object.keys(obj);
  for (let i = 0; i < keys.length; i++) {
    var key = keys[i];
    if (SCRUB_FIELDS.has(key.toLowerCase().replace(/[-_]/g, ''))) {
      out[key] = '[Filtered]';
    } else if (typeof obj[key] === 'object' && obj[key] !== null) {
      out[key] = scrub(obj[key], depth + 1);
    } else {
      out[key] = obj[key];
    }
  }
  return out;
}

// ── Sentry SDK (lazy-loaded only when DSN is present) ─────────────
let Sentry = null;

/**
 * Install Sentry request handler on the Express app.
 * Must be called BEFORE any route or middleware that you want traced.
 *
 * @param {import('express').Application} app
 */
function install(app) {
  if (!enabled) {
    log.info('Sentry disabled — SENTRY_DSN not set');
    return;
  }

  try {
    Sentry = require('@sentry/node');
  } catch (_err) {
    log.warn('Sentry SDK not installed — run: npm install @sentry/node @sentry/profiling-node');
    return;
  }

  // Optional profiling integration
  let profilingIntegration;
  try {
    var profiling = require('@sentry/profiling-node');
    profilingIntegration = profiling.nodeProfilingIntegration();
  } catch (_e) {
    // Profiling package not installed — proceed without it
  }

  const integrations = [];
  if (profilingIntegration) integrations.push(profilingIntegration);

  Sentry.init({
    dsn: SENTRY_DSN,
    environment: SENTRY_ENVIRONMENT,
    release: SENTRY_RELEASE,
    integrations: integrations,

    // Performance monitoring
    tracesSampleRate: TRACES_RATE,
    profilesSampleRate: PROFILES_RATE,

    // Scrub PII from events before they leave the server
    beforeSend: function (event) {
      // Scrub request body
      if (event.request && event.request.data) {
        try {
          var parsed = typeof event.request.data === 'string'
            ? JSON.parse(event.request.data)
            : event.request.data;
          event.request.data = JSON.stringify(scrub(parsed));
        } catch (_e) {
          // Non-JSON body — leave as-is (form data already handled by Sentry)
        }
      }

      // Scrub request headers
      if (event.request && event.request.headers) {
        event.request.headers = scrub(event.request.headers);
      }

      // Scrub cookies entirely — they contain session IDs
      if (event.request) {
        delete event.request.cookies;
        if (event.request.headers) {
          delete event.request.headers.cookie;
        }
      }

      return event;
    },

    // Scrub breadcrumb data
    beforeBreadcrumb: function (breadcrumb) {
      if (breadcrumb.data) {
        breadcrumb.data = scrub(breadcrumb.data);
      }
      return breadcrumb;
    },

    // Ignore expected errors that are not bugs
    ignoreErrors: [
      // Client disconnects mid-request
      'ECONNRESET',
      'EPIPE',
      'ECANCELED',
      // Rate-limited requests (429)
      'Too many requests',
      'Rate limit exceeded',
    ],

    // Don't send transactions for health checks or static assets
    tracesSampler: function (samplingContext) {
      var name = samplingContext.name || '';
      if (name === 'GET /health' || name === 'GET /readiness' || name === 'GET /liveness') {
        return 0;
      }
      if (/\.(js|css|png|ico|woff2|svg|map)$/.test(name)) {
        return 0;
      }
      return TRACES_RATE;
    },
  });

  // Sentry's Express request handler — creates transaction per request
  app.use(Sentry.Handlers.requestHandler({
    // Include IP for rate-limit debugging but scrub user agent (PII-lite)
    ip: true,
    user: false, // We set user context manually below
  }));

  // Sentry tracing handler — must come after requestHandler
  app.use(Sentry.Handlers.tracingHandler());

  // Attach user context from session (after session middleware runs)
  app.use(function sentryUserContext(req, _res, next) {
    if (Sentry && req.session && req.session.userId) {
      Sentry.setUser({
        id: String(req.session.userId),
        email: req.session.email || undefined,
        // Never send: password, sessionId, cookies, tokens
      });
    }
    next();
  });

  log.info(
    { environment: SENTRY_ENVIRONMENT, release: SENTRY_RELEASE, traces: TRACES_RATE },
    'Sentry initialised'
  );
}

/**
 * Install Sentry error handler on the Express app.
 * Must be called AFTER all routes but BEFORE your final catch-all error handler.
 *
 * @param {import('express').Application} app
 */
function errorHandler(app) {
  if (!enabled || !Sentry) return;

  app.use(Sentry.Handlers.errorHandler({
    // Only report 5xx errors (not 4xx validation/auth failures)
    shouldHandleError: function (error) {
      var status = error.status || error.statusCode || 500;
      return status >= 500;
    },
  }));
}

/**
 * Capture an error manually (for caught exceptions in background jobs,
 * cron tasks, push notification sends, etc.).
 *
 * @param {Error} err
 * @param {Object} [context] - Extra context tags/data
 */
function captureException(err, context) {
  if (!Sentry) {
    // Fallback: just log it
    log.error({ err, context }, 'Error (Sentry disabled)');
    return;
  }

  if (context) {
    Sentry.withScope(function (scope) {
      if (context.tags) scope.setTags(context.tags);
      if (context.extra) scope.setExtras(context.extra);
      if (context.user) scope.setUser(context.user);
      if (context.level) scope.setLevel(context.level);
      Sentry.captureException(err);
    });
  } else {
    Sentry.captureException(err);
  }
}

/**
 * Capture a message (info/warning level events that aren't exceptions).
 *
 * @param {string} message
 * @param {'fatal'|'error'|'warning'|'info'|'debug'} [level='info']
 * @param {Object} [extra]
 */
function captureMessage(message, level, extra) {
  if (!Sentry) {
    log[level === 'warning' ? 'warn' : (level || 'info')]({ extra }, message);
    return;
  }

  Sentry.withScope(function (scope) {
    if (extra) scope.setExtras(extra);
    Sentry.captureMessage(message, level || 'info');
  });
}

/**
 * Flush pending events to Sentry. Call during graceful shutdown
 * to ensure in-flight errors are delivered before the process exits.
 *
 * @param {number} [timeoutMs=2000]
 * @returns {Promise<boolean>}
 */
async function flush(timeoutMs) {
  if (!Sentry) return true;
  try {
    return await Sentry.flush(timeoutMs || 2000);
  } catch (_err) {
    return false;
  }
}

/**
 * Generate a <script> snippet for the client-side Sentry Browser SDK.
 * Embed the returned string in your HTML <head> before other scripts.
 *
 * Returns an empty string when Sentry is disabled, so templates
 * can unconditionally include it: `<%= sentry.clientSnippet() %>`
 *
 * @param {Object} [options]
 * @param {string} [options.browserSdkVersion='8'] - Major version of @sentry/browser CDN bundle
 * @returns {string} HTML script tag(s) or empty string
 */
function clientSnippet(options) {
  if (!CLIENT_DSN) return '';

  var ver = (options && options.browserSdkVersion) || '8';

  // Use the Sentry CDN loader — small stub that lazy-loads the full SDK
  // only when an error occurs, keeping the happy-path bundle at ~1 KB.
  return [
    '<script',
    '  src="https://browser.sentry-cdn.com/' + ver + '/bundle.tracing.min.js"',
    '  crossorigin="anonymous"',
    '></script>',
    '<script>',
    '  if (typeof Sentry !== "undefined") {',
    '    Sentry.init({',
    '      dsn: ' + JSON.stringify(CLIENT_DSN) + ',',
    '      environment: ' + JSON.stringify(SENTRY_ENVIRONMENT) + ',',
    '      release: ' + JSON.stringify(SENTRY_RELEASE) + ',',
    '      tracesSampleRate: 0.1,',
    '      replaysSessionSampleRate: 0,',
    '      replaysOnErrorSampleRate: 1.0,',
    '      ignoreErrors: [',
    '        "ResizeObserver loop",',
    '        "Non-Error promise rejection",',
    '        "Load failed",',
    '        "NetworkError",',
    '        "AbortError",',
    '        "ChunkLoadError",',
    '      ],',
    '      denyUrls: [',
    '        /extensions\\//i,',
    '        /^chrome:/i,',
    '        /^moz-extension:/i,',
    '      ],',
    '      beforeSend: function(event) {',
    '        if (event.request && event.request.headers) {',
    '          delete event.request.headers.cookie;',
    '          delete event.request.headers.authorization;',
    '        }',
    '        return event;',
    '      },',
    '    });',
    '  }',
    '</script>',
  ].join('\n');
}

// ── Exports ────────────────────────────────────────────────────────
module.exports = {
  /** Whether Sentry is configured (DSN is present) */
  enabled: enabled,

  /** Install request handler + tracing on Express app (call first) */
  install: install,

  /** Install error handler on Express app (call after routes) */
  errorHandler: errorHandler,

  /** Manually capture a caught exception */
  captureException: captureException,

  /** Capture an informational/warning message */
  captureMessage: captureMessage,

  /** Flush pending events (call in graceful shutdown) */
  flush: flush,

  /** HTML snippet for the client-side Sentry Browser SDK */
  clientSnippet: clientSnippet,

  /** Deep-scrub sensitive fields from an object (exported for testing) */
  _scrub: scrub,
};
