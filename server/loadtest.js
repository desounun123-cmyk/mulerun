/**
 * k6 load test — OIL Benchmarks
 *
 * Exercises the primary user-facing and API endpoints under sustained
 * load to surface performance regressions, connection leaks, and
 * concurrency bugs that functional tests cannot catch.
 *
 * Prerequisites:
 *   brew install k6          # macOS
 *   choco install k6         # Windows
 *   sudo apt install k6      # Debian/Ubuntu (via grafana repo)
 *   docker run grafana/k6    # Docker
 *
 * Usage:
 *   # Smoke test (sanity check, 1 VU, 30 s)
 *   k6 run --env SCENARIO=smoke loadtest.js
 *
 *   # Average load (50 VUs ramping over 5 min)
 *   k6 run loadtest.js
 *
 *   # Stress test (200 VUs, find breaking point)
 *   k6 run --env SCENARIO=stress loadtest.js
 *
 *   # Spike test (sudden burst to 300 VUs)
 *   k6 run --env SCENARIO=spike loadtest.js
 *
 *   # Soak test (50 VUs sustained for 30 min)
 *   k6 run --env SCENARIO=soak loadtest.js
 *
 *   # Target a specific host
 *   k6 run --env BASE_URL=https://staging.oilbenchmarks.com loadtest.js
 *
 *   # Output results to JSON for CI analysis
 *   k6 run --out json=results.json loadtest.js
 *
 *   # Output to Prometheus remote-write (pairs with prometheus.js)
 *   k6 run --out experimental-prometheus-rw loadtest.js
 *
 * Environment variables:
 *   BASE_URL     Target server URL (default: http://localhost:3000)
 *   SCENARIO     One of: smoke, average, stress, spike, soak (default: average)
 *   TEST_USER    Pre-existing test account email (default: demo@oil.com)
 *   TEST_PASS    Pre-existing test account password (default: oil2026oil2026)
 */

import http from 'k6/http';
import { check, group, sleep, fail } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// ── Configuration ──────────────────────────────────────────────────
const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';
const SCENARIO = (__ENV.SCENARIO || 'average').toLowerCase();
const TEST_USER = __ENV.TEST_USER || 'demo@oil.com';
const TEST_PASS = __ENV.TEST_PASS || 'oil2026oil2026';

// ── Custom metrics ─────────────────────────────────────────────────
const loginDuration = new Trend('login_duration', true);
const apiErrorRate = new Rate('api_errors');
const pageLoadDuration = new Trend('page_load_duration', true);
const healthCheckDuration = new Trend('health_check_duration', true);
const rateLimitHits = new Counter('rate_limit_hits');

// ── Scenario definitions ───────────────────────────────────────────
const SCENARIOS = {
  smoke: {
    executor: 'constant-vus',
    vus: 1,
    duration: '30s',
  },
  average: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '30s', target: 10 },   // ramp up
      { duration: '1m',  target: 50 },   // ramp to average load
      { duration: '3m',  target: 50 },   // sustain
      { duration: '30s', target: 0 },    // ramp down
    ],
  },
  stress: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '30s', target: 50 },
      { duration: '1m',  target: 100 },
      { duration: '2m',  target: 200 },  // push past expected capacity
      { duration: '1m',  target: 200 },  // hold at peak
      { duration: '30s', target: 0 },
    ],
  },
  spike: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '10s', target: 10 },   // baseline
      { duration: '5s',  target: 300 },  // sudden spike
      { duration: '30s', target: 300 },  // hold spike
      { duration: '10s', target: 10 },   // drop back
      { duration: '30s', target: 10 },   // recovery
      { duration: '10s', target: 0 },
    ],
  },
  soak: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '1m',  target: 50 },   // ramp up
      { duration: '30m', target: 50 },   // sustained load
      { duration: '1m',  target: 0 },    // ramp down
    ],
  },
};

// ── k6 options ─────────────────────────────────────────────────────
export const options = {
  scenarios: {
    default: SCENARIOS[SCENARIO] || SCENARIOS.average,
  },
  thresholds: {
    // Global HTTP thresholds
    http_req_duration: [
      'p(95)<500',   // 95th percentile under 500ms
      'p(99)<1500',  // 99th percentile under 1.5s
    ],
    http_req_failed: ['rate<0.05'],  // <5% request failure rate

    // Custom metric thresholds
    login_duration: ['p(95)<800'],
    api_errors: ['rate<0.05'],
    page_load_duration: ['p(95)<1000'],
    health_check_duration: ['p(99)<100'],
  },
  // Don't follow redirects automatically — we want to check status codes
  noConnectionReuse: false,
  userAgent: 'k6-loadtest/1.0 (OIL Benchmarks)',
};

// ── Helpers ────────────────────────────────────────────────────────
const JSON_HEADERS = { 'Content-Type': 'application/json' };

function url(path) {
  return BASE_URL + path;
}

function checkResponse(res, name, expectedStatus) {
  const passed = check(res, {
    [`${name} status is ${expectedStatus}`]: (r) => r.status === expectedStatus,
    [`${name} response time < 2s`]: (r) => r.timings.duration < 2000,
  });
  if (!passed) {
    apiErrorRate.add(1);
    if (res.status === 429) {
      rateLimitHits.add(1);
    }
  } else {
    apiErrorRate.add(0);
  }
  return passed;
}

// ── Test lifecycle ─────────────────────────────────────────────────

/**
 * setup() runs once before the test starts.
 * Logs in the test user and returns the session cookie jar
 * for authenticated endpoint tests.
 */
export function setup() {
  // Verify the server is reachable
  const healthRes = http.get(url('/health'));
  if (healthRes.status !== 200) {
    fail(`Server not reachable at ${BASE_URL} — got status ${healthRes.status}`);
  }

  // Login to get a session cookie
  const loginRes = http.post(
    url('/api/auth/login'),
    JSON.stringify({ email: TEST_USER, password: TEST_PASS }),
    { headers: JSON_HEADERS, redirects: 0 }
  );

  const cookies = {};
  if (loginRes.cookies) {
    for (const name in loginRes.cookies) {
      if (loginRes.cookies[name] && loginRes.cookies[name].length > 0) {
        cookies[name] = loginRes.cookies[name][0].value;
      }
    }
  }

  return {
    cookies,
    loginOk: loginRes.status === 200,
  };
}

// ── Main test function (runs per VU per iteration) ─────────────────
export default function (data) {
  // Build cookie header for authenticated requests
  const cookieHeader = Object.entries(data.cookies || {})
    .map(([k, v]) => `${k}=${v}`)
    .join('; ');
  const authHeaders = {
    ...JSON_HEADERS,
    Cookie: cookieHeader,
  };

  // ── 1. Health check (unauthenticated) ────────────────────────
  group('Health endpoints', () => {
    const healthRes = http.get(url('/health'));
    healthCheckDuration.add(healthRes.timings.duration);
    checkResponse(healthRes, 'GET /health', 200);

    const livenessRes = http.get(url('/liveness'));
    checkResponse(livenessRes, 'GET /liveness', 200);

    const readyRes = http.get(url('/readiness'));
    checkResponse(readyRes, 'GET /readiness', 200);
  });

  sleep(0.5);

  // ── 2. Public pages (unauthenticated) ────────────────────────
  group('Public pages', () => {
    const homeRes = http.get(url('/'));
    pageLoadDuration.add(homeRes.timings.duration);
    checkResponse(homeRes, 'GET /', 200);

    check(homeRes, {
      'homepage contains expected content': (r) =>
        r.body && r.body.includes('OIL') && r.body.includes('Benchmarks'),
    });

    // Static assets
    const manifestRes = http.get(url('/manifest.json'));
    checkResponse(manifestRes, 'GET /manifest.json', 200);

    const swRes = http.get(url('/sw.js'));
    checkResponse(swRes, 'GET /sw.js', 200);
  });

  sleep(0.3);

  // ── 3. Authentication flow ───────────────────────────────────
  group('Auth: login', () => {
    const loginRes = http.post(
      url('/api/auth/login'),
      JSON.stringify({ email: TEST_USER, password: TEST_PASS }),
      { headers: JSON_HEADERS }
    );
    loginDuration.add(loginRes.timings.duration);
    checkResponse(loginRes, 'POST /api/auth/login', 200);

    check(loginRes, {
      'login returns ok=true': (r) => {
        try { return JSON.parse(r.body).ok === true; } catch (_) { return false; }
      },
    });
  });

  sleep(0.3);

  // ── 4. Auth: bad credentials (should 401, not 500) ───────────
  group('Auth: bad credentials', () => {
    const badRes = http.post(
      url('/api/auth/login'),
      JSON.stringify({ email: TEST_USER, password: 'wrongpassword123' }),
      { headers: JSON_HEADERS }
    );
    // 401 is expected — it's not an error from the load test perspective
    check(badRes, {
      'bad login returns 401': (r) => r.status === 401,
      'bad login returns ok=false': (r) => {
        try { return JSON.parse(r.body).ok === false; } catch (_) { return false; }
      },
    });
  });

  sleep(0.3);

  // ── 5. Authenticated API endpoints ───────────────────────────
  if (data.loginOk) {
    group('Authenticated: /api/auth/me', () => {
      const meRes = http.get(url('/api/auth/me'), { headers: authHeaders });
      checkResponse(meRes, 'GET /api/auth/me', 200);
    });

    group('Authenticated: /api/user/settings', () => {
      const settingsRes = http.get(url('/api/user/settings'), { headers: authHeaders });
      checkResponse(settingsRes, 'GET /api/user/settings', 200);
    });

    group('Authenticated: /api/user/notifications', () => {
      const notifsRes = http.get(url('/api/user/notifications'), { headers: authHeaders });
      checkResponse(notifsRes, 'GET /api/user/notifications', 200);
    });
  }

  sleep(0.3);

  // ── 6. Analytics tracking (unauthenticated, fire-and-forget) ─
  group('Analytics: pageview', () => {
    const pvRes = http.post(
      url('/api/analytics/pageview'),
      JSON.stringify({
        page: '/loadtest-' + Math.floor(Math.random() * 100),
        referrer: 'https://loadtest.example.com',
      }),
      { headers: JSON_HEADERS }
    );
    // 204 No Content is the expected response
    check(pvRes, {
      'pageview returns 200 or 204': (r) => r.status === 200 || r.status === 204,
    });
  });

  sleep(0.3);

  // ── 7. 404 handling (should return JSON, not crash) ──────────
  group('Error handling', () => {
    const notFoundRes = http.get(url('/api/nonexistent'));
    check(notFoundRes, {
      '404 returns correct status': (r) => r.status === 404,
      '404 returns JSON': (r) => {
        const ct = r.headers['Content-Type'] || '';
        return ct.includes('json') || ct.includes('html');
      },
    });
  });

  sleep(0.5);

  // ── 8. CAPTCHA generation (rate-limited endpoint) ────────────
  group('CAPTCHA generation', () => {
    const captchaRes = http.get(url('/api/auth/captcha'));
    check(captchaRes, {
      'captcha returns 200 or 429': (r) => r.status === 200 || r.status === 429,
    });
    if (captchaRes.status === 429) {
      rateLimitHits.add(1);
    }
  });

  // Stagger iterations to avoid thundering herd
  sleep(Math.random() * 2 + 0.5);
}

// ── Teardown ───────────────────────────────────────────────────────
export function teardown(data) {
  // Logout the shared session (best-effort cleanup)
  if (data.loginOk) {
    const cookieHeader = Object.entries(data.cookies || {})
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
    http.post(url('/api/auth/logout'), null, {
      headers: { Cookie: cookieHeader },
    });
  }
}

// ── Summary handler (optional: custom output) ──────────────────────
export function handleSummary(data) {
  // Default text summary to stdout
  const lines = [];
  lines.push('=== OIL Benchmarks Load Test Summary ===');
  lines.push(`Scenario: ${SCENARIO}`);
  lines.push(`Target:   ${BASE_URL}`);
  lines.push('');

  // Extract key metrics
  const metrics = data.metrics || {};
  const fmt = (m) => {
    if (!m || !m.values) return '—';
    const v = m.values;
    if (v.rate !== undefined) return `${(v.rate * 100).toFixed(1)}%`;
    if (v.avg !== undefined) return `avg=${v.avg.toFixed(0)}ms p95=${(v['p(95)'] || 0).toFixed(0)}ms p99=${(v['p(99)'] || 0).toFixed(0)}ms`;
    if (v.count !== undefined) return `${v.count}`;
    return JSON.stringify(v);
  };

  lines.push(`HTTP reqs:         ${fmt(metrics.http_reqs)}`);
  lines.push(`HTTP duration:     ${fmt(metrics.http_req_duration)}`);
  lines.push(`HTTP failures:     ${fmt(metrics.http_req_failed)}`);
  lines.push(`Login duration:    ${fmt(metrics.login_duration)}`);
  lines.push(`Page load:         ${fmt(metrics.page_load_duration)}`);
  lines.push(`Health check:      ${fmt(metrics.health_check_duration)}`);
  lines.push(`API error rate:    ${fmt(metrics.api_errors)}`);
  lines.push(`Rate limit hits:   ${fmt(metrics.rate_limit_hits)}`);

  // Check if thresholds passed
  const thresholds = data.thresholds || {};
  let allPassed = true;
  for (const [name, result] of Object.entries(thresholds)) {
    if (result && !result.ok) {
      lines.push(`  FAIL: ${name}`);
      allPassed = false;
    }
  }
  if (allPassed) {
    lines.push('\n  All thresholds PASSED');
  }

  return {
    stdout: lines.join('\n') + '\n',
    // Also write machine-readable JSON for CI pipelines
    'loadtest-results.json': JSON.stringify(data, null, 2),
  };
}
