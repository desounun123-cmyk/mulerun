/**
 * Traffic Anomaly Detector
 *
 * Analyses page_views and analytics_events to detect unusual patterns:
 *   - Hourly traffic spikes / drops (Z-score against rolling baseline)
 *   - Referrer surges (single referrer dominating recent traffic)
 *   - Bot-like behaviour (high request rate from single session hash)
 *   - Event anomalies (sudden appearance of new event types)
 *
 * Environment variables:
 *   ANOMALY_ZSCORE_THRESHOLD  — Z-score to flag (default 2.5)
 *   ANOMALY_BASELINE_DAYS     — days of history for baseline (default 14)
 *   ANOMALY_CHECK_INTERVAL_MIN — minutes between checks (default 30)
 */
const db = require('../db/db');
const log = require('./logger').child({ module: 'anomaly-detector' });
const { createMonitor } = require('./job-monitor');

const Z_THRESHOLD = parseFloat(process.env.ANOMALY_ZSCORE_THRESHOLD) || 2.5;
const BASELINE_DAYS = parseInt(process.env.ANOMALY_BASELINE_DAYS, 10) || 14;

// ── Stats helpers ───────────────────────────────────────────────

function mean(arr) {
  if (arr.length === 0) return 0;
  return arr.reduce((s, v) => s + v, 0) / arr.length;
}

function stddev(arr) {
  if (arr.length < 2) return 0;
  const m = mean(arr);
  const variance = arr.reduce((s, v) => s + (v - m) * (v - m), 0) / (arr.length - 1);
  return Math.sqrt(variance);
}

function zScore(value, m, sd) {
  if (sd === 0) return value === m ? 0 : (value > m ? Infinity : -Infinity);
  return (value - m) / sd;
}

// ── Detection functions ─────────────────────────────────────────

/**
 * Detect hourly traffic spikes and drops.
 * Compares the most recent complete hour against the same hour-of-day
 * baseline over the past BASELINE_DAYS.
 */
function detectHourlyAnomalies() {
  const anomalies = [];

  // Get hourly view counts for the baseline period
  const hourlyHistory = db.prepare(`
    SELECT strftime('%H', created_at) AS hour,
           date(created_at) AS day,
           COUNT(*) AS views
    FROM page_views
    WHERE created_at >= datetime('now', '-' || ? || ' days')
    GROUP BY date(created_at), strftime('%H', created_at)
    ORDER BY day ASC, hour ASC
  `).all(BASELINE_DAYS);

  // Get the most recent hour's count
  const recentHour = db.prepare(`
    SELECT strftime('%H', created_at) AS hour,
           COUNT(*) AS views,
           COUNT(DISTINCT session_hash) AS visitors
    FROM page_views
    WHERE created_at >= datetime('now', '-1 hour')
  `).get();

  if (!recentHour || !recentHour.hour) return anomalies;

  // Build baseline for the same hour-of-day
  const sameHourCounts = hourlyHistory
    .filter(h => h.hour === recentHour.hour)
    .map(h => h.views);

  if (sameHourCounts.length < 3) return anomalies; // not enough data

  const m = mean(sameHourCounts);
  const sd = stddev(sameHourCounts);
  const z = zScore(recentHour.views, m, sd);

  if (z > Z_THRESHOLD) {
    anomalies.push({
      type: 'traffic_spike',
      severity: z > Z_THRESHOLD * 2 ? 'critical' : 'warning',
      message: `Traffic spike detected at hour ${recentHour.hour}:00 — ${recentHour.views} views (baseline: ${m.toFixed(1)} ± ${sd.toFixed(1)}, z=${z.toFixed(2)})`,
      details: { hour: recentHour.hour, views: recentHour.views, visitors: recentHour.visitors, baseline_mean: +m.toFixed(1), baseline_sd: +sd.toFixed(1), z_score: +z.toFixed(2) },
      detectedAt: new Date().toISOString(),
    });
  } else if (z < -Z_THRESHOLD && m > 5) {
    anomalies.push({
      type: 'traffic_drop',
      severity: 'warning',
      message: `Traffic drop detected at hour ${recentHour.hour}:00 — ${recentHour.views} views (baseline: ${m.toFixed(1)} ± ${sd.toFixed(1)}, z=${z.toFixed(2)})`,
      details: { hour: recentHour.hour, views: recentHour.views, visitors: recentHour.visitors, baseline_mean: +m.toFixed(1), baseline_sd: +sd.toFixed(1), z_score: +z.toFixed(2) },
      detectedAt: new Date().toISOString(),
    });
  }

  return anomalies;
}

/**
 * Detect daily traffic anomalies.
 * Compares today's total so far against full-day totals from the baseline.
 */
function detectDailyAnomalies() {
  const anomalies = [];

  const dailyHistory = db.prepare(`
    SELECT date(created_at) AS day, COUNT(*) AS views
    FROM page_views
    WHERE created_at >= datetime('now', '-' || ? || ' days')
      AND date(created_at) < date('now')
    GROUP BY date(created_at)
    ORDER BY day ASC
  `).all(BASELINE_DAYS);

  const todayCount = db.prepare(`
    SELECT COUNT(*) AS views, COUNT(DISTINCT session_hash) AS visitors
    FROM page_views
    WHERE date(created_at) = date('now')
  `).get();

  if (!todayCount || dailyHistory.length < 3) return anomalies;

  const counts = dailyHistory.map(d => d.views);
  const m = mean(counts);
  const sd = stddev(counts);

  // Project today's total based on time elapsed
  const now = new Date();
  const hoursPassed = now.getUTCHours() + now.getUTCMinutes() / 60;
  if (hoursPassed < 1) return anomalies; // too early to judge

  const projectedDaily = (todayCount.views / hoursPassed) * 24;
  const z = zScore(projectedDaily, m, sd);

  if (z > Z_THRESHOLD) {
    anomalies.push({
      type: 'daily_spike',
      severity: z > Z_THRESHOLD * 2 ? 'critical' : 'warning',
      message: `Daily traffic trending high — ${todayCount.views} views so far, projected ~${Math.round(projectedDaily)} (baseline: ${m.toFixed(1)} ± ${sd.toFixed(1)}/day, z=${z.toFixed(2)})`,
      details: { todayViews: todayCount.views, todayVisitors: todayCount.visitors, projected: Math.round(projectedDaily), baseline_mean: +m.toFixed(1), baseline_sd: +sd.toFixed(1), z_score: +z.toFixed(2) },
      detectedAt: new Date().toISOString(),
    });
  } else if (z < -Z_THRESHOLD && m > 10) {
    anomalies.push({
      type: 'daily_drop',
      severity: 'warning',
      message: `Daily traffic trending low — ${todayCount.views} views so far, projected ~${Math.round(projectedDaily)} (baseline: ${m.toFixed(1)} ± ${sd.toFixed(1)}/day, z=${z.toFixed(2)})`,
      details: { todayViews: todayCount.views, todayVisitors: todayCount.visitors, projected: Math.round(projectedDaily), baseline_mean: +m.toFixed(1), baseline_sd: +sd.toFixed(1), z_score: +z.toFixed(2) },
      detectedAt: new Date().toISOString(),
    });
  }

  return anomalies;
}

/**
 * Detect referrer surges — a single referrer accounting for an
 * abnormally large share of recent traffic.
 */
function detectReferrerSurges() {
  const anomalies = [];

  const recent = db.prepare(`
    SELECT referrer, COUNT(*) AS count
    FROM page_views
    WHERE referrer IS NOT NULL AND referrer != ''
      AND created_at >= datetime('now', '-6 hours')
    GROUP BY referrer
    ORDER BY count DESC
    LIMIT 5
  `).all();

  const totalRecent = db.prepare(`
    SELECT COUNT(*) AS total FROM page_views
    WHERE created_at >= datetime('now', '-6 hours')
  `).get();

  if (!totalRecent || totalRecent.total < 20) return anomalies;

  for (const ref of recent) {
    const share = ref.count / totalRecent.total;
    // Flag if a single referrer accounts for > 60% of last 6h traffic
    if (share > 0.6 && ref.count > 10) {
      // Check if this referrer was also dominant historically
      const historical = db.prepare(`
        SELECT COUNT(*) AS count FROM page_views
        WHERE referrer = ? AND created_at >= datetime('now', '-' || ? || ' days')
      `).get(ref.referrer, BASELINE_DAYS);

      const historicalTotal = db.prepare(`
        SELECT COUNT(*) AS total FROM page_views
        WHERE created_at >= datetime('now', '-' || ? || ' days')
      `).get(BASELINE_DAYS);

      const historicalShare = historicalTotal && historicalTotal.total > 0
        ? historical.count / historicalTotal.total : 0;

      // Only flag if current share is significantly above historical share
      if (share > historicalShare * 2 || historicalShare < 0.2) {
        anomalies.push({
          type: 'referrer_surge',
          severity: 'warning',
          message: `Referrer surge: "${ref.referrer}" accounts for ${(share * 100).toFixed(0)}% of last 6h traffic (${ref.count}/${totalRecent.total} views, historical: ${(historicalShare * 100).toFixed(0)}%)`,
          details: { referrer: ref.referrer, recentCount: ref.count, recentTotal: totalRecent.total, recentShare: +share.toFixed(3), historicalShare: +historicalShare.toFixed(3) },
          detectedAt: new Date().toISOString(),
        });
      }
    }
  }

  return anomalies;
}

/**
 * Detect bot-like behaviour — session hashes with abnormally high
 * request counts in a short window.
 */
function detectBotPatterns() {
  const anomalies = [];

  const highRate = db.prepare(`
    SELECT session_hash, COUNT(*) AS count,
           COUNT(DISTINCT page) AS unique_pages
    FROM page_views
    WHERE created_at >= datetime('now', '-1 hour')
      AND session_hash IS NOT NULL
    GROUP BY session_hash
    HAVING count > 50
    ORDER BY count DESC
    LIMIT 10
  `).all();

  for (const sess of highRate) {
    // Low unique-page-to-total ratio suggests automated crawling
    const ratio = sess.unique_pages / sess.count;
    const isLikelyBot = ratio < 0.1 || sess.count > 200;

    anomalies.push({
      type: 'bot_pattern',
      severity: isLikelyBot ? 'critical' : 'warning',
      message: `Possible bot: session ${sess.session_hash.slice(0, 8)}… made ${sess.count} requests in 1h (${sess.unique_pages} unique pages, ratio=${ratio.toFixed(2)})`,
      details: { sessionHash: sess.session_hash, requests: sess.count, uniquePages: sess.unique_pages, pageRatio: +ratio.toFixed(3) },
      detectedAt: new Date().toISOString(),
    });
  }

  return anomalies;
}

/**
 * Detect new/unusual event types that appeared recently but were
 * never seen before in the baseline period.
 */
function detectNewEventTypes() {
  const anomalies = [];

  const recentEvents = db.prepare(`
    SELECT event, COUNT(*) AS count
    FROM analytics_events
    WHERE created_at >= datetime('now', '-24 hours')
    GROUP BY event
  `).all();

  const baselineEvents = db.prepare(`
    SELECT DISTINCT event FROM analytics_events
    WHERE created_at < datetime('now', '-24 hours')
      AND created_at >= datetime('now', '-' || ? || ' days')
  `).all(BASELINE_DAYS);

  const knownEvents = new Set(baselineEvents.map(e => e.event));

  for (const evt of recentEvents) {
    if (!knownEvents.has(evt.event) && evt.count >= 3) {
      anomalies.push({
        type: 'new_event_type',
        severity: 'info',
        message: `New event type detected: "${evt.event}" (${evt.count} occurrences in last 24h, never seen in baseline)`,
        details: { event: evt.event, count: evt.count },
        detectedAt: new Date().toISOString(),
      });
    }
  }

  return anomalies;
}

// ── Main detection runner ───────────────────────────────────────

/**
 * Run all anomaly detectors and return combined results.
 */
function runAllDetectors() {
  const all = [];
  const detectors = [
    { name: 'hourly', fn: detectHourlyAnomalies },
    { name: 'daily', fn: detectDailyAnomalies },
    { name: 'referrer', fn: detectReferrerSurges },
    { name: 'bot', fn: detectBotPatterns },
    { name: 'events', fn: detectNewEventTypes },
  ];

  for (const d of detectors) {
    try {
      const results = d.fn();
      all.push(...results);
    } catch (err) {
      log.error({ err, detector: d.name }, 'Anomaly detector failed');
    }
  }

  return all;
}

// ── Background monitor ──────────────────────────────────────────

let recentAnomalies = [];

/**
 * Start a background job that runs anomaly detection periodically.
 * Logs warnings for any detected anomalies.
 * Returns a handle with `.stop()` and `.getAnomalies()`.
 */
function startMonitor(options) {
  const intervalMin = (options && options.intervalMin)
    || parseInt(process.env.ANOMALY_CHECK_INTERVAL_MIN, 10) || 30;

  const _monitor = createMonitor({
    name: 'anomaly-detector',
    fn: () => {
      const results = runAllDetectors();
      if (results.length > 0) {
        recentAnomalies = results;
        for (const a of results) {
          const level = a.severity === 'critical' ? 'error' : a.severity === 'warning' ? 'warn' : 'info';
          log[level]({ anomaly: a.type, details: a.details }, a.message);
        }
      } else {
        // Keep stale anomalies for 2 intervals then clear
        if (recentAnomalies.length > 0) {
          const cutoff = Date.now() - intervalMin * 2 * 60 * 1000;
          recentAnomalies = recentAnomalies.filter(a => new Date(a.detectedAt).getTime() > cutoff);
        }
      }
      return results;
    },
    alertThreshold: 3,
    cooldownMs: 60 * 60 * 1000,   // 1 hour cooldown (anomaly detector runs less frequently)
  });

  // First run after a short delay (let the server finish booting)
  setTimeout(() => _monitor.run(), 10000);
  const timer = setInterval(() => _monitor.run(), intervalMin * 60 * 1000);
  timer.unref();

  log.info({ intervalMin, zThreshold: Z_THRESHOLD, baselineDays: BASELINE_DAYS },
    'Traffic anomaly detector started');

  return {
    stop() { clearInterval(timer); },
    getAnomalies() { return recentAnomalies; },
    runNow() { _monitor.run(); return recentAnomalies; },
    getStatus: _monitor.getStatus,
    runAllDetectors,
  };
}

module.exports = {
  runAllDetectors,
  startMonitor,
  detectHourlyAnomalies,
  detectDailyAnomalies,
  detectReferrerSurges,
  detectBotPatterns,
  detectNewEventTypes,
};
