/**
 * Background Job Monitor — failure tracking, retry awareness, and admin alerting.
 *
 * Wraps any background job function with:
 *   - Consecutive and total failure counters
 *   - Configurable threshold for admin notification (default: 3 consecutive failures)
 *   - In-app notification to all Admin users when threshold is breached
 *   - Automatic counter reset on success
 *   - Per-job status queryable via getStatus()
 *
 * Usage:
 *   const { createMonitor } = require('./job-monitor');
 *   const monitor = createMonitor({
 *     name: 'price-checker',
 *     fn: runCheck,                   // async or sync function to wrap
 *     alertThreshold: 3,              // notify admins after N consecutive failures
 *     cooldownMs: 30 * 60 * 1000,    // don't re-alert within this window
 *   });
 *   await monitor.run();              // call this instead of fn() directly
 *   monitor.getStatus();              // { consecutiveFailures, totalFailures, ... }
 */
const db = require('../db/db');
const log = require('./logger').child({ module: 'job-monitor' });

// Registry of all monitors for the /admin/job-health endpoint
const _monitors = {};

/**
 * Create a monitored wrapper for a background job.
 *
 * @param {object} opts
 * @param {string} opts.name             — human-readable job name (e.g. 'price-checker')
 * @param {Function} opts.fn             — the job function (async or sync)
 * @param {number} [opts.alertThreshold] — consecutive failures before alerting (default: 3)
 * @param {number} [opts.cooldownMs]     — min ms between admin alerts (default: 30 min)
 * @returns {{ run: Function, getStatus: Function, reset: Function }}
 */
function createMonitor(opts) {
  const name = opts.name;
  const fn = opts.fn;
  const alertThreshold = opts.alertThreshold || 3;
  const cooldownMs = opts.cooldownMs || 30 * 60 * 1000;

  let consecutiveFailures = 0;
  let totalFailures = 0;
  let totalRuns = 0;
  let lastSuccess = null;
  let lastFailure = null;
  let lastError = null;
  let lastAlertAt = 0;

  /**
   * Notify all Admin users by inserting an in-app notification.
   */
  function notifyAdmins(errorMsg) {
    try {
      const now = Date.now();
      // Respect cooldown — don't spam admins
      if (now - lastAlertAt < cooldownMs) return;
      lastAlertAt = now;

      const admins = db.prepare("SELECT id FROM users WHERE plan = 'Admin'").all();
      if (admins.length === 0) {
        log.warn({ job: name }, 'No admin users to notify about job failure');
        return;
      }

      const title = `Background job "${name}" failing`;
      const message = `${consecutiveFailures} consecutive failure(s). `
        + `Last error: ${(errorMsg || 'unknown').slice(0, 500)}. `
        + `Total failures: ${totalFailures}/${totalRuns} runs.`;

      const stmt = db.prepare(
        "INSERT INTO notifications (user_id, type, title, message) VALUES (?, 'warning', ?, ?)"
      );

      for (const admin of admins) {
        stmt.run(admin.id, title, message);
      }

      log.warn({ job: name, adminsNotified: admins.length, consecutiveFailures },
        'Admin notification sent for repeated job failures');
    } catch (err) {
      // Notification failure must never crash the job loop
      log.error({ err, job: name }, 'Failed to send admin notification for job failure');
    }
  }

  /**
   * Execute the wrapped job function with failure tracking.
   * Returns whatever the original function returns on success.
   */
  async function run() {
    totalRuns++;
    try {
      const result = await fn();
      // Success — reset consecutive counter
      if (consecutiveFailures > 0) {
        log.info({ job: name, previousFailures: consecutiveFailures },
          'Job recovered after consecutive failures');
      }
      consecutiveFailures = 0;
      lastSuccess = new Date().toISOString();
      return result;
    } catch (err) {
      consecutiveFailures++;
      totalFailures++;
      lastFailure = new Date().toISOString();
      lastError = err.message || String(err);

      log.error({ err, job: name, consecutiveFailures, totalFailures },
        `Background job "${name}" failed (attempt ${consecutiveFailures})`);

      // Alert admins if threshold is reached
      if (consecutiveFailures >= alertThreshold) {
        notifyAdmins(lastError);
      }

      return undefined;
    }
  }

  function getStatus() {
    return {
      name,
      consecutiveFailures,
      totalFailures,
      totalRuns,
      lastSuccess,
      lastFailure,
      lastError,
      alertThreshold,
      healthy: consecutiveFailures < alertThreshold,
    };
  }

  function reset() {
    consecutiveFailures = 0;
    totalFailures = 0;
    totalRuns = 0;
    lastSuccess = null;
    lastFailure = null;
    lastError = null;
    lastAlertAt = 0;
  }

  const monitor = { run, getStatus, reset };
  _monitors[name] = monitor;
  return monitor;
}

/**
 * Get the status of all registered monitors.
 * Useful for an admin health endpoint.
 */
function getAllStatus() {
  const statuses = {};
  for (const [name, monitor] of Object.entries(_monitors)) {
    statuses[name] = monitor.getStatus();
  }
  return statuses;
}

module.exports = { createMonitor, getAllStatus };
