/**
 * server/routes/gdpr.js
 *
 * GDPR compliance endpoints — user self-service data portability and
 * erasure request management.
 *
 * Covers:
 *   Article 15 — Right of Access        → GET  /api/user/gdpr/export
 *   Article 17 — Right to Erasure       → POST /api/user/gdpr/delete-request
 *   Article 20 — Right to Portability   → GET  /api/user/gdpr/export
 *
 * The existing DELETE /api/auth/account performs immediate erasure.
 * This module adds:
 *   1. A user-facing data export (own data only, JSON download)
 *   2. A confirmed deletion request flow with cooling-off window
 *   3. A gdpr_requests audit table for compliance record-keeping
 *
 * Mount:  app.use('/api/user/gdpr', require('./routes/gdpr'));
 */
'use strict';

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const log = require('../utils/logger');
const { ok, fail } = require('../utils/response');
const db = require('../db/db');

// ── Rate limiting ────────────────────────────────────────────────────
const rateLimit = require('express-rate-limit');
const isTest = process.env.NODE_ENV === 'test';

const gdprLimiter = isTest
  ? (_req, _res, next) => next()
  : rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5,
      standardHeaders: true,
      legacyHeaders: false,
      message: { ok: false, error: 'Too many requests. Please try again later.' },
    });

// ── Auth guard ───────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return fail(res, 401, 'Authentication required.');
  }
  next();
}

// All routes require authentication
router.use(requireAuth);
router.use(gdprLimiter);

// ── Migration — gdpr_requests table ─────────────────────────────────
// Tracks every export and deletion request for audit / compliance.
try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS gdpr_requests (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id     INTEGER NOT NULL,
      type        TEXT    NOT NULL CHECK(type IN ('export', 'deletion')),
      status      TEXT    NOT NULL DEFAULT 'pending'
                          CHECK(status IN ('pending', 'completed', 'cancelled', 'expired')),
      token       TEXT    UNIQUE,
      expires_at  TEXT,
      completed_at TEXT,
      ip_address  TEXT,
      user_agent  TEXT,
      created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
} catch (_err) {
  // Table may already exist — non-fatal
}

// ── Helpers ──────────────────────────────────────────────────────────

/** Collect all data belonging to a single user, structured for portability. */
function collectUserData(userId) {
  const user = db.prepare(`
    SELECT id, name, email, plan, avatar, avatar_bg,
           created_at, last_login, login_count, last_settings_change,
           oauth_provider, email_verified, totp_enabled
    FROM users WHERE id = ?
  `).get(userId);

  if (!user) return null;

  // Strip sensitive internal fields
  delete user.totp_enabled;

  const settings = db.prepare(`
    SELECT price_alerts, weekly_newsletter, dark_mode,
           notify_email, notify_inapp, notify_push
    FROM user_settings WHERE user_id = ?
  `).get(userId) || {};

  let notifications = [];
  try {
    notifications = db.prepare(`
      SELECT type, title, message, read, created_at
      FROM notifications WHERE user_id = ?
      ORDER BY created_at DESC
    `).all(userId);
  } catch (_) { /* table may not exist */ }

  let alertRules = [];
  try {
    alertRules = db.prepare(`
      SELECT product, direction, threshold, active, triggered,
             last_triggered_at, created_at
      FROM price_alert_rules WHERE user_id = ?
      ORDER BY created_at DESC
    `).all(userId);
  } catch (_) { /* table may not exist */ }

  let pushSubscriptions = [];
  try {
    pushSubscriptions = db.prepare(`
      SELECT endpoint, created_at
      FROM push_subscriptions WHERE user_id = ?
      ORDER BY created_at DESC
    `).all(userId);
  } catch (_) { /* table may not exist */ }

  return {
    exportedAt: new Date().toISOString(),
    dataController: {
      name: 'OIL Benchmarks',
      contact: process.env.GDPR_CONTACT_EMAIL || 'privacy@oilbenchmarks.com',
      purpose: 'This file contains all personal data we hold about you, '
             + 'exported per GDPR Article 20 (Right to Data Portability).',
    },
    profile: user,
    settings: settings,
    notifications: notifications,
    priceAlertRules: alertRules,
    pushSubscriptions: pushSubscriptions,
  };
}

/** Generate a secure random token for deletion confirmation. */
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ── GET /api/user/gdpr/export ────────────────────────────────────────
// Generates and downloads a JSON file with all data belonging to the
// authenticated user. Machine-readable for portability (Article 20).

router.get('/export', (req, res) => {
  try {
    const userId = req.session.userId;
    const data = collectUserData(userId);

    if (!data) {
      return fail(res, 404, 'User not found.');
    }

    // Record the export request for audit
    try {
      db.prepare(`
        INSERT INTO gdpr_requests (user_id, type, status, completed_at, ip_address, user_agent)
        VALUES (?, 'export', 'completed', datetime('now'), ?, ?)
      `).run(userId, req.ip, (req.headers['user-agent'] || '').substring(0, 500));
    } catch (_) { /* audit insert non-fatal */ }

    log.info(
      { audit: true, action: 'gdpr-export', userId },
      'GDPR: user data export downloaded'
    );

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = 'my-data-' + timestamp + '.json';

    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
    res.setHeader('Cache-Control', 'no-store');
    res.json(data);
  } catch (err) {
    log.error({ err, userId: req.session.userId }, 'GDPR data export failed');
    fail(res, 500, 'Data export failed. Please try again or contact support.');
  }
});

// ── GET /api/user/gdpr/export-status ─────────────────────────────────
// Returns a list of past export requests for the current user.

router.get('/export-status', (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT id, type, status, created_at, completed_at
      FROM gdpr_requests
      WHERE user_id = ? AND type = 'export'
      ORDER BY created_at DESC
      LIMIT 20
    `).all(req.session.userId);

    ok(res, { requests: rows });
  } catch (err) {
    log.error({ err }, 'Failed to fetch export status');
    fail(res, 500, 'Could not retrieve export history.');
  }
});

// ── POST /api/user/gdpr/delete-request ───────────────────────────────
// Initiates an account deletion request with a 72-hour cooling-off
// period. Returns a confirmation token that must be passed to the
// confirm endpoint. This two-step flow prevents accidental deletions
// and satisfies the "clear affirmative action" requirement.
//
// The user can cancel during the cooling-off window.
// After 72 hours without confirmation, the request expires.

router.post('/delete-request', (req, res) => {
  try {
    const userId = req.session.userId;

    // Prevent admin self-deletion
    const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(userId);
    if (user && user.plan === 'Admin') {
      return fail(res, 403, 'Admin accounts cannot be deleted via self-service.');
    }

    // Check for an existing pending deletion request
    const existing = db.prepare(`
      SELECT id, created_at, expires_at FROM gdpr_requests
      WHERE user_id = ? AND type = 'deletion' AND status = 'pending'
      ORDER BY created_at DESC LIMIT 1
    `).get(userId);

    if (existing) {
      return ok(res, {
        message: 'A deletion request is already pending.',
        requestId: existing.id,
        expiresAt: existing.expires_at,
      });
    }

    const token = generateToken();
    const coolingOffHours = parseInt(process.env.GDPR_COOLING_OFF_HOURS, 10) || 72;

    db.prepare(`
      INSERT INTO gdpr_requests (user_id, type, status, token, expires_at, ip_address, user_agent)
      VALUES (?, 'deletion', 'pending', ?, datetime('now', '+${coolingOffHours} hours'), ?, ?)
    `).run(
      userId,
      token,
      req.ip,
      (req.headers['user-agent'] || '').substring(0, 500)
    );

    log.warn(
      { audit: true, action: 'gdpr-delete-request', userId, coolingOffHours },
      'GDPR: account deletion requested'
    );

    ok(res, {
      message: 'Deletion request created. You have ' + coolingOffHours +
               ' hours to confirm or cancel. After confirmation, all your data '
             + 'will be permanently erased.',
      confirmationToken: token,
      coolingOffHours: coolingOffHours,
      confirmEndpoint: '/api/user/gdpr/delete-confirm',
      cancelEndpoint: '/api/user/gdpr/delete-cancel',
    });
  } catch (err) {
    log.error({ err, userId: req.session.userId }, 'GDPR deletion request failed');
    fail(res, 500, 'Could not process deletion request.');
  }
});

// ── POST /api/user/gdpr/delete-confirm ───────────────────────────────
// Confirms and executes the account deletion. Requires the token from
// the delete-request step. This is the "clear affirmative action".
//
// Performs the same complete data erasure as DELETE /api/auth/account.

router.post('/delete-confirm', (req, res) => {
  try {
    const userId = req.session.userId;
    const { token } = req.body || {};

    if (!token || typeof token !== 'string') {
      return fail(res, 400, 'Confirmation token is required.');
    }

    // Find the matching pending request
    const request = db.prepare(`
      SELECT id, user_id, expires_at FROM gdpr_requests
      WHERE token = ? AND user_id = ? AND type = 'deletion' AND status = 'pending'
    `).get(token, userId);

    if (!request) {
      return fail(res, 404, 'No matching pending deletion request found.');
    }

    // Check expiry
    if (new Date(request.expires_at) < new Date()) {
      db.prepare("UPDATE gdpr_requests SET status = 'expired' WHERE id = ?")
        .run(request.id);
      return fail(res, 410, 'Deletion request has expired. Please submit a new request.');
    }

    // Prevent admin self-deletion (double-check)
    const user = db.prepare('SELECT plan, avatar FROM users WHERE id = ?').get(userId);
    if (user && user.plan === 'Admin') {
      return fail(res, 403, 'Admin accounts cannot be deleted.');
    }

    // ── Complete data erasure (matches DELETE /api/auth/account) ──
    const eraseUser = db.transaction((uid) => {
      db.prepare('DELETE FROM notifications WHERE user_id = ?').run(uid);
      db.prepare('DELETE FROM push_subscriptions WHERE user_id = ?').run(uid);
      db.prepare('DELETE FROM price_alert_rules WHERE user_id = ?').run(uid);
      db.prepare('DELETE FROM email_verification_tokens WHERE user_id = ?').run(uid);
      db.prepare('DELETE FROM password_reset_tokens WHERE user_id = ?').run(uid);
      db.prepare('DELETE FROM user_settings WHERE user_id = ?').run(uid);
      db.prepare(
        "DELETE FROM sessions WHERE json_extract(sess, '$.userId') = ?" +
        " OR sess LIKE '%\"userId\":' || ? || ',%'" +
        " OR sess LIKE '%\"userId\":' || ? || '}%'"
      ).run(uid, uid, uid);
      db.prepare('DELETE FROM users WHERE id = ?').run(uid);
      // Mark the GDPR request as completed (keeps the audit trail)
      db.prepare(`
        UPDATE gdpr_requests SET status = 'completed', completed_at = datetime('now')
        WHERE id = ?
      `).run(request.id);
    });
    eraseUser(userId);

    // Avatar cleanup after transaction
    if (user && user.avatar) {
      try {
        const { safeDeleteAvatar } = require('./user');
        safeDeleteAvatar(user.avatar);
      } catch (_) { /* non-fatal */ }
    }

    log.warn(
      { audit: true, action: 'gdpr-delete-confirm', userId, requestId: request.id },
      'GDPR: account permanently deleted'
    );

    // Destroy session
    req.session.destroy((err) => {
      if (err) {
        log.error({ err }, 'Session destroy failed after GDPR deletion');
      }
      res.clearCookie(req.app.locals.sessionCookieName || 'sid', { path: '/' });
      ok(res, null, 'Your account and all associated data have been permanently deleted.');
    });
  } catch (err) {
    log.error({ err, userId: req.session.userId }, 'GDPR deletion confirmation failed');
    fail(res, 500, 'Deletion failed. Please contact support.');
  }
});

// ── POST /api/user/gdpr/delete-cancel ────────────────────────────────
// Cancels a pending deletion request during the cooling-off window.

router.post('/delete-cancel', (req, res) => {
  try {
    const userId = req.session.userId;
    const { token } = req.body || {};

    if (!token || typeof token !== 'string') {
      return fail(res, 400, 'Confirmation token is required.');
    }

    const result = db.prepare(`
      UPDATE gdpr_requests SET status = 'cancelled'
      WHERE token = ? AND user_id = ? AND type = 'deletion' AND status = 'pending'
    `).run(token, userId);

    if (result.changes === 0) {
      return fail(res, 404, 'No matching pending deletion request found.');
    }

    log.info(
      { audit: true, action: 'gdpr-delete-cancel', userId },
      'GDPR: account deletion request cancelled'
    );

    ok(res, null, 'Deletion request cancelled. Your account will not be deleted.');
  } catch (err) {
    log.error({ err, userId: req.session.userId }, 'GDPR deletion cancel failed');
    fail(res, 500, 'Could not cancel the request.');
  }
});

// ── GET /api/user/gdpr/delete-status ─────────────────────────────────
// Returns the current deletion request status (if any).

router.get('/delete-status', (req, res) => {
  try {
    const request = db.prepare(`
      SELECT id, status, created_at, expires_at, completed_at
      FROM gdpr_requests
      WHERE user_id = ? AND type = 'deletion'
      ORDER BY created_at DESC LIMIT 1
    `).get(req.session.userId);

    ok(res, { request: request || null });
  } catch (err) {
    log.error({ err }, 'Failed to fetch deletion status');
    fail(res, 500, 'Could not retrieve deletion status.');
  }
});

// ── Background: expire stale requests ────────────────────────────────
// Call this from your existing background job (e.g. the cron in index.js).
function expireStaleRequests() {
  try {
    const result = db.prepare(`
      UPDATE gdpr_requests SET status = 'expired'
      WHERE type = 'deletion' AND status = 'pending'
        AND expires_at < datetime('now')
    `).run();
    if (result.changes > 0) {
      log.info({ expired: result.changes }, 'GDPR: expired stale deletion requests');
    }
  } catch (_) { /* non-fatal */ }
}

// ── Exports ──────────────────────────────────────────────────────────
module.exports = router;
module.exports.expireStaleRequests = expireStaleRequests;
module.exports.collectUserData = collectUserData;
