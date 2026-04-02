const express = require('express');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const sharp = require('sharp');
const db = require('../db/db');
const log = require('../utils/logger').child({ module: 'user' });
const webPush = require('../utils/web-push');
const { ok, created, paginated, fail, noContent, conditionalOk } = require('../utils/response');
const { validate, schemas } = require('../utils/validate');

const router = express.Router();

// Upload directory
const uploadDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

/**
 * Safely delete an avatar file and its thumbnail from the uploads directory.
 * Rejects any filename that would resolve outside uploadDir (path traversal).
 */
function safeDeleteAvatar(avatarFilename) {
  if (!avatarFilename || typeof avatarFilename !== 'string') return;
  const base = path.basename(avatarFilename);
  if (base !== avatarFilename) {
    log.warn({ avatarFilename }, 'Path traversal blocked in avatar filename');
    return;
  }
  const fullPath = path.resolve(uploadDir, base);
  if (!fullPath.startsWith(uploadDir + path.sep)) return;
  if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
  // Thumbnail
  const thumbName = base.replace('.webp', '_thumb.webp');
  const thumbPath = path.resolve(uploadDir, thumbName);
  if (thumbPath.startsWith(uploadDir + path.sep) && fs.existsSync(thumbPath)) {
    fs.unlinkSync(thumbPath);
  }
}

// Avatar config
const AVATAR_MAX_SIZE = 256;     // px — full-size output square
const AVATAR_THUMB_SIZE = 48;    // px — thumbnail for compact UI (notifications, admin lists)
const AVATAR_QUALITY = 80;       // WebP quality for full avatar (1-100)
const AVATAR_THUMB_QUALITY = 72; // WebP quality for thumbnail (slightly more aggressive)
const AVATAR_EFFORT = 4;         // WebP compression effort (0-6, higher = smaller file / slower encode)
const AVATAR_MAX_UPLOAD = 5 * 1024 * 1024; // 5 MB raw upload limit (compressed output will be much smaller)

// Multer uses memory storage — file goes to buffer, sharp processes it, then we write the result
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: AVATAR_MAX_UPLOAD },
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) cb(null, true);
    else cb(new Error('Only image files are allowed.'));
  }
});

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return fail(res, 401, 'Not authenticated.');
  }
  next();
}

// ── Cross-device sync infrastructure ─────────────────────────────────
// Every mutation to user preferences (settings, profile, avatar) bumps a
// monotonically increasing `sync_version` counter in user_settings.
// Other devices poll GET /api/user/sync/check with their last-known version;
// if the server version is higher, the device fetches the full state bundle
// from GET /api/user/sync.  This avoids transferring the full payload on
// every poll — only the integer comparison travels the wire until a real
// change is detected.

// Migration: add sync_version column if missing
const settingsColsSync = db.prepare("PRAGMA table_info(user_settings)").all().map(c => c.name);
if (!settingsColsSync.includes('sync_version')) {
  db.exec("ALTER TABLE user_settings ADD COLUMN sync_version INTEGER NOT NULL DEFAULT 1");
  log.info('Migration: added sync_version column to user_settings');
}

// Bump the sync version for a user — call after any preference mutation
function bumpSyncVersion(userId) {
  db.prepare(
    "UPDATE user_settings SET sync_version = sync_version + 1 WHERE user_id = ?"
  ).run(userId);
  // Also update last_settings_change timestamp on the users table
  db.prepare(
    "UPDATE users SET last_settings_change = datetime('now') WHERE id = ?"
  ).run(userId);
}

// Return the current sync version for a user (0 if no settings row yet)
function getSyncVersion(userId) {
  const row = db.prepare('SELECT sync_version FROM user_settings WHERE user_id = ?').get(userId);
  return row ? row.sync_version : 0;
}

// Attach X-Sync-Version header to a response
function setSyncHeader(res, version) {
  res.setHeader('X-Sync-Version', version);
}

// GET /api/user/settings
router.get('/settings', requireAuth, (req, res) => {
  try {
    const settings = db.prepare(
      'SELECT price_alerts, weekly_newsletter, dark_mode, notify_email, notify_inapp, notify_push, sync_version FROM user_settings WHERE user_id = ?'
    ).get(req.session.userId);

    if (!settings) {
      // Create default settings if missing
      db.prepare(
        'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode, notify_email, notify_inapp, notify_push) VALUES (?, TRUE, FALSE, TRUE, FALSE, TRUE, TRUE)'
      ).run(req.session.userId);

      setSyncHeader(res, 1);
      return conditionalOk(req, res, {
        priceAlerts: true,
        weeklyNewsletter: false,
        darkMode: true,
        notifyEmail: false,
        notifyInapp: true,
        notifyPush: true
      }, { etag: 'settings-' + req.session.userId + '-v1' });
    }

    setSyncHeader(res, settings.sync_version);
    conditionalOk(req, res, {
      priceAlerts: !!settings.price_alerts,
      weeklyNewsletter: !!settings.weekly_newsletter,
      darkMode: !!settings.dark_mode,
      notifyEmail: !!settings.notify_email,
      notifyInapp: settings.notify_inapp !== undefined ? !!settings.notify_inapp : true,
      notifyPush: settings.notify_push !== undefined ? !!settings.notify_push : true
    }, { etag: 'settings-' + req.session.userId + '-v' + settings.sync_version });
  } catch (err) {
    log.error({ err }, 'Get settings failed');
    fail(res, 500, 'Internal server error.');
  }
});

// PUT /api/user/settings
router.put('/settings', requireAuth, validate(schemas.updateSettings), (req, res) => {
  try {
    const { priceAlerts, weeklyNewsletter, darkMode, notifyEmail, notifyInapp, notifyPush } = req.body;

    // Ensure row exists
    const existing = db.prepare(
      'SELECT user_id FROM user_settings WHERE user_id = ?'
    ).get(req.session.userId);

    if (!existing) {
      db.prepare(
        'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode, notify_email, notify_inapp, notify_push) VALUES (?, ?, ?, ?, ?, ?, ?)'
      ).run(
        req.session.userId,
        priceAlerts !== undefined ? (priceAlerts ? 1 : 0) : 1,
        weeklyNewsletter !== undefined ? (weeklyNewsletter ? 1 : 0) : 0,
        darkMode !== undefined ? (darkMode ? 1 : 0) : 1,
        notifyEmail !== undefined ? (notifyEmail ? 1 : 0) : 0,
        notifyInapp !== undefined ? (notifyInapp ? 1 : 0) : 1,
        notifyPush !== undefined ? (notifyPush ? 1 : 0) : 1
      );
    } else {
      const updates = [];
      const params = [];

      if (priceAlerts !== undefined) {
        updates.push('price_alerts = ?');
        params.push(priceAlerts ? 1 : 0);
      }
      if (weeklyNewsletter !== undefined) {
        updates.push('weekly_newsletter = ?');
        params.push(weeklyNewsletter ? 1 : 0);
      }
      if (darkMode !== undefined) {
        updates.push('dark_mode = ?');
        params.push(darkMode ? 1 : 0);
      }
      if (notifyEmail !== undefined) {
        updates.push('notify_email = ?');
        params.push(notifyEmail ? 1 : 0);
      }
      if (notifyInapp !== undefined) {
        updates.push('notify_inapp = ?');
        params.push(notifyInapp ? 1 : 0);
      }
      if (notifyPush !== undefined) {
        updates.push('notify_push = ?');
        params.push(notifyPush ? 1 : 0);
      }

      if (updates.length > 0) {
        params.push(req.session.userId);
        db.prepare(
          `UPDATE user_settings SET ${updates.join(', ')} WHERE user_id = ?`
        ).run(...params);
      }
    }

    // Bump sync version so other devices detect the change
    bumpSyncVersion(req.session.userId);

    // Return updated settings
    const settings = db.prepare(
      'SELECT price_alerts, weekly_newsletter, dark_mode, notify_email, notify_inapp, notify_push, sync_version FROM user_settings WHERE user_id = ?'
    ).get(req.session.userId);

    setSyncHeader(res, settings.sync_version);
    ok(res, {
      priceAlerts: !!settings.price_alerts,
      weeklyNewsletter: !!settings.weekly_newsletter,
      darkMode: !!settings.dark_mode,
      notifyEmail: !!settings.notify_email,
      notifyInapp: settings.notify_inapp !== undefined ? !!settings.notify_inapp : true,
      notifyPush: settings.notify_push !== undefined ? !!settings.notify_push : true
    }, 'Settings updated successfully.');
  } catch (err) {
    log.error({ err }, 'Update settings failed');
    fail(res, 500, 'Internal server error.');
  }
});

// PUT /api/user/profile — update user profile (name)
router.put('/profile', requireAuth, validate(schemas.updateProfile), (req, res) => {
  try {
    // name is already sanitized (HTML-stripped, trimmed, length-checked) by Zod
    const trimmed = req.body.name;

    db.prepare('UPDATE users SET name = ? WHERE id = ?').run(trimmed, req.session.userId);
    bumpSyncVersion(req.session.userId);

    const user = db.prepare(
      'SELECT id, name, email, plan, avatar, avatar_bg, created_at FROM users WHERE id = ?'
    ).get(req.session.userId);

    ok(res, {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        plan: user.plan,
        avatar: user.avatar ? '/uploads/' + user.avatar : null,
        avatarBg: user.avatar_bg || null,
        joinedDate: user.created_at
      }
    }, 'Profile updated.');
  } catch (err) {
    log.error({ err }, 'Update profile failed');
    fail(res, 500, 'Internal server error.');
  }
});

// PUT /api/user/avatar-bg — save avatar background color
router.put('/avatar-bg', requireAuth, validate(schemas.updateAvatarBg), (req, res) => {
  try {
    const { avatarBg } = req.body;
    db.prepare('UPDATE users SET avatar_bg = ? WHERE id = ?').run(avatarBg || null, req.session.userId);
    bumpSyncVersion(req.session.userId);
    ok(res, { avatarBg: avatarBg || null }, 'Avatar background updated.');
  } catch (e) {
    log.error({ err: e }, 'Avatar background update failed');
    fail(res, 500, 'Internal server error.');
  }
});

// POST /api/user/avatar — upload avatar (resized & compressed via sharp)
// Pipeline: buffer → strip metadata → resize → WebP encode → atomic swap
//
// Crash-safety: new files are written to .tmp paths first, then the DB is
// updated and the temp files are atomically renamed to their final names.
// Old avatar files are deleted only after the rename succeeds.  If the
// server crashes at any point:
//   - Before rename: only .tmp files exist; they are harmless orphans that
//     a periodic cleanup or the next upload can remove.
//   - After rename, before old-file deletion: the DB already points to the
//     new filename, so the old files are orphaned but the state is consistent.
//     The next upload for this user will delete them via safeDeleteAvatar().

// Rate limiter for avatar uploads — each upload triggers multipart parsing,
// buffering up to 5 MB, and two sharp resize/encode pipelines (CPU-bound).
// Without a limit, an authenticated user can saturate disk I/O and the
// sharp thread pool by spamming large image uploads in rapid succession.
//
// 5 uploads per 15-minute window per user is generous for legitimate use
// (profile photo experimentation) while stopping floods.  Keyed by userId
// so one abusive session cannot affect other users' upload ability.
const avatarUploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,                     // 5 uploads per window
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.session.userId || req.ip,
  message: { error: 'Too many avatar uploads. Please wait before trying again.' },
  handler: (req, res, next, options) => {
    const retryAfter = req.rateLimit && req.rateLimit.resetTime
      ? Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000)
      : Math.ceil(options.windowMs / 1000);
    res.setHeader('Retry-After', Math.max(retryAfter, 1));
    res.status(429).json(options.message);
  },
});

router.post('/avatar', requireAuth, avatarUploadLimiter, (req, res) => {
  upload.single('avatar')(req, res, async (err) => {
    if (err) {
      const msg = err.code === 'LIMIT_FILE_SIZE' ? 'File too large. Max 5 MB.' : err.message;
      return fail(res, 400, msg);
    }
    if (!req.file) {
      return fail(res, 400, 'No file uploaded.');
    }

    const baseName = crypto.randomBytes(16).toString('hex');
    const filename = baseName + '.webp';
    const thumbFilename = baseName + '_thumb.webp';
    const outputPath = path.join(uploadDir, filename);
    const thumbPath = path.join(uploadDir, thumbFilename);
    // Temp paths — written first, renamed atomically after DB update
    const tmpOutputPath = outputPath + '.tmp';
    const tmpThumbPath = thumbPath + '.tmp';

    let oldAvatarFilename = null;

    try {
      // Shared base: auto-orient from EXIF, then strip all metadata (privacy + smaller file)
      const normalized = sharp(req.file.buffer)
        .rotate()                                  // auto-orient from EXIF
        .withMetadata(false);                      // strip EXIF, ICC, XMP — prevents location/device leaks

      // Run full-size and thumbnail pipelines in parallel to temp paths
      // (both use .clone() so they decode the source buffer independently
      // in sharp's thread pool)
      await Promise.all([
        // Full-size avatar (256x256 WebP)
        normalized
          .clone()
          .resize(AVATAR_MAX_SIZE, AVATAR_MAX_SIZE, {
            fit: 'cover',                            // crop to square
            position: 'centre'
          })
          .webp({ quality: AVATAR_QUALITY, effort: AVATAR_EFFORT })
          .toFile(tmpOutputPath),

        // Thumbnail (48x48 WebP) — used in notifications, admin user lists, compact views
        normalized
          .clone()
          .resize(AVATAR_THUMB_SIZE, AVATAR_THUMB_SIZE, {
            fit: 'cover',
            position: 'centre'
          })
          .webp({ quality: AVATAR_THUMB_QUALITY, effort: AVATAR_EFFORT })
          .toFile(tmpThumbPath),
      ]);

      // Read old avatar filename before updating — we'll delete it after rename
      const user = db.prepare('SELECT avatar FROM users WHERE id = ?').get(req.session.userId);
      if (user && user.avatar) {
        oldAvatarFilename = user.avatar;
      }

      // Update DB first (synchronous with better-sqlite3, so it's atomic)
      db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(filename, req.session.userId);
      bumpSyncVersion(req.session.userId);

      // Atomic rename: temp → final (same filesystem, so rename is atomic)
      await fs.promises.rename(tmpOutputPath, outputPath);
      await fs.promises.rename(tmpThumbPath, thumbPath);

      // Now safe to delete old avatar files — DB already points to new ones
      if (oldAvatarFilename) {
        try {
          safeDeleteAvatar(oldAvatarFilename);
        } catch (cleanupErr) {
          // Non-fatal: old files become orphans, cleaned up on next upload or by maintenance
          log.warn({ err: cleanupErr, oldAvatarFilename }, 'Failed to delete old avatar files');
        }
      }

      const [stats, thumbStats] = await Promise.all([
        fs.promises.stat(outputPath),
        fs.promises.stat(thumbPath),
      ]);
      log.info({
        userId: req.session.userId,
        fullSizeKB: +(stats.size / 1024).toFixed(1),
        thumbKB: +(thumbStats.size / 1024).toFixed(1),
        originalKB: +(req.file.size / 1024).toFixed(1),
      }, 'Avatar optimized and saved');

      ok(res, {
        avatar: '/uploads/' + filename,
        thumbnail: '/uploads/' + thumbFilename
      }, 'Avatar uploaded successfully.');
    } catch (e) {
      // Clean up temp files if they were written before the failure
      for (const tmp of [tmpOutputPath, tmpThumbPath]) {
        try { fs.unlinkSync(tmp); } catch (_) { /* may not exist yet */ }
      }
      log.error({ err: e }, 'Avatar upload failed');
      fail(res, 500, 'Failed to process image.');
    }
  });
});

// DELETE /api/user/avatar — remove avatar (full + thumbnail)
router.delete('/avatar', requireAuth, (req, res) => {
  try {
    const user = db.prepare('SELECT avatar FROM users WHERE id = ?').get(req.session.userId);
    if (user && user.avatar) {
      safeDeleteAvatar(user.avatar);
      db.prepare('UPDATE users SET avatar = NULL WHERE id = ?').run(req.session.userId);
      bumpSyncVersion(req.session.userId);
    }
    ok(res, null, 'Avatar removed.');
  } catch (e) {
    log.error({ err: e }, 'Avatar delete failed');
    fail(res, 500, 'Internal server error.');
  }
});

// ─── Cross-device Preferences Sync ──────────────────────────────────

// GET /api/user/sync/check — lightweight version check for polling
// Returns only the current sync_version integer. Devices compare this to
// their last-known version; if it differs, they fetch the full state bundle.
// Designed to be called frequently (e.g. every 30-60s) with minimal overhead.
router.get('/sync/check', requireAuth, (req, res) => {
  try {
    const version = getSyncVersion(req.session.userId);
    setSyncHeader(res, version);
    ok(res, { syncVersion: version });
  } catch (err) {
    log.error({ err }, 'Sync check failed');
    fail(res, 500, 'Internal server error.');
  }
});

// GET /api/user/sync — full state bundle for cross-device sync
// Returns profile, settings, avatar, and alert rules in a single payload.
// Called when a device detects its sync_version is stale, or on initial load
// of a new device session. Avoids multiple round-trips to separate endpoints.
router.get('/sync', requireAuth, (req, res) => {
  try {
    const userId = req.session.userId;

    // Profile
    const user = db.prepare(
      'SELECT id, name, email, plan, avatar, avatar_bg, created_at, oauth_provider, email_verified, last_settings_change FROM users WHERE id = ?'
    ).get(userId);

    if (!user) {
      return fail(res, 401, 'User not found.');
    }

    // Settings (ensure row exists)
    let settings = db.prepare(
      'SELECT price_alerts, weekly_newsletter, dark_mode, notify_email, notify_inapp, notify_push, sync_version FROM user_settings WHERE user_id = ?'
    ).get(userId);

    if (!settings) {
      db.prepare(
        'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode, notify_email, notify_inapp, notify_push) VALUES (?, TRUE, FALSE, TRUE, FALSE, TRUE, TRUE)'
      ).run(userId);
      settings = db.prepare(
        'SELECT price_alerts, weekly_newsletter, dark_mode, notify_email, notify_inapp, notify_push, sync_version FROM user_settings WHERE user_id = ?'
      ).get(userId);
    }

    // Active alert rules
    const alerts = db.prepare(
      'SELECT id, product, direction, threshold, active, triggered, last_triggered_at, created_at FROM price_alert_rules WHERE user_id = ? ORDER BY created_at DESC'
    ).all(userId);

    // Unread notification count (not the full list — keeps payload small)
    const unreadCount = db.prepare(
      'SELECT COUNT(*) as c FROM notifications WHERE user_id = ? AND read = 0'
    ).get(userId).c;

    setSyncHeader(res, settings.sync_version);
    ok(res, {
      syncVersion: settings.sync_version,
      lastChanged: user.last_settings_change,
      profile: {
        id: user.id,
        name: user.name,
        email: user.email,
        plan: user.plan,
        avatar: user.avatar ? '/uploads/' + user.avatar : null,
        avatarBg: user.avatar_bg || null,
        joinedDate: user.created_at,
        oauthProvider: user.oauth_provider || null,
        emailVerified: !!user.email_verified,
      },
      settings: {
        priceAlerts: !!settings.price_alerts,
        weeklyNewsletter: !!settings.weekly_newsletter,
        darkMode: !!settings.dark_mode,
        notifyEmail: !!settings.notify_email,
        notifyInapp: settings.notify_inapp !== undefined ? !!settings.notify_inapp : true,
        notifyPush: settings.notify_push !== undefined ? !!settings.notify_push : true,
      },
      alerts,
      unreadNotifications: unreadCount,
    });
  } catch (err) {
    log.error({ err }, 'Full sync failed');
    fail(res, 500, 'Internal server error.');
  }
});

// ─── Price Alert Rules ──────────────────────────────────────────

const VALID_PRODUCTS = ['WTI', 'BRENT', 'HO', 'GAS'];
const MAX_ALERTS_PER_USER = 20;

// GET /api/user/alerts — list user's alert rules (cursor-paginated)
// Query params:
//   cursor  — id of the last item from the previous page (omit for first page)
//   limit   — items per page (default 20, max 100)
router.get('/alerts', requireAuth, (req, res) => {
  try {
    const MAX_LIMIT = 100;
    let limit = parseInt(req.query.limit, 10) || 20;
    if (limit < 1) limit = 1;
    if (limit > MAX_LIMIT) limit = MAX_LIMIT;

    const cursor = parseInt(req.query.cursor, 10) || null;
    const userId = req.session.userId;

    let alerts;
    if (cursor) {
      alerts = db.prepare(
        'SELECT id, product, direction, threshold, active, triggered, last_triggered_at, created_at FROM price_alert_rules WHERE user_id = ? AND id < ? ORDER BY id DESC LIMIT ?'
      ).all(userId, cursor, limit + 1);
    } else {
      alerts = db.prepare(
        'SELECT id, product, direction, threshold, active, triggered, last_triggered_at, created_at FROM price_alert_rules WHERE user_id = ? ORDER BY id DESC LIMIT ?'
      ).all(userId, limit + 1);
    }

    const hasMore = alerts.length > limit;
    if (hasMore) alerts = alerts.slice(0, limit);

    const nextCursor = alerts.length > 0 ? alerts[alerts.length - 1].id : null;

    res.json({
      ok: true,
      data: { alerts },
      cursor: { next: hasMore ? nextCursor : null, hasMore }
    });
  } catch (err) {
    log.error({ err }, 'Get alerts failed');
    fail(res, 500, 'Internal server error.');
  }
});

// POST /api/user/alerts — create a new alert rule
router.post('/alerts', requireAuth, validate(schemas.createAlert), (req, res) => {
  try {
    const { product, direction, threshold } = req.body;
    // threshold is already parsed and validated as a positive number by Zod
    const price = threshold;

    // Check limit
    const count = db.prepare('SELECT COUNT(*) as c FROM price_alert_rules WHERE user_id = ?').get(req.session.userId);
    if (count.c >= MAX_ALERTS_PER_USER) {
      return fail(res, 400, 'Maximum ' + MAX_ALERTS_PER_USER + ' alerts allowed.');
    }

    const result = db.prepare(
      'INSERT INTO price_alert_rules (user_id, product, direction, threshold) VALUES (?, ?, ?, ?)'
    ).run(req.session.userId, product, direction, price);

    const alert = db.prepare('SELECT * FROM price_alert_rules WHERE id = ?').get(result.lastInsertRowid);
    created(res, { alert }, 'Alert created.');
  } catch (err) {
    log.error({ err }, 'Create alert failed');
    fail(res, 500, 'Internal server error.');
  }
});

// DELETE /api/user/alerts/:id — delete an alert rule
router.delete('/alerts/:id', requireAuth, validate(schemas.idParam, 'params'), (req, res) => {
  try {
    const id = req.params.id;

    const alert = db.prepare('SELECT id FROM price_alert_rules WHERE id = ? AND user_id = ?').get(id, req.session.userId);
    if (!alert) return fail(res, 404, 'Alert not found.');

    db.prepare('DELETE FROM price_alert_rules WHERE id = ?').run(id);
    ok(res, null, 'Alert deleted.');
  } catch (err) {
    log.error({ err }, 'Delete alert failed');
    fail(res, 500, 'Internal server error.');
  }
});

// POST /api/user/alerts/check — check prices against active alerts, return triggered ones
// Called by the frontend with current prices; marks alerts as triggered
router.post('/alerts/check', requireAuth, validate(schemas.checkAlertPrices), (req, res) => {
  try {
    const { prices } = req.body;
    // prices = { WTI: 72.50, BRENT: 76.10, ... }

    const alerts = db.prepare(
      'SELECT id, product, direction, threshold FROM price_alert_rules WHERE user_id = ? AND active = 1 AND triggered = 0'
    ).all(req.session.userId);

    const triggered = [];
    const now = new Date().toISOString();

    for (const a of alerts) {
      const currentPrice = parseFloat(prices[a.product]);
      if (isNaN(currentPrice)) continue;

      const hit = (a.direction === 'above' && currentPrice >= a.threshold) ||
                  (a.direction === 'below' && currentPrice <= a.threshold);

      if (hit) {
        db.prepare(
          'UPDATE price_alert_rules SET triggered = TRUE, last_triggered_at = ? WHERE id = ?'
        ).run(now, a.id);
        triggered.push({
          id: a.id,
          product: a.product,
          direction: a.direction,
          threshold: a.threshold,
          currentPrice
        });
      }
    }

    ok(res, { triggered });

    // Send push notifications for triggered alerts (async, non-blocking)
    if (triggered.length > 0) {
      const userSettings = db.prepare('SELECT notify_push FROM user_settings WHERE user_id = ?').get(req.session.userId);
      if (userSettings && userSettings.notify_push) {
        for (const tr of triggered) {
          const unit = (tr.product === 'HO' || tr.product === 'GAS') ? '/gal' : '/bbl';
          webPush.sendToUser(req.session.userId, {
            title: 'Price Alert: ' + tr.product,
            body: tr.product + ' is now $' + tr.currentPrice.toFixed(2) + unit
              + ' (' + tr.direction + ' $' + tr.threshold.toFixed(2) + ')',
            icon: '/icons/icon-192.svg',
            tag: 'price-alert-' + tr.id,
            data: { url: '/' }
          }).catch(function(err) { log.error({ err }, 'Push send failed for price alert'); });
        }
      }
    }
  } catch (err) {
    log.error({ err }, 'Check alerts failed');
    fail(res, 500, 'Internal server error.');
  }
});

// POST /api/user/alerts/:id/reset — re-arm a triggered alert
router.post('/alerts/:id/reset', requireAuth, validate(schemas.idParam, 'params'), (req, res) => {
  try {
    const id = req.params.id;

    const alert = db.prepare('SELECT id FROM price_alert_rules WHERE id = ? AND user_id = ?').get(id, req.session.userId);
    if (!alert) return fail(res, 404, 'Alert not found.');

    db.prepare('UPDATE price_alert_rules SET triggered = FALSE, last_triggered_at = NULL WHERE id = ?').run(id);
    ok(res, null, 'Alert re-armed.');
  } catch (err) {
    log.error({ err }, 'Reset alert failed');
    fail(res, 500, 'Internal server error.');
  }
});

// ─── Notifications ────────────────────────────────────────────────

const MAX_NOTIFICATIONS = 50; // max stored per user

// Pagination helper (mirrors admin.js — defaults: page 1, limit 30, max 100)
function parsePagination(query, defaultLimit = 30) {
  const MAX_LIMIT = 100;
  let page = parseInt(query.page, 10) || 1;
  let limit = parseInt(query.limit, 10) || defaultLimit;
  if (page < 1) page = 1;
  if (limit < 1) limit = 1;
  if (limit > MAX_LIMIT) limit = MAX_LIMIT;
  const offset = (page - 1) * limit;
  return { page, limit, offset };
}

// GET /api/user/notifications — list notifications (newest first, cursor-paginated)
// Query params:
//   cursor  — id of the last item from the previous page (omit for first page)
//   limit   — items per page (default 30, max 100)
//   (legacy: page + limit still supported if cursor is absent)
router.get('/notifications', requireAuth, (req, res) => {
  try {
    const MAX_LIMIT = 100;
    let limit = parseInt(req.query.limit, 10) || 30;
    if (limit < 1) limit = 1;
    if (limit > MAX_LIMIT) limit = MAX_LIMIT;

    const cursor = parseInt(req.query.cursor, 10) || null;
    const userId = req.session.userId;

    let notifications;
    if (cursor) {
      // Cursor-based: fetch items with id < cursor (descending)
      notifications = db.prepare(
        'SELECT id, type, title, message, read, created_at FROM notifications WHERE user_id = ? AND id < ? ORDER BY id DESC LIMIT ?'
      ).all(userId, cursor, limit + 1);
    } else if (req.query.page) {
      // Legacy offset-based fallback
      const { page, limit: pLimit, offset } = parsePagination(req.query);
      const total = db.prepare(
        'SELECT COUNT(*) as c FROM notifications WHERE user_id = ?'
      ).get(userId).c;
      notifications = db.prepare(
        'SELECT id, type, title, message, read, created_at FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT ? OFFSET ?'
      ).all(userId, pLimit, offset);
      const unreadCount = db.prepare(
        'SELECT COUNT(*) as c FROM notifications WHERE user_id = ? AND read = 0'
      ).get(userId).c;
      return res.json({ ok: true, data: notifications, unreadCount, pagination: { page, limit: pLimit, total, totalPages: Math.ceil(total / pLimit) } });
    } else {
      // First page (no cursor, no page param)
      notifications = db.prepare(
        'SELECT id, type, title, message, read, created_at FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT ?'
      ).all(userId, limit + 1);
    }

    // Determine if there are more items beyond this page
    const hasMore = notifications.length > limit;
    if (hasMore) notifications = notifications.slice(0, limit);

    const nextCursor = notifications.length > 0 ? notifications[notifications.length - 1].id : null;

    const unreadCount = db.prepare(
      'SELECT COUNT(*) as c FROM notifications WHERE user_id = ? AND read = 0'
    ).get(userId).c;

    res.json({
      ok: true,
      data: notifications,
      unreadCount,
      cursor: { next: hasMore ? nextCursor : null, hasMore }
    });
  } catch (err) {
    log.error({ err }, 'Get notifications failed');
    fail(res, 500, 'Internal server error.');
  }
});

// PUT /api/user/notifications/read-all — mark all as read
router.put('/notifications/read-all', requireAuth, (req, res) => {
  try {
    db.prepare('UPDATE notifications SET read = TRUE WHERE user_id = ? AND read = FALSE').run(req.session.userId);
    ok(res, null, 'All notifications marked as read.');
  } catch (err) {
    log.error({ err }, 'Mark all read failed');
    fail(res, 500, 'Internal server error.');
  }
});

// PUT /api/user/notifications/:id/read — mark one as read
router.put('/notifications/:id/read', requireAuth, validate(schemas.idParam, 'params'), (req, res) => {
  try {
    const id = req.params.id;
    const notif = db.prepare('SELECT id FROM notifications WHERE id = ? AND user_id = ?').get(id, req.session.userId);
    if (!notif) return fail(res, 404, 'Notification not found.');
    db.prepare('UPDATE notifications SET read = TRUE WHERE id = ?').run(id);
    ok(res, null, 'Notification marked as read.');
  } catch (err) {
    log.error({ err }, 'Mark notification read failed');
    fail(res, 500, 'Internal server error.');
  }
});

// DELETE /api/user/notifications/:id — delete a notification
router.delete('/notifications/:id', requireAuth, validate(schemas.idParam, 'params'), (req, res) => {
  try {
    const id = req.params.id;
    const notif = db.prepare('SELECT id FROM notifications WHERE id = ? AND user_id = ?').get(id, req.session.userId);
    if (!notif) return fail(res, 404, 'Notification not found.');
    db.prepare('DELETE FROM notifications WHERE id = ?').run(id);
    ok(res, null, 'Notification deleted.');
  } catch (err) {
    log.error({ err }, 'Delete notification failed');
    fail(res, 500, 'Internal server error.');
  }
});

// DELETE /api/user/notifications — clear all notifications
router.delete('/notifications', requireAuth, (req, res) => {
  try {
    db.prepare('DELETE FROM notifications WHERE user_id = ?').run(req.session.userId);
    ok(res, null, 'All notifications cleared.');
  } catch (err) {
    log.error({ err }, 'Clear notifications failed');
    fail(res, 500, 'Internal server error.');
  }
});

// ── Web Push API ───────────────────────────────────────────────────

// GET /api/user/push/vapid-key — return the VAPID public key
router.get('/push/vapid-key', (req, res) => {
  ok(res, { publicKey: webPush.getPublicKey() });
});

// POST /api/user/push/subscribe — save a push subscription
const pushSubscribeLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,                   // 10 requests per window per user
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.session.userId || req.ip,
  message: { error: 'Too many subscription requests. Try again later.' },
  handler: (req, res, next, options) => {
    const retryAfter = req.rateLimit && req.rateLimit.resetTime
      ? Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000)
      : Math.ceil(options.windowMs / 1000);
    res.setHeader('Retry-After', Math.max(retryAfter, 1));
    res.status(429).json(options.message);
  },
});
router.post('/push/subscribe', requireAuth, pushSubscribeLimit, validate(schemas.pushSubscribe), (req, res) => {
  try {
    const { subscription } = req.body;
    webPush.saveSubscription(req.session.userId, subscription);
    ok(res, null, 'Push subscription saved.');
  } catch (err) {
    log.error({ err }, 'Push subscribe failed');
    fail(res, 500, 'Internal server error.');
  }
});

// POST /api/user/push/unsubscribe — remove a push subscription
router.post('/push/unsubscribe', requireAuth, validate(schemas.pushUnsubscribe), (req, res) => {
  try {
    const { endpoint } = req.body;
    webPush.removeSubscription(endpoint);
    ok(res, null, 'Push subscription removed.');
  } catch (err) {
    log.error({ err }, 'Push unsubscribe failed');
    fail(res, 500, 'Internal server error.');
  }
});

// POST /api/user/push/test — send a test push notification to current user
router.post('/push/test', requireAuth, async (req, res) => {
  try {
    const sent = await webPush.sendToUser(req.session.userId, {
      title: 'OIL Benchmarks',
      body: 'Push notifications are working!',
      icon: '/icons/icon-192.svg',
      tag: 'test-push'
    });
    ok(res, { sent }, sent > 0 ? 'Test notification sent.' : 'No active push subscriptions found.');
  } catch (err) {
    log.error({ err }, 'Push test failed');
    fail(res, 500, 'Internal server error.');
  }
});

module.exports = router;
module.exports.safeDeleteAvatar = safeDeleteAvatar;
