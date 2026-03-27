const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const sharp = require('sharp');
const db = require('../db');
const log = require('../logger').child({ module: 'user' });
const webPush = require('../utils/web-push');

const router = express.Router();

// Upload directory
const uploadDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// Avatar config
const AVATAR_MAX_SIZE = 256;     // px — output square
const AVATAR_QUALITY = 80;       // WebP quality (1-100)
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
    return res.status(401).json({ error: 'Not authenticated.' });
  }
  next();
}

// GET /api/user/settings
router.get('/settings', requireAuth, (req, res) => {
  try {
    const settings = db.prepare(
      'SELECT price_alerts, weekly_newsletter, dark_mode, notify_email, notify_inapp, notify_push FROM user_settings WHERE user_id = ?'
    ).get(req.session.userId);

    if (!settings) {
      // Create default settings if missing
      db.prepare(
        'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode, notify_email, notify_inapp, notify_push) VALUES (?, 1, 0, 1, 0, 1, 1)'
      ).run(req.session.userId);

      return res.json({
        priceAlerts: true,
        weeklyNewsletter: false,
        darkMode: true,
        notifyEmail: false,
        notifyInapp: true,
        notifyPush: true
      });
    }

    res.json({
      priceAlerts: !!settings.price_alerts,
      weeklyNewsletter: !!settings.weekly_newsletter,
      darkMode: !!settings.dark_mode,
      notifyEmail: !!settings.notify_email,
      notifyInapp: settings.notify_inapp !== undefined ? !!settings.notify_inapp : true,
      notifyPush: settings.notify_push !== undefined ? !!settings.notify_push : true
    });
  } catch (err) {
    log.error({ err }, 'Get settings failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// PUT /api/user/settings
router.put('/settings', requireAuth, (req, res) => {
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

    // Track last settings change
    db.prepare(
      "UPDATE users SET last_settings_change = datetime('now') WHERE id = ?"
    ).run(req.session.userId);

    // Return updated settings
    const settings = db.prepare(
      'SELECT price_alerts, weekly_newsletter, dark_mode, notify_email, notify_inapp, notify_push FROM user_settings WHERE user_id = ?'
    ).get(req.session.userId);

    res.json({
      message: 'Settings updated successfully.',
      priceAlerts: !!settings.price_alerts,
      weeklyNewsletter: !!settings.weekly_newsletter,
      darkMode: !!settings.dark_mode,
      notifyEmail: !!settings.notify_email,
      notifyInapp: settings.notify_inapp !== undefined ? !!settings.notify_inapp : true,
      notifyPush: settings.notify_push !== undefined ? !!settings.notify_push : true
    });
  } catch (err) {
    log.error({ err }, 'Update settings failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// PUT /api/user/profile — update user profile (name)
router.put('/profile', requireAuth, (req, res) => {
  try {
    const { name } = req.body;

    if (!name || typeof name !== 'string' || !name.trim()) {
      return res.status(400).json({ error: 'Name is required.' });
    }

    const trimmed = name.replace(/<[^>]*>/g, '').trim();
    if (!trimmed || trimmed.length === 0) {
      return res.status(400).json({ error: 'Name must contain valid characters.' });
    }
    if (trimmed.length > 100) {
      return res.status(400).json({ error: 'Name must be 100 characters or fewer.' });
    }

    db.prepare('UPDATE users SET name = ? WHERE id = ?').run(trimmed, req.session.userId);

    const user = db.prepare(
      'SELECT id, name, email, plan, avatar, avatar_bg, created_at FROM users WHERE id = ?'
    ).get(req.session.userId);

    res.json({
      message: 'Profile updated.',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        plan: user.plan,
        avatar: user.avatar ? '/uploads/' + user.avatar : null,
        avatarBg: user.avatar_bg || null,
        joinedDate: user.created_at
      }
    });
  } catch (err) {
    log.error({ err }, 'Update profile failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// PUT /api/user/avatar-bg — save avatar background color
router.put('/avatar-bg', requireAuth, (req, res) => {
  try {
    const { avatarBg } = req.body;
    if (avatarBg !== null && typeof avatarBg !== 'string') {
      return res.status(400).json({ error: 'Invalid avatar background.' });
    }
    // Sanitize: only allow safe CSS color/gradient values (no url(), expression(), javascript:)
    if (avatarBg) {
      const lower = avatarBg.toLowerCase().replace(/\s/g, '');
      if (/url\(|expression\(|javascript:|data:|@import|behavior:|;/.test(lower)) {
        return res.status(400).json({ error: 'Invalid avatar background value.' });
      }
    }
    db.prepare('UPDATE users SET avatar_bg = ? WHERE id = ?').run(avatarBg || null, req.session.userId);
    res.json({ message: 'Avatar background updated.', avatarBg: avatarBg || null });
  } catch (e) {
    log.error({ err: e }, 'Avatar background update failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// POST /api/user/avatar — upload avatar (resized & compressed via sharp)
router.post('/avatar', requireAuth, (req, res) => {
  upload.single('avatar')(req, res, async (err) => {
    if (err) {
      const msg = err.code === 'LIMIT_FILE_SIZE' ? 'File too large. Max 5 MB.' : err.message;
      return res.status(400).json({ error: msg });
    }
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded.' });
    }

    try {
      // Process image: resize to 256x256, convert to WebP
      const filename = crypto.randomBytes(16).toString('hex') + '.webp';
      const outputPath = path.join(uploadDir, filename);

      await sharp(req.file.buffer)
        .rotate()                                  // auto-orient from EXIF
        .resize(AVATAR_MAX_SIZE, AVATAR_MAX_SIZE, {
          fit: 'cover',                            // crop to square
          position: 'centre'
        })
        .webp({ quality: AVATAR_QUALITY })
        .toFile(outputPath);

      // Delete old avatar file if exists
      const user = db.prepare('SELECT avatar FROM users WHERE id = ?').get(req.session.userId);
      if (user && user.avatar) {
        const oldPath = path.join(uploadDir, user.avatar);
        if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
      }

      // Save new avatar filename
      db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(filename, req.session.userId);

      res.json({
        message: 'Avatar uploaded successfully.',
        avatar: '/uploads/' + filename
      });
    } catch (e) {
      log.error({ err: e }, 'Avatar upload failed');
      res.status(500).json({ error: 'Failed to process image.' });
    }
  });
});

// DELETE /api/user/avatar — remove avatar
router.delete('/avatar', requireAuth, (req, res) => {
  try {
    const user = db.prepare('SELECT avatar FROM users WHERE id = ?').get(req.session.userId);
    if (user && user.avatar) {
      const filePath = path.join(uploadDir, user.avatar);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      db.prepare('UPDATE users SET avatar = NULL WHERE id = ?').run(req.session.userId);
    }
    res.json({ message: 'Avatar removed.' });
  } catch (e) {
    log.error({ err: e }, 'Avatar delete failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// ─── Price Alert Rules ──────────────────────────────────────────

const VALID_PRODUCTS = ['WTI', 'BRENT', 'HO', 'GAS'];
const MAX_ALERTS_PER_USER = 20;

// GET /api/user/alerts — list user's alert rules
router.get('/alerts', requireAuth, (req, res) => {
  try {
    const alerts = db.prepare(
      'SELECT id, product, direction, threshold, active, triggered, last_triggered_at, created_at FROM price_alert_rules WHERE user_id = ? ORDER BY created_at DESC'
    ).all(req.session.userId);
    res.json({ alerts });
  } catch (err) {
    log.error({ err }, 'Get alerts failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// POST /api/user/alerts — create a new alert rule
router.post('/alerts', requireAuth, (req, res) => {
  try {
    const { product, direction, threshold } = req.body;

    if (!product || !VALID_PRODUCTS.includes(product)) {
      return res.status(400).json({ error: 'Product must be one of: ' + VALID_PRODUCTS.join(', ') });
    }
    if (direction !== 'above' && direction !== 'below') {
      return res.status(400).json({ error: 'Direction must be "above" or "below".' });
    }
    const price = parseFloat(threshold);
    if (isNaN(price) || price <= 0 || price > 999999) {
      return res.status(400).json({ error: 'Threshold must be a positive number.' });
    }

    // Check limit
    const count = db.prepare('SELECT COUNT(*) as c FROM price_alert_rules WHERE user_id = ?').get(req.session.userId);
    if (count.c >= MAX_ALERTS_PER_USER) {
      return res.status(400).json({ error: 'Maximum ' + MAX_ALERTS_PER_USER + ' alerts allowed.' });
    }

    const result = db.prepare(
      'INSERT INTO price_alert_rules (user_id, product, direction, threshold) VALUES (?, ?, ?, ?)'
    ).run(req.session.userId, product, direction, price);

    const alert = db.prepare('SELECT * FROM price_alert_rules WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json({ message: 'Alert created.', alert });
  } catch (err) {
    log.error({ err }, 'Create alert failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// DELETE /api/user/alerts/:id — delete an alert rule
router.delete('/alerts/:id', requireAuth, (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid alert ID.' });

    const alert = db.prepare('SELECT id FROM price_alert_rules WHERE id = ? AND user_id = ?').get(id, req.session.userId);
    if (!alert) return res.status(404).json({ error: 'Alert not found.' });

    db.prepare('DELETE FROM price_alert_rules WHERE id = ?').run(id);
    res.json({ message: 'Alert deleted.' });
  } catch (err) {
    log.error({ err }, 'Delete alert failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// POST /api/user/alerts/check — check prices against active alerts, return triggered ones
// Called by the frontend with current prices; marks alerts as triggered
router.post('/alerts/check', requireAuth, (req, res) => {
  try {
    const { prices } = req.body;
    // prices = { WTI: 72.50, BRENT: 76.10, ... }
    if (!prices || typeof prices !== 'object') {
      return res.status(400).json({ error: 'prices object required.' });
    }

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
          'UPDATE price_alert_rules SET triggered = 1, last_triggered_at = ? WHERE id = ?'
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

    res.json({ triggered });

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
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// POST /api/user/alerts/:id/reset — re-arm a triggered alert
router.post('/alerts/:id/reset', requireAuth, (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid alert ID.' });

    const alert = db.prepare('SELECT id FROM price_alert_rules WHERE id = ? AND user_id = ?').get(id, req.session.userId);
    if (!alert) return res.status(404).json({ error: 'Alert not found.' });

    db.prepare('UPDATE price_alert_rules SET triggered = 0, last_triggered_at = NULL WHERE id = ?').run(id);
    res.json({ message: 'Alert re-armed.' });
  } catch (err) {
    log.error({ err }, 'Reset alert failed');
    res.status(500).json({ error: 'Internal server error.' });
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

// GET /api/user/notifications — list notifications (newest first, paginated)
router.get('/notifications', requireAuth, (req, res) => {
  try {
    const { page, limit, offset } = parsePagination(req.query);
    const total = db.prepare(
      'SELECT COUNT(*) as c FROM notifications WHERE user_id = ?'
    ).get(req.session.userId).c;
    const notifications = db.prepare(
      'SELECT id, type, title, message, read, created_at FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?'
    ).all(req.session.userId, limit, offset);
    const unreadCount = db.prepare(
      'SELECT COUNT(*) as c FROM notifications WHERE user_id = ? AND read = 0'
    ).get(req.session.userId).c;
    res.json({ notifications, unreadCount, page, limit, total, totalPages: Math.ceil(total / limit) });
  } catch (err) {
    log.error({ err }, 'Get notifications failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// PUT /api/user/notifications/read-all — mark all as read
router.put('/notifications/read-all', requireAuth, (req, res) => {
  try {
    db.prepare('UPDATE notifications SET read = 1 WHERE user_id = ? AND read = 0').run(req.session.userId);
    res.json({ message: 'All notifications marked as read.' });
  } catch (err) {
    log.error({ err }, 'Mark all read failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// PUT /api/user/notifications/:id/read — mark one as read
router.put('/notifications/:id/read', requireAuth, (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid notification ID.' });
    const notif = db.prepare('SELECT id FROM notifications WHERE id = ? AND user_id = ?').get(id, req.session.userId);
    if (!notif) return res.status(404).json({ error: 'Notification not found.' });
    db.prepare('UPDATE notifications SET read = 1 WHERE id = ?').run(id);
    res.json({ message: 'Notification marked as read.' });
  } catch (err) {
    log.error({ err }, 'Mark notification read failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// DELETE /api/user/notifications/:id — delete a notification
router.delete('/notifications/:id', requireAuth, (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid notification ID.' });
    const notif = db.prepare('SELECT id FROM notifications WHERE id = ? AND user_id = ?').get(id, req.session.userId);
    if (!notif) return res.status(404).json({ error: 'Notification not found.' });
    db.prepare('DELETE FROM notifications WHERE id = ?').run(id);
    res.json({ message: 'Notification deleted.' });
  } catch (err) {
    log.error({ err }, 'Delete notification failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// DELETE /api/user/notifications — clear all notifications
router.delete('/notifications', requireAuth, (req, res) => {
  try {
    db.prepare('DELETE FROM notifications WHERE user_id = ?').run(req.session.userId);
    res.json({ message: 'All notifications cleared.' });
  } catch (err) {
    log.error({ err }, 'Clear notifications failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// ── Web Push API ───────────────────────────────────────────────────

// GET /api/user/push/vapid-key — return the VAPID public key
router.get('/push/vapid-key', (req, res) => {
  res.json({ publicKey: webPush.getPublicKey() });
});

// POST /api/user/push/subscribe — save a push subscription
router.post('/push/subscribe', requireAuth, (req, res) => {
  try {
    const { subscription } = req.body;
    if (!subscription || !subscription.endpoint || !subscription.keys) {
      return res.status(400).json({ error: 'Invalid push subscription.' });
    }
    webPush.saveSubscription(req.session.userId, subscription);
    res.json({ message: 'Push subscription saved.' });
  } catch (err) {
    log.error({ err }, 'Push subscribe failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// POST /api/user/push/unsubscribe — remove a push subscription
router.post('/push/unsubscribe', requireAuth, (req, res) => {
  try {
    const { endpoint } = req.body;
    if (!endpoint) {
      return res.status(400).json({ error: 'Endpoint is required.' });
    }
    webPush.removeSubscription(endpoint);
    res.json({ message: 'Push subscription removed.' });
  } catch (err) {
    log.error({ err }, 'Push unsubscribe failed');
    res.status(500).json({ error: 'Internal server error.' });
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
    res.json({ message: sent > 0 ? 'Test notification sent.' : 'No active push subscriptions found.', sent });
  } catch (err) {
    log.error({ err }, 'Push test failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

module.exports = router;
