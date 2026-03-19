const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const db = require('../db');

const router = express.Router();

// Multer config for avatar uploads
const uploadDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase() || '.jpg';
    const name = crypto.randomBytes(16).toString('hex') + ext;
    cb(null, name);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2 MB
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
      'SELECT price_alerts, weekly_newsletter, dark_mode FROM user_settings WHERE user_id = ?'
    ).get(req.session.userId);

    if (!settings) {
      // Create default settings if missing
      db.prepare(
        'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode) VALUES (?, 1, 0, 1)'
      ).run(req.session.userId);

      return res.json({
        priceAlerts: true,
        weeklyNewsletter: false,
        darkMode: true
      });
    }

    res.json({
      priceAlerts: !!settings.price_alerts,
      weeklyNewsletter: !!settings.weekly_newsletter,
      darkMode: !!settings.dark_mode
    });
  } catch (err) {
    console.error('Get settings error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// PUT /api/user/settings
router.put('/settings', requireAuth, (req, res) => {
  try {
    const { priceAlerts, weeklyNewsletter, darkMode } = req.body;

    // Ensure row exists
    const existing = db.prepare(
      'SELECT user_id FROM user_settings WHERE user_id = ?'
    ).get(req.session.userId);

    if (!existing) {
      db.prepare(
        'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode) VALUES (?, ?, ?, ?)'
      ).run(
        req.session.userId,
        priceAlerts !== undefined ? (priceAlerts ? 1 : 0) : 1,
        weeklyNewsletter !== undefined ? (weeklyNewsletter ? 1 : 0) : 0,
        darkMode !== undefined ? (darkMode ? 1 : 0) : 1
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

      if (updates.length > 0) {
        params.push(req.session.userId);
        db.prepare(
          `UPDATE user_settings SET ${updates.join(', ')} WHERE user_id = ?`
        ).run(...params);
      }
    }

    // Return updated settings
    const settings = db.prepare(
      'SELECT price_alerts, weekly_newsletter, dark_mode FROM user_settings WHERE user_id = ?'
    ).get(req.session.userId);

    res.json({
      message: 'Settings updated successfully.',
      priceAlerts: !!settings.price_alerts,
      weeklyNewsletter: !!settings.weekly_newsletter,
      darkMode: !!settings.dark_mode
    });
  } catch (err) {
    console.error('Update settings error:', err);
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
    db.prepare('UPDATE users SET avatar_bg = ? WHERE id = ?').run(avatarBg || null, req.session.userId);
    res.json({ message: 'Avatar background updated.', avatarBg: avatarBg || null });
  } catch (e) {
    console.error('Avatar bg error:', e);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// POST /api/user/avatar — upload avatar
router.post('/avatar', requireAuth, (req, res) => {
  upload.single('avatar')(req, res, (err) => {
    if (err) {
      const msg = err.code === 'LIMIT_FILE_SIZE' ? 'File too large. Max 2 MB.' : err.message;
      return res.status(400).json({ error: msg });
    }
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded.' });
    }

    try {
      // Delete old avatar file if exists
      const user = db.prepare('SELECT avatar FROM users WHERE id = ?').get(req.session.userId);
      if (user && user.avatar) {
        const oldPath = path.join(uploadDir, user.avatar);
        if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
      }

      // Save new avatar filename
      db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(req.file.filename, req.session.userId);

      res.json({
        message: 'Avatar uploaded successfully.',
        avatar: '/uploads/' + req.file.filename
      });
    } catch (e) {
      console.error('Avatar upload error:', e);
      res.status(500).json({ error: 'Internal server error.' });
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
    console.error('Avatar delete error:', e);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

module.exports = router;
