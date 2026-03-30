const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const db = require('../db/db');
const log = require('../utils/logger').child({ module: 'auth' });
const { getTransporter, getFromAddress } = require('../utils/mailer');
const { getSafeOrigin } = require('../utils/safe-origin');

const router = express.Router();

// HTML entity escaping for server-rendered templates (emails, admin pages).
// Prevents XSS when interpolating user-supplied strings into HTML context.
function escHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ─── TOTP two-factor authentication helpers (otpauth library) ───
const { TOTP, Secret } = require('otpauth');

const TOTP_ISSUER = 'OIL Benchmarks';
const TOTP_DIGITS = 6;
const TOTP_PERIOD = 30;
const TOTP_WINDOW  = 1; // accept ±1 time-step (previous, current, next)

// ── Base32 validation ──────────────────────────────────────────
// RFC 4648 base32 alphabet. We explicitly validate secrets before passing
// them to the library so that malformed values (e.g. a corrupted DB row)
// produce a clear, early error instead of silently decoding to wrong bytes
// or throwing an opaque TypeError deep in the TOTP constructor.
const BASE32_ALPHABET = /^[A-Z2-7]+=*$/;

/**
 * Validates that `str` is a well-formed RFC 4648 base32 string.
 * Accepts upper-case letters A-Z, digits 2-7, optional trailing '=' padding,
 * and optional spaces (which some authenticator apps insert for readability).
 * Throws a descriptive error on any invalid input.
 */
function validateBase32(str) {
  if (typeof str !== 'string' || str.length === 0) {
    throw new Error('TOTP secret must be a non-empty base32 string');
  }
  // Strip spaces (some issuers add them for readability) and normalise case
  const cleaned = str.replace(/ /g, '').toUpperCase();
  if (!BASE32_ALPHABET.test(cleaned)) {
    // Find the first offending character for a useful error message
    const bad = cleaned.split('').find(c => !/[A-Z2-7=]/.test(c));
    throw new Error(`Invalid base32 character: '${bad}' in TOTP secret`);
  }
  // Padding must only appear at the end and be correct length (0, 1, 3, 4, or 6 '=' chars)
  const paddingMatch = cleaned.match(/=+$/);
  if (paddingMatch) {
    const padLen = paddingMatch[0].length;
    const validPadLengths = [0, 1, 3, 4, 6];
    if (!validPadLengths.includes(padLen)) {
      throw new Error(`Invalid base32 padding: ${padLen} '=' characters`);
    }
  }
  return cleaned;
}

function _makeTOTP(secret, label) {
  const cleaned = validateBase32(secret);
  return new TOTP({
    issuer: TOTP_ISSUER,
    label: label || '',
    algorithm: 'SHA1',
    digits: TOTP_DIGITS,
    period: TOTP_PERIOD,
    secret: Secret.fromBase32(cleaned),
  });
}

function generateTOTPSecret() {
  // 20-byte (160-bit) secret, matching RFC 4226 recommendation for SHA-1
  return new Secret({ size: 20 }).base32;
}

function verifyTOTP(secret, token) {
  const totp = _makeTOTP(secret);
  // Returns null on failure, or a delta integer on success.
  // The library uses timing-safe comparison internally.
  return totp.validate({ token, window: TOTP_WINDOW }) !== null;
}

// ─── Token hashing helper ────────────────────────────────────────
// Password reset tokens are stored as SHA-256 hashes so a DB leak
// doesn't expose usable tokens.
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// ─── Honeypot anti-bot protection ───────────────────────────────
// Invisible form fields that real users never fill in.  Bots that blindly
// populate every field will trigger the trap.  We check two fields:
//   • "website"  — classic honeypot (looks like a normal optional field)
//   • "confirm_email" — looks like an email-confirmation field
// If either field contains a value the request is silently rejected with a
// generic success-looking response so the bot doesn't know it was caught.
function rejectIfHoneypot(req, res) {
  const hp1 = req.body.website;
  const hp2 = req.body.confirm_email;
  if ((hp1 !== undefined && hp1 !== '') || (hp2 !== undefined && hp2 !== '')) {
    // Log only safe metadata — never log raw honeypot values, as attackers
    // may stuff XSS payloads that could execute in a log viewer.
    log.warn(
      { ip: req.ip, path: req.originalUrl, honeypot: { websiteLen: hp1 ? hp1.length : 0, confirmEmailLen: hp2 ? hp2.length : 0 } },
      'Honeypot field filled — likely bot submission'
    );
    return true;   // caller should return a decoy response
  }
  return false;
}

// In test mode, bypass rate limiters
const isTest = process.env.NODE_ENV === 'test';
const noopLimiter = (req, res, next) => next();

// ─── Account lockout configuration ─────────────────────────────
const LOGIN_MAX_ATTEMPTS = parseInt(process.env.LOGIN_MAX_ATTEMPTS, 10) || 5;
const LOGIN_LOCKOUT_MINUTES = parseInt(process.env.LOGIN_LOCKOUT_MINUTES, 10) || 15;
const CAPTCHA_THRESHOLD = parseInt(process.env.CAPTCHA_THRESHOLD, 10) || 2; // show captcha after this many fails

// ─── Password-reset velocity configuration ──────────────────────
// Per-account: max resets in a rolling window before we suppress and warn
const RESET_VELOCITY_MAX     = parseInt(process.env.RESET_VELOCITY_MAX, 10) || 3;
const RESET_VELOCITY_WINDOW  = parseInt(process.env.RESET_VELOCITY_WINDOW_MIN, 10) || 60; // minutes
// Per-IP: track reset requests across all accounts from the same IP
const RESET_IP_MAX           = parseInt(process.env.RESET_IP_MAX, 10) || 5;
const RESET_IP_WINDOW        = parseInt(process.env.RESET_IP_WINDOW_MIN, 10) || 60; // minutes

// In-memory sliding-window tracker for per-IP reset velocity.
// Map<ip, timestamp[]>  — cleaned up lazily on each check.
const resetIpLog = new Map();

function checkResetIpVelocity(ip) {
  const now = Date.now();
  const windowMs = RESET_IP_WINDOW * 60 * 1000;
  let timestamps = resetIpLog.get(ip) || [];
  // Evict entries outside the window
  timestamps = timestamps.filter(ts => now - ts < windowMs);
  timestamps.push(now);
  resetIpLog.set(ip, timestamps);
  // Periodic cleanup: drop IPs with empty arrays every ~100 calls
  if (Math.random() < 0.01) {
    for (const [k, v] of resetIpLog) {
      if (v.length === 0 || now - v[v.length - 1] > windowMs) resetIpLog.delete(k);
    }
  }
  return timestamps.length > RESET_IP_MAX;
}

function checkResetAccountVelocity(userId) {
  const cutoff = new Date(Date.now() - RESET_VELOCITY_WINDOW * 60 * 1000).toISOString();
  const row = db.prepare(
    'SELECT COUNT(*) AS cnt FROM password_reset_tokens WHERE user_id = ? AND created_at >= ?'
  ).get(userId, cutoff);
  return (row.cnt || 0) >= RESET_VELOCITY_MAX;
}

// ─── CAPTCHA generation helpers ─────────────────────────────────
// Generates a math challenge whose answer space is large enough that
// brute-forcing all possible answers is impractical within the rate-limit
// window.  With the ranges below the answer space spans ~10,000+ values.
function generateCaptchaChallenge() {
  const ops = ['+', '-', '\u00d7', '+', '-'];  // weighted toward +/- (simpler UX)
  const op = ops[Math.floor(Math.random() * ops.length)];
  let a, b, answer;
  if (op === '+') {
    a = Math.floor(Math.random() * 900) + 100;   // 100–999
    b = Math.floor(Math.random() * 900) + 100;    // 100–999
    answer = a + b;                                // 200–1998
  } else if (op === '-') {
    a = Math.floor(Math.random() * 900) + 100;    // 100–999
    b = Math.floor(Math.random() * (a - 1)) + 1;  // 1–(a-1)
    answer = a - b;                                // 1–998
  } else {
    // multiplication with one large and one small operand keeps the
    // arithmetic human-doable while expanding the answer space
    a = Math.floor(Math.random() * 90) + 10;      // 10–99
    b = Math.floor(Math.random() * 9) + 2;        // 2–10
    answer = a * b;                                // 20–990
  }
  return { text: `${a} ${op} ${b} = ?`, answer };
}

function renderCaptchaSVG(text) {
  const w = 240, h = 50;
  let paths = '';
  // Add noise lines
  for (let i = 0; i < 5; i++) {
    const x1 = Math.floor(Math.random() * w);
    const y1 = Math.floor(Math.random() * h);
    const x2 = Math.floor(Math.random() * w);
    const y2 = Math.floor(Math.random() * h);
    const c = `rgb(${60 + Math.floor(Math.random() * 80)},${60 + Math.floor(Math.random() * 80)},${60 + Math.floor(Math.random() * 80)})`;
    paths += `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${c}" stroke-width="1"/>`;
  }
  // Add noise dots
  for (let i = 0; i < 30; i++) {
    const cx = Math.floor(Math.random() * w);
    const cy = Math.floor(Math.random() * h);
    const c = `rgb(${80 + Math.floor(Math.random() * 100)},${80 + Math.floor(Math.random() * 100)},${80 + Math.floor(Math.random() * 100)})`;
    paths += `<circle cx="${cx}" cy="${cy}" r="1" fill="${c}"/>`;
  }
  // Render each character with slight rotation and offset
  const startX = 20;
  const charW = Math.floor((w - 40) / text.length);
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const x = startX + i * charW + Math.floor(Math.random() * 4) - 2;
    const y = 32 + Math.floor(Math.random() * 8) - 4;
    const rot = Math.floor(Math.random() * 20) - 10;
    const c = `rgb(${170 + Math.floor(Math.random() * 60)},${140 + Math.floor(Math.random() * 60)},${60 + Math.floor(Math.random() * 40)})`;
    paths += `<text x="${x}" y="${y}" font-family="monospace" font-size="22" font-weight="bold" fill="${c}" transform="rotate(${rot},${x},${y})">${ch === '&' ? '&amp;' : ch}</text>`;
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"><rect width="${w}" height="${h}" fill="#0a0a0a"/>${paths}</svg>`;
}

// ─── Rate limiters ──────────────────────────────────────────────
// Login: 5 attempts per 1 minute per IP
const loginLimiter = isTest ? noopLimiter : rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again in 1 minute.' },
  keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown'
});

// Register: 3 attempts per 60 minutes per IP (short window)
const registerLimiter = isTest ? noopLimiter : rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many accounts created from this IP. Please try again in 1 hour.' },
  keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown'
});

// Register daily cap: 10 accounts per 24 hours per IP (prevents sustained abuse)
const registerDailyLimiter = isTest ? noopLimiter : rateLimit({
  windowMs: 24 * 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Daily registration limit reached. Please try again tomorrow.' },
  keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown'
});

// Blocked email domains for registration (disposable/temp mail services)
const BLOCKED_EMAIL_DOMAINS = (process.env.BLOCKED_EMAIL_DOMAINS || '')
  .split(',')
  .map(d => d.trim().toLowerCase())
  .filter(Boolean);

// Forgot password: 3 attempts per 15 minutes per IP
const forgotLimiter = isTest ? noopLimiter : rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many password reset requests. Please try again in 15 minutes.' },
  keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown'
});

// Reset password (token submit): 5 attempts per 15 minutes per IP
const resetLimiter = isTest ? noopLimiter : rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many reset attempts. Please try again in 15 minutes.' },
  keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown'
});

// Password change: 5 attempts per 15 minutes per IP
const passwordChangeLimiter = isTest ? noopLimiter : rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many password change attempts. Please try again in 15 minutes.' },
  keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown'
});

// POST /api/auth/register
router.post('/register', registerLimiter, registerDailyLimiter, async (req, res) => {
  try {
    const { name, email, password, captchaAnswer } = req.body;

    // ── Honeypot check ──────────────────────────────────────────
    if (rejectIfHoneypot(req, res)) {
      return res.status(201).json({ message: 'Account created.' });
    }

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required.' });
    }

    // Sanitize name: strip HTML tags, trim, enforce length
    const cleanName = name.replace(/<[^>]*>/g, '').trim();
    if (!cleanName || cleanName.length === 0) {
      return res.status(400).json({ error: 'Name must contain valid characters.' });
    }
    if (cleanName.length > 100) {
      return res.status(400).json({ error: 'Name must be 100 characters or fewer.' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }

    // Validate email format and length
    const emailTrimmed = email.trim().toLowerCase();
    if (emailTrimmed.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailTrimmed)) {
      return res.status(400).json({ error: 'Please provide a valid email address.' });
    }

    // Block disposable / banned email domains
    //   — always block internal OAuth placeholder domains
    const domain = emailTrimmed.split('@')[1];
    if (domain && (domain === 'oauth.local' || domain === 'oauth.internal.noreply')) {
      return res.status(400).json({ error: 'Registration with this email domain is not allowed.' });
    }
    if (BLOCKED_EMAIL_DOMAINS.length > 0) {
      if (domain && BLOCKED_EMAIL_DOMAINS.includes(domain)) {
        return res.status(400).json({ error: 'Registration with this email domain is not allowed.' });
      }
    }

    // ── CAPTCHA required for all registrations ──────────────────
    // Skipped in test mode (rate limiters are also disabled in test mode)
    if (!isTest) {
      const sessionAnswer = req.session.captchaAnswer;
      const sessionTs = req.session.captchaTs || 0;
      // Clear captcha after check (one-time use)
      delete req.session.captchaAnswer;
      delete req.session.captchaTs;

      if (!captchaAnswer && captchaAnswer !== 0) {
        return res.status(400).json({
          error: 'Please complete the CAPTCHA challenge.',
          captchaRequired: true
        });
      }
      const captchaExpired = (Date.now() - sessionTs) > 5 * 60 * 1000;
      if (captchaExpired || sessionAnswer === undefined || parseInt(captchaAnswer, 10) !== sessionAnswer) {
        return res.status(400).json({
          error: 'Incorrect or expired CAPTCHA. Please try again.',
          captchaRequired: true
        });
      }
    }

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(emailTrimmed);
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare(
      'INSERT INTO users (name, email, password_hash, email_verified) VALUES (?, ?, ?, FALSE)'
    ).run(cleanName, emailTrimmed, hash);

    const userId = result.lastInsertRowid;

    // Create default settings for the new user
    db.prepare(
      'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode) VALUES (?, TRUE, FALSE, TRUE)'
    ).run(userId);

    // Generate verification token — invalidate any prior tokens for this user
    // so only the most recent token is usable (matches resend-verification logic).
    db.prepare('UPDATE email_verification_tokens SET used = TRUE WHERE user_id = ? AND used = FALSE').run(userId);

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24 hours

    db.prepare(
      'INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES (?, ?, ?)'
    ).run(userId, token, expiresAt);

    // Send verification email — use server-configured origin to prevent host header injection
    const origin = getSafeOrigin(req);
    const verifyUrl = `${origin}/verify-email?token=${token}`;

    try {
      const transporter = await getTransporter();
      const info = await transporter.sendMail({
        from: getFromAddress(),
        to: emailTrimmed,
        subject: 'Verify your email — OIL Benchmarks',
        text: `Welcome to OIL Benchmarks, ${cleanName}!\n\nPlease verify your email address by clicking the link below (valid for 24 hours):\n${verifyUrl}\n\nIf you did not create this account, you can ignore this email.`,
        html: `<div style="font-family:monospace;background:#0c0c0e;color:#e8e4dc;padding:30px;border-radius:8px;max-width:500px;margin:0 auto"><h2 style="color:#c9a84c;font-size:14px;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:16px">Email Verification</h2><p style="font-size:12px;line-height:1.6;color:#bbb">Welcome to OIL Benchmarks, <strong>${escHtml(cleanName)}</strong>!</p><p style="font-size:12px;line-height:1.6;color:#bbb">Please verify your email address by clicking the button below:</p><p style="text-align:center;margin:24px 0"><a href="${escHtml(verifyUrl)}" style="display:inline-block;padding:10px 24px;background:linear-gradient(135deg,#85783c,#c9a84c);color:#0c0c0e;font-weight:700;font-size:11px;letter-spacing:1px;text-transform:uppercase;text-decoration:none;border-radius:4px">Verify Email</a></p><p style="font-size:10px;color:#666;line-height:1.5">This link is valid for 24 hours. If you did not create this account, you can ignore this email.</p></div>`
      });

      if (!process.env.SMTP_HOST) {
        const previewUrl = nodemailer.getTestMessageUrl(info);
        if (previewUrl) log.info({ previewUrl }, 'Verification email preview (Ethereal)');
      }
    } catch (mailErr) {
      log.error({ err: mailErr }, 'Failed to send verification email');
      // Registration still succeeds — user can request a resend
    }

    // Set session — regenerate session ID to prevent session fixation
    req.session.regenerate((err) => {
      if (err) {
        log.error({ err }, 'Session regeneration failed during registration');
        return res.status(500).json({ error: 'Internal server error.' });
      }

      req.session.userId = userId;

      // Create welcome notification
      db.prepare(
        "INSERT INTO notifications (user_id, type, title, message) VALUES (?, 'info', 'Welcome!', 'Your account has been created. Explore your dashboard to set up alerts and preferences.')"
      ).run(userId);

      const user = db.prepare(
        'SELECT id, name, email, plan, avatar, avatar_bg, created_at, email_verified FROM users WHERE id = ?'
      ).get(userId);

      res.status(201).json({
        message: 'Account created. Please check your email to verify your address.',
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          plan: user.plan,
          avatar: user.avatar ? '/uploads/' + user.avatar : null,
          avatarBg: user.avatar_bg || null,
          joinedDate: user.created_at,
          emailVerified: !!user.email_verified
        }
      });
    });
  } catch (err) {
    log.error({ err }, 'Registration failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// GET /api/auth/captcha — generate a new CAPTCHA challenge
router.get('/captcha', (req, res) => {
  const challenge = generateCaptchaChallenge();
  req.session.captchaAnswer = challenge.answer;
  req.session.captchaTs = Date.now();
  const svg = renderCaptchaSVG(challenge.text);
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.send(svg);
});

// POST /api/auth/login
router.post('/login', loginLimiter, (req, res) => {
  try {
    const { email, password, rememberMe, captchaAnswer } = req.body;

    // ── Honeypot check ──────────────────────────────────────────
    if (rejectIfHoneypot(req, res)) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = db.prepare(
      'SELECT id, name, email, password_hash, plan, avatar, avatar_bg, created_at, failed_login_attempts, locked_until, totp_enabled, totp_secret FROM users WHERE email = ?'
    ).get(email);

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // ── Account lockout check ──────────────────────────────────
    if (user.locked_until) {
      const lockedUntil = new Date(user.locked_until);
      if (lockedUntil > new Date()) {
        const remainingMs = lockedUntil - new Date();
        const remainingMin = Math.ceil(remainingMs / 60000);
        return res.status(423).json({
          error: `Account is temporarily locked. Try again in ${remainingMin} minute${remainingMin !== 1 ? 's' : ''}.`,
          lockedUntil: user.locked_until,
          remainingMinutes: remainingMin
        });
      }
      // Lock has expired — clear it so the user can try again
      db.prepare('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?').run(user.id);
      user.failed_login_attempts = 0;
      user.locked_until = null;
    }

    // ── CAPTCHA check — required after CAPTCHA_THRESHOLD failed attempts ──
    // Skipped in test mode (rate limiters are also disabled in test mode)
    const needsCaptcha = !isTest && (user.failed_login_attempts || 0) >= CAPTCHA_THRESHOLD;
    if (needsCaptcha) {
      const sessionAnswer = req.session.captchaAnswer;
      const sessionTs = req.session.captchaTs || 0;
      // Clear captcha after check (one-time use)
      delete req.session.captchaAnswer;
      delete req.session.captchaTs;

      if (!captchaAnswer && captchaAnswer !== 0) {
        return res.status(400).json({
          error: 'Please complete the CAPTCHA challenge.',
          captchaRequired: true
        });
      }
      // Expire captcha after 5 minutes
      const captchaExpired = (Date.now() - sessionTs) > 5 * 60 * 1000;
      if (captchaExpired || sessionAnswer === undefined || parseInt(captchaAnswer, 10) !== sessionAnswer) {
        return res.status(400).json({
          error: 'Incorrect or expired CAPTCHA. Please try again.',
          captchaRequired: true
        });
      }
    }

    // OAuth-only accounts cannot log in with password
    if (user.password_hash === '__oauth_no_password__') {
      return res.status(401).json({ error: 'This account uses social login. Please sign in with Google or GitHub.' });
    }

    const valid = bcrypt.compareSync(password, user.password_hash);
    if (!valid) {
      // ── Increment failed attempts ────────────────────────────
      const attempts = (user.failed_login_attempts || 0) + 1;
      const remaining = LOGIN_MAX_ATTEMPTS - attempts;

      if (attempts >= LOGIN_MAX_ATTEMPTS) {
        // Lock the account
        const lockUntil = new Date(Date.now() + LOGIN_LOCKOUT_MINUTES * 60 * 1000).toISOString();
        db.prepare('UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?')
          .run(attempts, lockUntil, user.id);
        return res.status(423).json({
          error: `Too many failed attempts. Account locked for ${LOGIN_LOCKOUT_MINUTES} minutes.`,
          lockedUntil: lockUntil,
          remainingMinutes: LOGIN_LOCKOUT_MINUTES
        });
      }

      db.prepare('UPDATE users SET failed_login_attempts = ? WHERE id = ?')
        .run(attempts, user.id);

      // Include remaining attempts hint (but keep the generic error message)
      const hint = remaining <= 2
        ? ` (${remaining} attempt${remaining !== 1 ? 's' : ''} remaining before lockout)`
        : '';
      const resp = { error: 'Invalid email or password.' + hint };
      // Signal that next attempt needs CAPTCHA
      if (attempts >= CAPTCHA_THRESHOLD) resp.captchaRequired = true;
      return res.status(401).json(resp);
    }

    // ── Successful login — reset failed attempts ───────────────
    if (user.failed_login_attempts > 0 || user.locked_until) {
      db.prepare('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?').run(user.id);
    }

    // ── TOTP two-factor check ──────────────────────────────────
    if (user.totp_enabled) {
      const { totpToken } = req.body;
      if (!totpToken) {
        // Password correct but 2FA token needed — return pending state
        return res.json({
          totpRequired: true,
          message: 'Two-factor authentication code required.'
        });
      }
      if (!verifyTOTP(user.totp_secret, totpToken)) {
        return res.status(401).json({ error: 'Invalid two-factor authentication code.' });
      }
    }

    // Set session — regenerate session ID to prevent session fixation
    req.session.regenerate((err) => {
      if (err) {
        log.error({ err }, 'Session regeneration failed during login');
        return res.status(500).json({ error: 'Internal server error.' });
      }

      req.session.userId = user.id;

      // Track login activity
      db.prepare(
        "UPDATE users SET last_login = datetime('now'), login_count = login_count + 1 WHERE id = ?"
      ).run(user.id);

      // Adjust cookie lifetime based on "Remember me"
      if (rememberMe) {
        req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
      } else {
        req.session.cookie.maxAge = null; // session cookie — expires when browser closes
      }

      res.json({
        message: 'Logged in successfully.',
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          plan: user.plan,
          avatar: user.avatar ? '/uploads/' + user.avatar : null,
          avatarBg: user.avatar_bg || null,
          joinedDate: user.created_at,
          emailVerified: !!user.email_verified
        }
      });
    });
  } catch (err) {
    log.error({ err }, 'Login failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// POST /api/auth/logout
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      log.error({ err }, 'Logout session destroy failed');
      return res.status(500).json({ error: 'Failed to log out.' });
    }
    res.clearCookie(req.app.locals.sessionCookieName, { path: '/' });
    res.json({ message: 'Logged out successfully.' });
  });
});

// GET /api/auth/me
router.get('/me', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }

  const user = db.prepare(
    'SELECT id, name, email, plan, avatar, avatar_bg, created_at, oauth_provider, email_verified FROM users WHERE id = ?'
  ).get(req.session.userId);

  if (!user) {
    return res.status(401).json({ error: 'User not found.' });
  }

  res.json({
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      plan: user.plan,
      avatar: user.avatar ? '/uploads/' + user.avatar : null,
      avatarBg: user.avatar_bg || null,
      joinedDate: user.created_at,
      oauthProvider: user.oauth_provider || null,
      emailVerified: !!user.email_verified
    }
  });
});

// Mail transporter is provided by the shared mailer module

// POST /api/auth/forgot — request password reset email
router.post('/forgot', forgotLimiter, async (req, res) => {
  try {
    const { email } = req.body;

    // ── Honeypot check ──────────────────────────────────────────
    if (rejectIfHoneypot(req, res)) {
      return res.json({ message: 'If that email exists, a reset link has been sent.' });
    }

    if (!email) {
      return res.status(400).json({ error: 'Email is required.' });
    }

    // Always return success to prevent email enumeration
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (!user) {
      return res.json({ message: 'If that email exists, a reset link has been sent.' });
    }

    // ── Velocity checks — too many resets = suspicious ──────────
    const ip = req.ip || req.connection.remoteAddress || 'unknown';

    // 1) Per-IP: too many reset requests from this IP across any account
    if (checkResetIpVelocity(ip)) {
      log.warn(
        { ip, email, window: `${RESET_IP_WINDOW}min`, limit: RESET_IP_MAX },
        'Password reset IP velocity exceeded — suppressing email'
      );
      // Return the same generic message so the requester can't tell
      return res.json({ message: 'If that email exists, a reset link has been sent.' });
    }

    // 2) Per-account: too many reset tokens created for this user recently
    if (checkResetAccountVelocity(user.id)) {
      log.warn(
        { userId: user.id, email, window: `${RESET_VELOCITY_WINDOW}min`, limit: RESET_VELOCITY_MAX },
        'Password reset account velocity exceeded — suppressing email'
      );
      // Notify the account owner that suspicious activity was detected
      try {
        db.prepare(
          "INSERT INTO notifications (user_id, type, title, message) VALUES (?, 'security', 'Suspicious Password Reset Activity', 'Multiple password reset requests were detected on your account. If this was not you, please secure your account.')"
        ).run(user.id);
      } catch (_) { /* best effort */ }
      return res.json({ message: 'If that email exists, a reset link has been sent.' });
    }

    // Invalidate any existing tokens for this user
    db.prepare('UPDATE password_reset_tokens SET used = TRUE WHERE user_id = ? AND used = FALSE').run(user.id);

    // Generate token (64 hex chars) — store only the SHA-256 hash in the DB
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = hashToken(token);
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour

    db.prepare(
      'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)'
    ).run(user.id, tokenHash, expiresAt);

    // Build reset URL — use server-configured origin to prevent host header injection
    const origin = getSafeOrigin(req);
    const resetUrl = `${origin}/reset-password?token=${token}`;

    // Send email
    const transporter = await getTransporter();
    const info = await transporter.sendMail({
      from: getFromAddress(),
      to: email,
      subject: 'Password Reset — OIL Benchmarks',
      text: `You requested a password reset.\n\nClick the link below to set a new password (valid for 1 hour):\n${resetUrl}\n\nIf you did not request this, ignore this email.`,
      html: `<p>You requested a password reset.</p><p>Click the link below to set a new password (valid for 1 hour):</p><p><a href="${escHtml(resetUrl)}">${escHtml(resetUrl)}</a></p><p>If you did not request this, ignore this email.</p>`
    });

    // Log preview URL for Ethereal (development only)
    if (!process.env.SMTP_HOST) {
      const previewUrl = nodemailer.getTestMessageUrl(info);
      if (previewUrl) log.info({ previewUrl }, 'Password reset email preview (Ethereal)');
    }

    res.json({ message: 'If that email exists, a reset link has been sent.' });
  } catch (err) {
    log.error({ err }, 'Forgot password failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// POST /api/auth/reset — reset password with token
router.post('/reset', resetLimiter, (req, res) => {
  try {
    const { token, newPassword } = req.body;

    // ── Honeypot check ──────────────────────────────────────────
    if (rejectIfHoneypot(req, res)) {
      return res.json({ message: 'Password has been reset successfully.' });
    }

    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token and new password are required.' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }

    const row = db.prepare(
      'SELECT id, user_id, expires_at, used FROM password_reset_tokens WHERE token = ?'
    ).get(hashToken(token));

    if (!row) {
      return res.status(400).json({ error: 'Invalid or expired reset link.' });
    }

    if (row.used) {
      return res.status(400).json({ error: 'This reset link has already been used.' });
    }

    if (new Date(row.expires_at) < new Date()) {
      return res.status(400).json({ error: 'This reset link has expired.' });
    }

    // Update password
    const hash = bcrypt.hashSync(newPassword, 10);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, row.user_id);

    // Clear any lockout so the user can log in immediately
    db.prepare('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?').run(row.user_id);

    // Mark token as used
    db.prepare('UPDATE password_reset_tokens SET used = TRUE WHERE id = ?').run(row.id);

    res.json({ message: 'Password has been reset successfully.' });
  } catch (err) {
    log.error({ err }, 'Password reset failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// PUT /api/auth/password — change password for logged-in user
router.put('/password', passwordChangeLimiter, (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }

  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current password and new password are required.' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters.' });
    }

    const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.session.userId);
    if (!user) {
      return res.status(401).json({ error: 'User not found.' });
    }

    // OAuth-only accounts cannot change password via this endpoint
    if (user.password_hash === '__oauth_no_password__') {
      return res.status(400).json({ error: 'This account uses social login and has no password to change.' });
    }

    const valid = bcrypt.compareSync(currentPassword, user.password_hash);
    if (!valid) {
      return res.status(403).json({ error: 'Current password is incorrect.' });
    }

    const newHash = bcrypt.hashSync(newPassword, 10);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newHash, req.session.userId);

    // Notify password change
    db.prepare(
      "INSERT INTO notifications (user_id, type, title, message) VALUES (?, 'security', 'Password Changed', 'Your password was changed successfully. If you did not make this change, contact support immediately.')"
    ).run(req.session.userId);

    res.json({ message: 'Password changed successfully.' });
  } catch (err) {
    log.error({ err }, 'Password change failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// DELETE /api/auth/account — delete own account (complete data erasure)
router.delete('/account', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }

  try {
    const userId = req.session.userId;

    // Prevent admin from self-deleting
    const user = db.prepare('SELECT plan, avatar FROM users WHERE id = ?').get(userId);
    if (user && user.plan === 'Admin') {
      return res.status(403).json({ error: 'Admin accounts cannot be deleted from the dashboard.' });
    }

    // ── Complete data erasure across all user-related tables ────
    // Use a transaction so either everything is deleted or nothing is.
    const eraseUser = db.transaction((uid) => {
      db.prepare('DELETE FROM notifications WHERE user_id = ?').run(uid);
      db.prepare('DELETE FROM push_subscriptions WHERE user_id = ?').run(uid);
      db.prepare('DELETE FROM price_alert_rules WHERE user_id = ?').run(uid);
      db.prepare('DELETE FROM email_verification_tokens WHERE user_id = ?').run(uid);
      db.prepare('DELETE FROM password_reset_tokens WHERE user_id = ?').run(uid);
      db.prepare('DELETE FROM user_settings WHERE user_id = ?').run(uid);
      // Delete any sessions belonging to this user from the session store.
      // json_extract returns NULL on malformed JSON, so also match the raw text
      // to ensure no orphaned session survives.
      db.prepare(
        "DELETE FROM sessions WHERE json_extract(sess, '$.userId') = ?" +
        " OR sess LIKE '%\"userId\":' || ? || ',%'" +
        " OR sess LIKE '%\"userId\":' || ? || '}%'"
      ).run(uid, uid, uid);
      // Finally delete the user row itself
      db.prepare('DELETE FROM users WHERE id = ?').run(uid);
    });
    eraseUser(userId);

    // Avatar cleanup happens AFTER the transaction commits so we never
    // delete files for a user that still exists in the DB.
    if (user && user.avatar) {
      const { safeDeleteAvatar } = require('./user');
      safeDeleteAvatar(user.avatar);
    }

    log.info({ userId }, 'Complete account data erasure performed');

    // Destroy the current session
    req.session.destroy((err) => {
      if (err) {
        log.error({ err }, 'Session destroy failed after account deletion');
      }
      res.clearCookie(req.app.locals.sessionCookieName, { path: '/' });
      res.json({ message: 'Account deleted successfully.' });
    });
  } catch (err) {
    log.error({ err }, 'Account deletion failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// GET /api/auth/verify — verify email with token
router.get('/verify', (req, res) => {
  try {
    const { token } = req.query;
    if (!token) {
      return res.status(400).json({ error: 'Verification token is required.' });
    }

    const row = db.prepare(
      'SELECT id, user_id, expires_at, used FROM email_verification_tokens WHERE token = ?'
    ).get(token);

    if (!row) {
      return res.status(400).json({ error: 'Invalid verification link.' });
    }

    if (row.used) {
      return res.status(400).json({ error: 'This verification link has already been used.', alreadyVerified: true });
    }

    if (new Date(row.expires_at) < new Date()) {
      return res.status(400).json({ error: 'This verification link has expired. Please request a new one.' });
    }

    // Mark email as verified
    db.prepare('UPDATE users SET email_verified = TRUE WHERE id = ?').run(row.user_id);

    // Invalidate ALL tokens for this user — not just the one used.
    // Older tokens must not remain valid after successful verification.
    db.prepare('UPDATE email_verification_tokens SET used = TRUE WHERE user_id = ? AND used = FALSE').run(row.user_id);

    res.json({ message: 'Email verified successfully!' });
  } catch (err) {
    log.error({ err }, 'Email verification failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// POST /api/auth/resend-verification — resend verification email
router.post('/resend-verification', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }

  try {
    const user = db.prepare('SELECT id, name, email, email_verified FROM users WHERE id = ?').get(req.session.userId);
    if (!user) {
      return res.status(401).json({ error: 'User not found.' });
    }

    if (user.email_verified) {
      return res.json({ message: 'Email is already verified.' });
    }

    // Rate limit: check if a token was created in the last 2 minutes
    const recent = db.prepare(
      "SELECT id FROM email_verification_tokens WHERE user_id = ? AND used = 0 AND created_at >= datetime('now', '-2 minutes')"
    ).get(user.id);
    if (recent) {
      return res.status(429).json({ error: 'A verification email was sent recently. Please wait before requesting another.' });
    }

    // Invalidate old tokens
    db.prepare('UPDATE email_verification_tokens SET used = TRUE WHERE user_id = ? AND used = FALSE').run(user.id);

    // Generate new token
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    db.prepare(
      'INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES (?, ?, ?)'
    ).run(user.id, token, expiresAt);

    const origin = getSafeOrigin(req);
    const verifyUrl = `${origin}/verify-email?token=${token}`;

    const transporter = await getTransporter();
    const info = await transporter.sendMail({
      from: getFromAddress(),
      to: user.email,
      subject: 'Verify your email — OIL Benchmarks',
      text: `Hi ${user.name},\n\nPlease verify your email address by clicking the link below (valid for 24 hours):\n${verifyUrl}\n\nIf you did not request this, you can ignore this email.`,
      html: `<div style="font-family:monospace;background:#0c0c0e;color:#e8e4dc;padding:30px;border-radius:8px;max-width:500px;margin:0 auto"><h2 style="color:#c9a84c;font-size:14px;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:16px">Email Verification</h2><p style="font-size:12px;line-height:1.6;color:#bbb">Hi <strong>${escHtml(user.name)}</strong>,</p><p style="font-size:12px;line-height:1.6;color:#bbb">Please verify your email address by clicking the button below:</p><p style="text-align:center;margin:24px 0"><a href="${escHtml(verifyUrl)}" style="display:inline-block;padding:10px 24px;background:linear-gradient(135deg,#85783c,#c9a84c);color:#0c0c0e;font-weight:700;font-size:11px;letter-spacing:1px;text-transform:uppercase;text-decoration:none;border-radius:4px">Verify Email</a></p><p style="font-size:10px;color:#666;line-height:1.5">This link is valid for 24 hours.</p></div>`
    });

    if (!process.env.SMTP_HOST) {
      const previewUrl = nodemailer.getTestMessageUrl(info);
      if (previewUrl) log.info({ previewUrl }, 'Verification email preview (Ethereal)');
    }

    res.json({ message: 'Verification email sent. Please check your inbox.' });
  } catch (err) {
    log.error({ err }, 'Resend verification failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// ─── TOTP Two-Factor Authentication ─────────────────────────────

// POST /api/auth/totp/setup — generate a new TOTP secret for the user
router.post('/totp/setup', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }
  try {
    const user = db.prepare('SELECT email, totp_enabled FROM users WHERE id = ?').get(req.session.userId);
    if (!user) return res.status(401).json({ error: 'User not found.' });
    if (user.totp_enabled) {
      return res.status(400).json({ error: 'Two-factor authentication is already enabled.' });
    }

    const secret = generateTOTPSecret();
    // Hold the secret in the session until the user verifies.
    // Nothing is written to the DB here — if the user abandons setup,
    // the secret disappears when the session expires.
    req.session.pendingTotpSecret = secret;

    const otpauthUrl = _makeTOTP(secret, user.email).toString();

    res.json({ secret, otpauthUrl });
  } catch (err) {
    log.error({ err }, 'TOTP setup failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// POST /api/auth/totp/verify — verify a TOTP token and enable 2FA
router.post('/totp/verify', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }
  try {
    const { token } = req.body;
    if (!token || typeof token !== 'string' || !/^\d{6}$/.test(token)) {
      return res.status(400).json({ error: 'A valid 6-digit code is required.' });
    }

    const user = db.prepare('SELECT totp_enabled FROM users WHERE id = ?').get(req.session.userId);
    if (!user) return res.status(401).json({ error: 'User not found.' });
    if (user.totp_enabled) {
      return res.status(400).json({ error: 'Two-factor authentication is already enabled.' });
    }

    // The secret lives in the session, not the DB, until verification succeeds.
    const pendingSecret = req.session.pendingTotpSecret;
    if (!pendingSecret) {
      return res.status(400).json({ error: 'Please initiate TOTP setup first.' });
    }

    if (!verifyTOTP(pendingSecret, token)) {
      return res.status(400).json({ error: 'Invalid code. Please try again.' });
    }

    // Verification succeeded — now persist both the secret and the enabled flag atomically.
    db.prepare('UPDATE users SET totp_secret = ?, totp_enabled = TRUE WHERE id = ?').run(pendingSecret, req.session.userId);
    delete req.session.pendingTotpSecret;
    // Notify 2FA enabled
    db.prepare(
      "INSERT INTO notifications (user_id, type, title, message) VALUES (?, 'security', 'Two-Factor Authentication Enabled', 'TOTP two-factor authentication is now active on your account.')"
    ).run(req.session.userId);

    res.json({ message: 'Two-factor authentication enabled successfully.' });
  } catch (err) {
    log.error({ err }, 'TOTP verify failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// POST /api/auth/totp/disable — disable 2FA
router.post('/totp/disable', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }
  try {
    const { password } = req.body;
    if (!password) {
      return res.status(400).json({ error: 'Password is required to disable 2FA.' });
    }

    const user = db.prepare('SELECT password_hash, totp_enabled FROM users WHERE id = ?').get(req.session.userId);
    if (!user) return res.status(401).json({ error: 'User not found.' });
    if (!user.totp_enabled) {
      return res.status(400).json({ error: 'Two-factor authentication is not enabled.' });
    }

    if (user.password_hash === '__oauth_no_password__' || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(403).json({ error: 'Incorrect password.' });
    }

    db.prepare('UPDATE users SET totp_enabled = FALSE, totp_secret = NULL WHERE id = ?').run(req.session.userId);
    // Notify 2FA disabled
    db.prepare(
      "INSERT INTO notifications (user_id, type, title, message) VALUES (?, 'security', 'Two-Factor Authentication Disabled', 'TOTP two-factor authentication has been removed from your account.')"
    ).run(req.session.userId);

    res.json({ message: 'Two-factor authentication disabled.' });
  } catch (err) {
    log.error({ err }, 'TOTP disable failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// GET /api/auth/totp/status — check if 2FA is enabled for current user
router.get('/totp/status', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }
  try {
    const user = db.prepare('SELECT totp_enabled FROM users WHERE id = ?').get(req.session.userId);
    if (!user) return res.status(401).json({ error: 'User not found.' });
    res.json({ totpEnabled: !!user.totp_enabled });
  } catch (err) {
    log.error({ err }, 'TOTP status check failed');
    res.status(500).json({ error: 'Internal server error.' });
  }
});

module.exports = router;
