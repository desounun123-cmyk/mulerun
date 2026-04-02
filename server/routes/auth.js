const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const db = require('../db/db');
const log = require('../utils/logger').child({ module: 'auth' });
const { getTransporter, getFromAddress } = require('../utils/mailer');
const { getSafeOrigin } = require('../utils/safe-origin');
const { ok, created, fail } = require('../utils/response');
const { validate, schemas } = require('../utils/validate');

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
const BASE32_ALPHABET = /^[A-Z2-7]+=*$/;

/**
 * Validates that `str` is a well-formed RFC 4648 base32 string.
 */
function validateBase32(str) {
  if (typeof str !== 'string' || str.length === 0) {
    throw new Error('TOTP secret must be a non-empty base32 string');
  }
  // Strip ALL whitespace (\s covers space, tab, newline, carriage return,
  // form feed, vertical tab, and Unicode whitespace).  The previous regex
  // only stripped ASCII space (0x20), allowing tabs, \r, and \n to slip
  // through.  While the base32 alphabet regex would reject most of these,
  // inconsistent normalisation between validation and storage could cause
  // the DB-stored secret to differ from the value actually verified,
  // enabling subtle bypass or comparison mismatches.
  const cleaned = str.replace(/\s/g, '').toUpperCase();
  if (cleaned.length === 0) {
    throw new Error('TOTP secret must contain at least one base32 character');
  }
  if (!BASE32_ALPHABET.test(cleaned)) {
    const bad = cleaned.split('').find(c => !/[A-Z2-7=]/.test(c));
    throw new Error(`Invalid base32 character: '${bad}' in TOTP secret`);
  }
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
  return new Secret({ size: 20 }).base32;
}

function verifyTOTP(secret, token) {
  const totp = _makeTOTP(secret);
  return totp.validate({ token, window: TOTP_WINDOW }) !== null;
}

// ─── Token hashing helper ────────────────────────────────────────
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// ─── Honeypot anti-bot protection ───────────────────────────────
function rejectIfHoneypot(req, res) {
  const hp1 = req.body.website;
  const hp2 = req.body.confirm_email;
  if ((hp1 !== undefined && hp1 !== '') || (hp2 !== undefined && hp2 !== '')) {
    log.warn(
      { ip: req.ip, path: req.originalUrl, honeypot: { websiteLen: hp1 ? hp1.length : 0, confirmEmailLen: hp2 ? hp2.length : 0 } },
      'Honeypot field filled — likely bot submission'
    );
    return true;
  }
  return false;
}

// In test mode, bypass rate limiters
const isTest = process.env.NODE_ENV === 'test';
const noopLimiter = (req, res, next) => next();

// ─── Account lockout configuration ─────────────────────────────
const LOGIN_MAX_ATTEMPTS = parseInt(process.env.LOGIN_MAX_ATTEMPTS, 10) || 5;
const LOGIN_LOCKOUT_MINUTES = parseInt(process.env.LOGIN_LOCKOUT_MINUTES, 10) || 15;
const CAPTCHA_THRESHOLD = parseInt(process.env.CAPTCHA_THRESHOLD, 10) || 2;

// ─── Password-reset velocity configuration ──────────────────────
const RESET_VELOCITY_MAX     = parseInt(process.env.RESET_VELOCITY_MAX, 10) || 3;
const RESET_VELOCITY_WINDOW  = parseInt(process.env.RESET_VELOCITY_WINDOW_MIN, 10) || 60;
const RESET_IP_MAX           = parseInt(process.env.RESET_IP_MAX, 10) || 5;
const RESET_IP_WINDOW        = parseInt(process.env.RESET_IP_WINDOW_MIN, 10) || 60;

const resetIpLog = new Map();
const RESET_IP_LOG_MAX_SIZE = 10000;
const RESET_IP_SWEEP_INTERVAL = 100;
let _resetIpCallCount = 0;

const _resetIpTimer = setInterval(() => {
  const now = Date.now();
  const windowMs = RESET_IP_WINDOW * 60 * 1000;
  for (const [k, v] of resetIpLog) {
    if (v.length === 0 || now - v[v.length - 1] > windowMs) resetIpLog.delete(k);
  }
}, 5 * 60 * 1000);
if (_resetIpTimer.unref) _resetIpTimer.unref();

function checkResetIpVelocity(ip) {
  const now = Date.now();
  const windowMs = RESET_IP_WINDOW * 60 * 1000;
  let timestamps = resetIpLog.get(ip) || [];
  timestamps = timestamps.filter(ts => now - ts < windowMs);
  timestamps.push(now);
  resetIpLog.set(ip, timestamps);

  _resetIpCallCount++;
  if (_resetIpCallCount >= RESET_IP_SWEEP_INTERVAL) {
    _resetIpCallCount = 0;
    for (const [k, v] of resetIpLog) {
      if (v.length === 0 || now - v[v.length - 1] > windowMs) resetIpLog.delete(k);
    }
  }

  if (resetIpLog.size > RESET_IP_LOG_MAX_SIZE) {
    const sorted = [...resetIpLog.entries()]
      .sort((a, b) => a[1][a[1].length - 1] - b[1][b[1].length - 1]);
    const toRemove = sorted.length - RESET_IP_LOG_MAX_SIZE;
    for (let i = 0; i < toRemove; i++) {
      resetIpLog.delete(sorted[i][0]);
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
function generateCaptchaChallenge() {
  const ops = ['+', '-', '\u00d7', '+', '-'];
  const op = ops[Math.floor(Math.random() * ops.length)];
  let a, b, answer;
  if (op === '+') {
    a = Math.floor(Math.random() * 900) + 100;
    b = Math.floor(Math.random() * 900) + 100;
    answer = a + b;
  } else if (op === '-') {
    a = Math.floor(Math.random() * 900) + 100;
    b = Math.floor(Math.random() * (a - 1)) + 1;
    answer = a - b;
  } else {
    a = Math.floor(Math.random() * 90) + 10;
    b = Math.floor(Math.random() * 9) + 2;
    answer = a * b;
  }
  return { text: `${a} ${op} ${b} = ?`, answer };
}

function renderCaptchaSVG(text) {
  const w = 240, h = 50;
  let paths = '';
  for (let i = 0; i < 5; i++) {
    const x1 = Math.floor(Math.random() * w);
    const y1 = Math.floor(Math.random() * h);
    const x2 = Math.floor(Math.random() * w);
    const y2 = Math.floor(Math.random() * h);
    const c = `rgb(${60 + Math.floor(Math.random() * 80)},${60 + Math.floor(Math.random() * 80)},${60 + Math.floor(Math.random() * 80)})`;
    paths += `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${c}" stroke-width="1"/>`;
  }
  for (let i = 0; i < 30; i++) {
    const cx = Math.floor(Math.random() * w);
    const cy = Math.floor(Math.random() * h);
    const c = `rgb(${80 + Math.floor(Math.random() * 100)},${80 + Math.floor(Math.random() * 100)},${80 + Math.floor(Math.random() * 100)})`;
    paths += `<circle cx="${cx}" cy="${cy}" r="1" fill="${c}"/>`;
  }
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

function rateLimitHandler(req, res, next, options) {
  const retryAfter = req.rateLimit && req.rateLimit.resetTime
    ? Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000)
    : Math.ceil(options.windowMs / 1000);
  res.setHeader('Retry-After', Math.max(retryAfter, 1));
  res.status(429).json(options.message);
}

// Login: 5 attempts per 1 minute per IP
const loginLimiter = isTest ? noopLimiter : rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again in 1 minute.' },
  keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown',
  handler: rateLimitHandler,
});

// Register: 3 attempts per 60 minutes per IP (short window)
const registerLimiter = isTest ? noopLimiter : rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many accounts created from this IP. Please try again in 1 hour.' },
  keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown',
  handler: rateLimitHandler,
});

// Register daily cap: 10 accounts per 24 hours per IP
const registerDailyLimiter = isTest ? noopLimiter : rateLimit({
  windowMs: 24 * 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Daily registration limit reached. Please try again tomorrow.' },
  keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown',
  handler: rateLimitHandler,
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
  keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown',
  handler: rateLimitHandler,
});

// Reset password (token submit): 5 attempts per 15 minutes per IP
const resetLimiter = isTest ? noopLimiter : rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many reset attempts. Please try again in 15 minutes.' },
  keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown',
  handler: rateLimitHandler,
});

// Password change: 5 attempts per 15 minutes per IP
const passwordChangeLimiter = isTest ? noopLimiter : rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many password change attempts. Please try again in 15 minutes.' },
  keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown',
  handler: rateLimitHandler,
});

// CAPTCHA generation: 10 requests per 1 minute per IP
// Prevents attackers from hammering the SVG generation endpoint to burn
// CPU/memory. Each legitimate user flow (login, register) only needs 1-2
// CAPTCHA requests, so 10/min is generous for real users while blocking abuse.
const captchaLimiter = isTest ? noopLimiter : rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many CAPTCHA requests. Please try again in 1 minute.' },
  keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown',
  handler: rateLimitHandler,
});

// POST /api/auth/register
router.post('/register', registerLimiter, registerDailyLimiter, validate(schemas.register), async (req, res) => {
  try {
    const { name, email, password, captchaAnswer } = req.body;

    // ── Honeypot check ──────────────────────────────────────────
    if (rejectIfHoneypot(req, res)) {
      return created(res, null, 'Account created.');
    }

    const cleanName = name;
    const emailTrimmed = email;

    // Block disposable / banned email domains
    const domain = emailTrimmed.split('@')[1];
    if (domain && (domain === 'oauth.local' || domain === 'oauth.internal.noreply')) {
      return fail(res, 400, 'Registration with this email domain is not allowed.');
    }
    if (BLOCKED_EMAIL_DOMAINS.length > 0) {
      if (domain && BLOCKED_EMAIL_DOMAINS.includes(domain)) {
        return fail(res, 400, 'Registration with this email domain is not allowed.');
      }
    }

    // ── CAPTCHA required for all registrations ──────────────────
    if (!isTest) {
      const sessionAnswer = req.session.captchaAnswer;
      const sessionTs = req.session.captchaTs || 0;
      delete req.session.captchaAnswer;
      delete req.session.captchaTs;

      if (!captchaAnswer && captchaAnswer !== 0) {
        return res.status(400).json({
          ok: false, error: 'Please complete the CAPTCHA challenge.',
          captchaRequired: true
        });
      }
      const captchaExpired = (Date.now() - sessionTs) > 5 * 60 * 1000;
      if (captchaExpired || sessionAnswer === undefined || parseInt(captchaAnswer, 10) !== sessionAnswer) {
        return res.status(400).json({
          ok: false, error: 'Incorrect or expired CAPTCHA. Please try again.',
          captchaRequired: true
        });
      }
    }

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(emailTrimmed);
    if (existing) {
      return fail(res, 409, 'An account with this email already exists.');
    }

    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare(
      'INSERT INTO users (name, email, password_hash, email_verified) VALUES (?, ?, ?, FALSE)'
    ).run(cleanName, emailTrimmed, hash);

    const userId = result.lastInsertRowid;

    db.prepare(
      'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode) VALUES (?, TRUE, FALSE, TRUE)'
    ).run(userId);

    db.prepare('UPDATE email_verification_tokens SET used = TRUE WHERE user_id = ? AND used = FALSE').run(userId);

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    db.prepare(
      'INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES (?, ?, ?)'
    ).run(userId, token, expiresAt);

    const origin = getSafeOrigin(req);
    const verifyUrl = `${origin}/verify-email?token=${token}`;

    let emailSendFailed = false;
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
      emailSendFailed = true;
      log.error({ err: mailErr, userId, email: emailTrimmed }, 'Failed to send verification email during registration');
    }

    req.session.regenerate((err) => {
      if (err) {
        log.error({ err }, 'Session regeneration failed during registration');
        return fail(res, 500, 'Internal server error.');
      }

      req.session.userId = userId;

      // Create appropriate notification based on email delivery outcome
      if (emailSendFailed) {
        db.prepare(
          "INSERT INTO notifications (user_id, type, title, message) VALUES (?, 'warning', 'Verification Email Not Sent', 'We could not send your verification email. Please go to your account settings and request a new verification email.')"
        ).run(userId);
      }
      db.prepare(
        "INSERT INTO notifications (user_id, type, title, message) VALUES (?, 'info', 'Welcome!', 'Your account has been created. Explore your dashboard to set up alerts and preferences.')"
      ).run(userId);

      const user = db.prepare(
        'SELECT id, name, email, plan, avatar, avatar_bg, created_at, email_verified FROM users WHERE id = ?'
      ).get(userId);

      const responseData = {
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
      };

      // Surface the email failure to the client so it can prompt a resend
      if (emailSendFailed) {
        responseData.emailSendFailed = true;
        return created(res, responseData,
          'Account created, but we could not send the verification email. Please request a new one from your account settings.');
      }

      created(res, responseData, 'Account created. Please check your email to verify your address.');
    });
  } catch (err) {
    log.error({ err }, 'Registration failed');
    fail(res, 500, 'Internal server error.');
  }
});

// GET /api/auth/captcha — generate a new CAPTCHA challenge
router.get('/captcha', captchaLimiter, (req, res) => {
  const challenge = generateCaptchaChallenge();
  req.session.captchaAnswer = challenge.answer;
  req.session.captchaTs = Date.now();
  const svg = renderCaptchaSVG(challenge.text);
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.send(svg);
});

// POST /api/auth/login
router.post('/login', loginLimiter, validate(schemas.login), (req, res) => {
  try {
    const { email, password, rememberMe, captchaAnswer } = req.body;

    // ── Honeypot check ──────────────────────────────────────────
    if (rejectIfHoneypot(req, res)) {
      return fail(res, 401, 'Invalid email or password.');
    }

    const user = db.prepare(
      'SELECT id, name, email, password_hash, plan, avatar, avatar_bg, created_at, failed_login_attempts, locked_until, totp_enabled, totp_secret FROM users WHERE email = ?'
    ).get(email);

    if (!user) {
      return fail(res, 401, 'Invalid email or password.');
    }

    // ── Account lockout check ──────────────────────────────────
    if (user.locked_until) {
      const lockedUntil = new Date(user.locked_until);
      if (lockedUntil > new Date()) {
        const remainingMs = lockedUntil - new Date();
        const remainingMin = Math.ceil(remainingMs / 60000);
        return res.status(423).json({
          ok: false, error: `Account is temporarily locked. Try again in ${remainingMin} minute${remainingMin !== 1 ? 's' : ''}.`,
          lockedUntil: user.locked_until,
          remainingMinutes: remainingMin
        });
      }
      db.prepare('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?').run(user.id);
      user.failed_login_attempts = 0;
      user.locked_until = null;
    }

    // ── CAPTCHA check — required after CAPTCHA_THRESHOLD failed attempts ──
    const needsCaptcha = !isTest && (user.failed_login_attempts || 0) >= CAPTCHA_THRESHOLD;
    if (needsCaptcha) {
      const sessionAnswer = req.session.captchaAnswer;
      const sessionTs = req.session.captchaTs || 0;
      delete req.session.captchaAnswer;
      delete req.session.captchaTs;

      if (!captchaAnswer && captchaAnswer !== 0) {
        return res.status(400).json({
          ok: false, error: 'Please complete the CAPTCHA challenge.',
          captchaRequired: true
        });
      }
      const captchaExpired = (Date.now() - sessionTs) > 5 * 60 * 1000;
      if (captchaExpired || sessionAnswer === undefined || parseInt(captchaAnswer, 10) !== sessionAnswer) {
        return res.status(400).json({
          ok: false, error: 'Incorrect or expired CAPTCHA. Please try again.',
          captchaRequired: true
        });
      }
    }

    // OAuth-only accounts cannot log in with password
    if (user.password_hash === '__oauth_no_password__') {
      return fail(res, 401, 'This account uses social login. Please sign in with Google or GitHub.');
    }

    const valid = bcrypt.compareSync(password, user.password_hash);
    if (!valid) {
      const attempts = (user.failed_login_attempts || 0) + 1;
      const remaining = LOGIN_MAX_ATTEMPTS - attempts;

      if (attempts >= LOGIN_MAX_ATTEMPTS) {
        const lockUntil = new Date(Date.now() + LOGIN_LOCKOUT_MINUTES * 60 * 1000).toISOString();
        db.prepare('UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?')
          .run(attempts, lockUntil, user.id);
        return res.status(423).json({
          ok: false, error: `Too many failed attempts. Account locked for ${LOGIN_LOCKOUT_MINUTES} minutes.`,
          lockedUntil: lockUntil,
          remainingMinutes: LOGIN_LOCKOUT_MINUTES
        });
      }

      db.prepare('UPDATE users SET failed_login_attempts = ? WHERE id = ?')
        .run(attempts, user.id);

      const hint = remaining <= 2
        ? ` (${remaining} attempt${remaining !== 1 ? 's' : ''} remaining before lockout)`
        : '';
      const resp = { ok: false, error: 'Invalid email or password.' + hint };
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
        return ok(res, { totpRequired: true }, 'Two-factor authentication code required.');
      }
      if (!verifyTOTP(user.totp_secret, totpToken)) {
        return fail(res, 401, 'Invalid two-factor authentication code.');
      }
    }

    req.session.regenerate((err) => {
      if (err) {
        log.error({ err }, 'Session regeneration failed during login');
        return fail(res, 500, 'Internal server error.');
      }

      req.session.userId = user.id;

      db.prepare(
        "UPDATE users SET last_login = datetime('now'), login_count = login_count + 1 WHERE id = ?"
      ).run(user.id);

      if (rememberMe) {
        req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
      } else {
        req.session.cookie.maxAge = null;
      }

      ok(res, {
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
      }, 'Logged in successfully.');
    });
  } catch (err) {
    log.error({ err }, 'Login failed');
    fail(res, 500, 'Internal server error.');
  }
});

// POST /api/auth/logout
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      log.error({ err }, 'Logout session destroy failed');
      return fail(res, 500, 'Failed to log out.');
    }
    res.clearCookie(req.app.locals.sessionCookieName, { path: '/' });
    ok(res, null, 'Logged out successfully.');
  });
});

// GET /api/auth/me
router.get('/me', (req, res) => {
  if (!req.session.userId) {
    return fail(res, 401, 'Not authenticated.');
  }

  const user = db.prepare(
    'SELECT id, name, email, plan, avatar, avatar_bg, created_at, oauth_provider, email_verified FROM users WHERE id = ?'
  ).get(req.session.userId);

  if (!user) {
    return fail(res, 401, 'User not found.');
  }

  ok(res, {
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

// POST /api/auth/forgot — request password reset email
router.post('/forgot', forgotLimiter, validate(schemas.forgotPassword), async (req, res) => {
  try {
    const { email } = req.body;

    if (rejectIfHoneypot(req, res)) {
      return ok(res, null, 'If an account with that email exists, a reset link has been sent.');
    }

    const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (!user) {
      return ok(res, null, 'If an account with that email exists, a reset link has been sent.');
    }

    const ip = req.ip || req.connection.remoteAddress || 'unknown';

    if (checkResetIpVelocity(ip)) {
      log.warn(
        { ip, email, window: `${RESET_IP_WINDOW}min`, limit: RESET_IP_MAX },
        'Password reset IP velocity exceeded — suppressing email'
      );
      return ok(res, null, 'If an account with that email exists, a reset link has been sent.');
    }

    if (checkResetAccountVelocity(user.id)) {
      log.warn(
        { userId: user.id, email, window: `${RESET_VELOCITY_WINDOW}min`, limit: RESET_VELOCITY_MAX },
        'Password reset account velocity exceeded — suppressing email'
      );
      try {
        db.prepare(
          "INSERT INTO notifications (user_id, type, title, message) VALUES (?, 'security', 'Suspicious Password Reset Activity', 'Multiple password reset requests were detected on your account. If this was not you, please secure your account.')"
        ).run(user.id);
      } catch (_) { /* best effort */ }
      return ok(res, null, 'If an account with that email exists, a reset link has been sent.');
    }

    db.prepare('UPDATE password_reset_tokens SET used = TRUE WHERE user_id = ? AND used = FALSE').run(user.id);

    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = hashToken(token);
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

    db.prepare(
      'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)'
    ).run(user.id, tokenHash, expiresAt);

    const origin = getSafeOrigin(req);
    const resetUrl = `${origin}/reset-password?token=${token}`;

    const transporter = await getTransporter();
    const info = await transporter.sendMail({
      from: getFromAddress(),
      to: email,
      subject: 'Password Reset — OIL Benchmarks',
      text: `You requested a password reset.\n\nClick the link below to set a new password (valid for 1 hour):\n${resetUrl}\n\nIf you did not request this, ignore this email.`,
      html: `<p>You requested a password reset.</p><p>Click the link below to set a new password (valid for 1 hour):</p><p><a href="${escHtml(resetUrl)}">${escHtml(resetUrl)}</a></p><p>If you did not request this, ignore this email.</p>`
    });

    if (!process.env.SMTP_HOST) {
      const previewUrl = nodemailer.getTestMessageUrl(info);
      if (previewUrl) log.info({ previewUrl }, 'Password reset email preview (Ethereal)');
    }

    ok(res, null, 'If an account with that email exists, a reset link has been sent.');
  } catch (err) {
    log.error({ err }, 'Forgot password failed');
    fail(res, 500, 'Internal server error.');
  }
});

// POST /api/auth/reset — reset password with token
router.post('/reset', resetLimiter, validate(schemas.resetPassword), (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (rejectIfHoneypot(req, res)) {
      return ok(res, null, 'Password has been reset successfully.');
    }

    const row = db.prepare(
      'SELECT id, user_id, expires_at, used FROM password_reset_tokens WHERE token = ?'
    ).get(hashToken(token));

    if (!row) {
      return fail(res, 400, 'Invalid or expired reset link.');
    }

    if (row.used) {
      return fail(res, 400, 'This reset link has already been used.');
    }

    if (new Date(row.expires_at) < new Date()) {
      return fail(res, 400, 'This reset link has expired.');
    }

    const hash = bcrypt.hashSync(newPassword, 10);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, row.user_id);

    db.prepare('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?').run(row.user_id);

    db.prepare('UPDATE password_reset_tokens SET used = TRUE WHERE id = ?').run(row.id);

    ok(res, null, 'Password has been reset successfully.');
  } catch (err) {
    log.error({ err }, 'Password reset failed');
    fail(res, 500, 'Internal server error.');
  }
});

// PUT /api/auth/password — change password for logged-in user
router.put('/password', passwordChangeLimiter, validate(schemas.changePassword), (req, res) => {
  if (!req.session.userId) {
    return fail(res, 401, 'Not authenticated.');
  }

  try {
    const { currentPassword, newPassword } = req.body;

    const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.session.userId);
    if (!user) {
      return fail(res, 401, 'User not found.');
    }

    if (user.password_hash === '__oauth_no_password__') {
      return fail(res, 400, 'This account uses social login and has no password to change.');
    }

    const valid = bcrypt.compareSync(currentPassword, user.password_hash);
    if (!valid) {
      return fail(res, 403, 'Current password is incorrect.');
    }

    const newHash = bcrypt.hashSync(newPassword, 10);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newHash, req.session.userId);

    db.prepare(
      "INSERT INTO notifications (user_id, type, title, message) VALUES (?, 'security', 'Password Changed', 'Your password was changed successfully. If you did not make this change, contact support immediately.')"
    ).run(req.session.userId);

    ok(res, null, 'Password changed successfully.');
  } catch (err) {
    log.error({ err }, 'Password change failed');
    fail(res, 500, 'Internal server error.');
  }
});

// DELETE /api/auth/account — delete own account (complete data erasure)
router.delete('/account', (req, res) => {
  if (!req.session.userId) {
    return fail(res, 401, 'Not authenticated.');
  }

  try {
    const userId = req.session.userId;

    const user = db.prepare('SELECT plan, avatar FROM users WHERE id = ?').get(userId);
    if (user && user.plan === 'Admin') {
      return fail(res, 403, 'Admin accounts cannot be deleted from the dashboard.');
    }

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
    });
    eraseUser(userId);

    if (user && user.avatar) {
      const { safeDeleteAvatar } = require('./user');
      safeDeleteAvatar(user.avatar);
    }

    log.info({ userId }, 'Complete account data erasure performed');

    req.session.destroy((err) => {
      if (err) {
        log.error({ err }, 'Session destroy failed after account deletion');
      }
      res.clearCookie(req.app.locals.sessionCookieName, { path: '/' });
      ok(res, null, 'Account deleted successfully.');
    });
  } catch (err) {
    log.error({ err }, 'Account deletion failed');
    fail(res, 500, 'Internal server error.');
  }
});

// GET /api/auth/verify — verify email with token
router.get('/verify', validate(schemas.verifyToken, 'query'), (req, res) => {
  try {
    const { token } = req.query;

    const row = db.prepare(
      'SELECT id, user_id, expires_at, used FROM email_verification_tokens WHERE token = ?'
    ).get(token);

    if (!row) {
      return fail(res, 400, 'Invalid verification link.');
    }

    if (row.used) {
      return fail(res, 400, 'This verification link has already been used.');
    }

    if (new Date(row.expires_at) < new Date()) {
      return fail(res, 400, 'This verification link has expired. Please request a new one.');
    }

    db.prepare('UPDATE users SET email_verified = TRUE WHERE id = ?').run(row.user_id);

    db.prepare('UPDATE email_verification_tokens SET used = TRUE WHERE user_id = ? AND used = FALSE').run(row.user_id);

    ok(res, null, 'Email verified successfully!');
  } catch (err) {
    log.error({ err }, 'Email verification failed');
    fail(res, 500, 'Internal server error.');
  }
});

// POST /api/auth/resend-verification — resend verification email
router.post('/resend-verification', async (req, res) => {
  if (!req.session.userId) {
    return fail(res, 401, 'Not authenticated.');
  }

  try {
    const user = db.prepare('SELECT id, name, email, email_verified FROM users WHERE id = ?').get(req.session.userId);
    if (!user) {
      return fail(res, 401, 'User not found.');
    }

    if (user.email_verified) {
      return ok(res, null, 'Email is already verified.');
    }

    const recent = db.prepare(
      "SELECT id FROM email_verification_tokens WHERE user_id = ? AND used = 0 AND created_at >= datetime('now', '-2 minutes')"
    ).get(user.id);
    if (recent) {
      return fail(res, 429, 'A verification email was sent recently. Please wait before requesting another.');
    }

    db.prepare('UPDATE email_verification_tokens SET used = TRUE WHERE user_id = ? AND used = FALSE').run(user.id);

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

    ok(res, null, 'Verification email sent. Please check your inbox.');
  } catch (err) {
    log.error({ err }, 'Resend verification failed');
    fail(res, 500, 'Internal server error.');
  }
});

// ─── TOTP Two-Factor Authentication ─────────────────────────────

// POST /api/auth/totp/setup — generate a new TOTP secret for the user
router.post('/totp/setup', (req, res) => {
  if (!req.session.userId) {
    return fail(res, 401, 'Not authenticated.');
  }
  try {
    const user = db.prepare('SELECT email, totp_enabled FROM users WHERE id = ?').get(req.session.userId);
    if (!user) return fail(res, 401, 'User not found.');
    if (user.totp_enabled) {
      return fail(res, 400, 'Two-factor authentication is already enabled.');
    }

    const secret = generateTOTPSecret();
    req.session.pendingTotpSecret = secret;

    const otpauthUrl = _makeTOTP(secret, user.email).toString();

    ok(res, { secret, otpauthUrl });
  } catch (err) {
    log.error({ err }, 'TOTP setup failed');
    fail(res, 500, 'Internal server error.');
  }
});

// POST /api/auth/totp/verify — verify a TOTP token and enable 2FA
router.post('/totp/verify', validate(schemas.totpVerify), (req, res) => {
  if (!req.session.userId) {
    return fail(res, 401, 'Not authenticated.');
  }
  try {
    const { token } = req.body;

    const user = db.prepare('SELECT totp_enabled FROM users WHERE id = ?').get(req.session.userId);
    if (!user) return fail(res, 401, 'User not found.');
    if (user.totp_enabled) {
      return fail(res, 400, 'Two-factor authentication is already enabled.');
    }

    const pendingSecret = req.session.pendingTotpSecret;
    if (!pendingSecret) {
      return fail(res, 400, 'Please initiate TOTP setup first.');
    }

    // Normalise the secret before verification and storage so the DB
    // always holds a clean, whitespace-free base32 value.
    const normalizedSecret = validateBase32(pendingSecret);

    if (!verifyTOTP(normalizedSecret, token)) {
      return fail(res, 400, 'Invalid code. Please try again.');
    }

    db.prepare('UPDATE users SET totp_secret = ?, totp_enabled = TRUE WHERE id = ?').run(normalizedSecret, req.session.userId);
    delete req.session.pendingTotpSecret;
    db.prepare(
      "INSERT INTO notifications (user_id, type, title, message) VALUES (?, 'security', 'Two-Factor Authentication Enabled', 'TOTP two-factor authentication is now active on your account.')"
    ).run(req.session.userId);

    ok(res, null, 'Two-factor authentication enabled successfully.');
  } catch (err) {
    log.error({ err }, 'TOTP verify failed');
    fail(res, 500, 'Internal server error.');
  }
});

// POST /api/auth/totp/disable — disable 2FA
router.post('/totp/disable', validate(schemas.totpDisable), (req, res) => {
  if (!req.session.userId) {
    return fail(res, 401, 'Not authenticated.');
  }
  try {
    const { password } = req.body;

    const user = db.prepare('SELECT password_hash, totp_enabled FROM users WHERE id = ?').get(req.session.userId);
    if (!user) return fail(res, 401, 'User not found.');
    if (!user.totp_enabled) {
      return fail(res, 400, 'Two-factor authentication is not enabled.');
    }

    if (user.password_hash === '__oauth_no_password__' || !bcrypt.compareSync(password, user.password_hash)) {
      return fail(res, 403, 'Incorrect password.');
    }

    db.prepare('UPDATE users SET totp_enabled = FALSE, totp_secret = NULL WHERE id = ?').run(req.session.userId);
    db.prepare(
      "INSERT INTO notifications (user_id, type, title, message) VALUES (?, 'security', 'Two-Factor Authentication Disabled', 'TOTP two-factor authentication has been removed from your account.')"
    ).run(req.session.userId);

    ok(res, null, 'Two-factor authentication disabled.');
  } catch (err) {
    log.error({ err }, 'TOTP disable failed');
    fail(res, 500, 'Internal server error.');
  }
});

// GET /api/auth/totp/status — check if 2FA is enabled for current user
router.get('/totp/status', (req, res) => {
  if (!req.session.userId) {
    return fail(res, 401, 'Not authenticated.');
  }
  try {
    const user = db.prepare('SELECT totp_enabled FROM users WHERE id = ?').get(req.session.userId);
    if (!user) return fail(res, 401, 'User not found.');
    ok(res, { totpEnabled: !!user.totp_enabled });
  } catch (err) {
    log.error({ err }, 'TOTP status check failed');
    fail(res, 500, 'Internal server error.');
  }
});

module.exports = router;

module.exports.shutdown = function () {
  clearInterval(_resetIpTimer);
  resetIpLog.clear();
};
