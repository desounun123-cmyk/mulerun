const express = require('express');
const crypto = require('crypto');
const db = require('../db/db');
const log = require('../utils/logger').child({ module: 'oauth' });
const { ok, fail } = require('../utils/response');
const { getSafeOrigin } = require('../utils/safe-origin');

const router = express.Router();

// ── Helpers ──────────────────────────────────────────────────────

/** Build the full callback URL using the safe server-configured origin */
function callbackUrl(req, provider) {
  const origin = getSafeOrigin(req);
  return `${origin}/api/oauth/${provider}/callback`;
}

// Internal-only domain for OAuth users whose provider returns no email.
// Uses a nonce so even if an attacker guesses the pattern, the address
// will never match a pre-registered row.
const OAUTH_PLACEHOLDER_DOMAIN = 'oauth.internal.noreply';

// Maximum age (ms) for an OAuth CSRF state token.  If the user takes
// longer than this to complete the provider flow, they must restart.
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000; // 10 minutes

/** Store a new OAuth state token (with timestamp) in the session */
function setOAuthState(req) {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  req.session.oauthStateTs = Date.now();
  return state;
}

/**
 * Validate and consume the OAuth state token from the session.
 * Returns true if valid; false if missing, mismatched, or expired.
 */
function consumeOAuthState(req, state) {
  if (!state || state !== req.session.oauthState) return false;

  const ts = req.session.oauthStateTs || 0;
  // Clean up regardless of outcome
  delete req.session.oauthState;
  delete req.session.oauthStateTs;

  if (Date.now() - ts > OAUTH_STATE_TTL_MS) {
    log.warn({ age: Date.now() - ts }, 'OAuth state token expired');
    return false;
  }

  return true;
}

/** Find or create a user from OAuth profile, returns user row */
function findOrCreateOAuthUser(provider, profile) {
  // Try to find existing OAuth-linked user
  const existing = db.prepare(
    'SELECT * FROM users WHERE oauth_provider = ? AND oauth_id = ?'
  ).get(provider, profile.id);

  if (existing) {
    // Update last login
    db.prepare(
      "UPDATE users SET last_login = datetime('now'), login_count = login_count + 1 WHERE id = ?"
    ).run(existing.id);
    return existing;
  }

  // Check if email already exists (link accounts) — but ONLY for real
  // provider-supplied emails.  Synthetic placeholder addresses must never
  // participate in account linking; an attacker could pre-register the
  // predictable placeholder before the OAuth user arrives.
  //
  // Also enforce RFC 5321 max length (254 chars) and basic format — OAuth
  // providers can return surprising values.
  const rawEmail = typeof profile.email === 'string' ? profile.email.trim().toLowerCase() : null;
  const realEmail = rawEmail
    && rawEmail.length <= 254
    && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rawEmail)
    && !rawEmail.endsWith('@' + OAUTH_PLACEHOLDER_DOMAIN)
    ? rawEmail
    : null;

  if (realEmail) {
    const byEmail = db.prepare('SELECT * FROM users WHERE email = ?').get(realEmail);
    if (byEmail) {
      // Link OAuth to existing account
      db.prepare(
        'UPDATE users SET oauth_provider = ?, oauth_id = ?, last_login = datetime(\'now\'), login_count = login_count + 1 WHERE id = ?'
      ).run(provider, profile.id, byEmail.id);
      return db.prepare('SELECT * FROM users WHERE id = ?').get(byEmail.id);
    }
  }

  // Create new user (no password — OAuth only)
  const name = (profile.name || profile.login || 'User').replace(/<[^>]*>/g, '').trim().slice(0, 100) || 'User';
  const nonce = crypto.randomBytes(8).toString('hex');
  const email = realEmail || `${provider}_${profile.id}_${nonce}@${OAUTH_PLACEHOLDER_DOMAIN}`;
  const placeholderHash = '__oauth_no_password__';

  const result = db.prepare(
    'INSERT INTO users (name, email, password_hash, oauth_provider, oauth_id) VALUES (?, ?, ?, ?, ?)'
  ).run(name, email, placeholderHash, provider, profile.id);

  const userId = result.lastInsertRowid;

  // Create default settings
  db.prepare(
    'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode) VALUES (?, TRUE, FALSE, TRUE)'
  ).run(userId);

  // Track login
  db.prepare(
    "UPDATE users SET last_login = datetime('now'), login_count = 1 WHERE id = ?"
  ).run(userId);

  return db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
}

/** Set session and redirect to app — regenerate session ID to prevent fixation */
function loginAndRedirect(req, res, user) {
  const oldId = req.sessionID;

  req.session.regenerate((err) => {
    if (err) {
      log.error({ err }, 'Session regeneration failed during OAuth login');
      return res.status(500).send('Internal server error');
    }

    // Guard against silent regeneration failures (broken store, middleware
    // misconfiguration, etc.).  If the session ID did not change, the user
    // would log in on the attacker-supplied session — classic fixation.
    if (req.sessionID === oldId) {
      log.error('Session ID unchanged after regenerate — possible session fixation; aborting login');
      req.session.destroy(() => {});
      return res.status(500).send('Internal server error');
    }

    req.session.userId = user.id;
    req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days for OAuth

    // Explicitly save so we don't race against res.redirect ending the
    // response before the store persists the new session data.
    req.session.save((saveErr) => {
      if (saveErr) {
        log.error({ err: saveErr }, 'Session save failed after OAuth login');
        return res.status(500).send('Internal server error');
      }
      res.redirect('/#oauth-success');
    });
  });
}

// ── Google OAuth ─────────────────────────────────────────────────

// Step 1: Redirect to Google
router.get('/google', (req, res) => {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) {
    return fail(res, 501, 'Google OAuth not configured.');
  }

  const state = setOAuthState(req);

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: callbackUrl(req, 'google'),
    response_type: 'code',
    scope: 'openid email profile',
    state: state,
    access_type: 'offline',
    prompt: 'select_account'
  });

  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

// Step 2: Google callback
router.get('/google/callback', async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code || !consumeOAuthState(req, state)) {
      return res.redirect('/#oauth-error');
    }

    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;

    // Exchange code for tokens
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: callbackUrl(req, 'google'),
        grant_type: 'authorization_code'
      })
    });

    const tokens = await tokenRes.json();
    if (!tokens.access_token) {
      log.error({ response: tokens }, 'Google token exchange failed');
      return res.redirect('/#oauth-error');
    }

    // Get user profile
    const profileRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });
    const profile = await profileRes.json();

    if (!profile.id) {
      return res.redirect('/#oauth-error');
    }

    const user = findOrCreateOAuthUser('google', {
      id: String(profile.id),
      name: profile.name,
      email: profile.email
    });

    loginAndRedirect(req, res, user);
  } catch (err) {
    log.error({ err }, 'Google OAuth callback failed');
    res.redirect('/#oauth-error');
  }
});

// ── GitHub OAuth ─────────────────────────────────────────────────

// Step 1: Redirect to GitHub
router.get('/github', (req, res) => {
  const clientId = process.env.GITHUB_CLIENT_ID;
  if (!clientId) {
    return fail(res, 501, 'GitHub OAuth not configured.');
  }

  const state = setOAuthState(req);

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: callbackUrl(req, 'github'),
    scope: 'read:user user:email',
    state: state
  });

  res.redirect(`https://github.com/login/oauth/authorize?${params}`);
});

// Step 2: GitHub callback
router.get('/github/callback', async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code || !consumeOAuthState(req, state)) {
      return res.redirect('/#oauth-error');
    }

    const clientId = process.env.GITHUB_CLIENT_ID;
    const clientSecret = process.env.GITHUB_CLIENT_SECRET;

    // Exchange code for access token
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        code,
        redirect_uri: callbackUrl(req, 'github')
      })
    });

    const tokens = await tokenRes.json();
    if (!tokens.access_token) {
      log.error({ response: tokens }, 'GitHub token exchange failed');
      return res.redirect('/#oauth-error');
    }

    // Get user profile
    const profileRes = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`,
        'User-Agent': 'OIL-Benchmarks-App'
      }
    });
    const profile = await profileRes.json();

    if (!profile.id) {
      return res.redirect('/#oauth-error');
    }

    // Get primary email if not public
    let email = profile.email;
    if (!email) {
      try {
        const emailsRes = await fetch('https://api.github.com/user/emails', {
          headers: {
            Authorization: `Bearer ${tokens.access_token}`,
            'User-Agent': 'OIL-Benchmarks-App'
          }
        });
        const emails = await emailsRes.json();
        if (Array.isArray(emails)) {
          const primary = emails.find(e => e.primary && e.verified);
          if (primary) email = primary.email;
          else if (emails.length > 0) email = emails[0].email;
        }
      } catch (_) { /* email optional */ }
    }

    const user = findOrCreateOAuthUser('github', {
      id: String(profile.id),
      name: profile.name || profile.login,
      email: email,
      login: profile.login
    });

    loginAndRedirect(req, res, user);
  } catch (err) {
    log.error({ err }, 'GitHub OAuth callback failed');
    res.redirect('/#oauth-error');
  }
});

// ── Status: check which providers are configured ─────────────────
router.get('/providers', (req, res) => {
  ok(res, {
    google: !!process.env.GOOGLE_CLIENT_ID,
    github: !!process.env.GITHUB_CLIENT_ID
  });
});

module.exports = router;
