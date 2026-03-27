const express = require('express');
const crypto = require('crypto');
const db = require('../db');

const router = express.Router();

// ── Helpers ──────────────────────────────────────────────────────

/** Build the full callback URL from the request */
function callbackUrl(req, provider) {
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const host = req.headers['x-forwarded-host'] || req.headers.host || 'localhost:8080';
  return `${proto}://${host}/api/oauth/${provider}/callback`;
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

  // Check if email already exists (link accounts)
  if (profile.email) {
    const byEmail = db.prepare('SELECT * FROM users WHERE email = ?').get(profile.email);
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
  const email = profile.email || `${provider}_${profile.id}@oauth.local`;
  const placeholderHash = '__oauth_no_password__';

  const result = db.prepare(
    'INSERT INTO users (name, email, password_hash, oauth_provider, oauth_id) VALUES (?, ?, ?, ?, ?)'
  ).run(name, email, placeholderHash, provider, profile.id);

  const userId = result.lastInsertRowid;

  // Create default settings
  db.prepare(
    'INSERT INTO user_settings (user_id, price_alerts, weekly_newsletter, dark_mode) VALUES (?, 1, 0, 1)'
  ).run(userId);

  // Track login
  db.prepare(
    "UPDATE users SET last_login = datetime('now'), login_count = 1 WHERE id = ?"
  ).run(userId);

  return db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
}

/** Set session and redirect to app */
function loginAndRedirect(req, res, user) {
  req.session.userId = user.id;
  req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days for OAuth
  res.redirect('/#oauth-success');
}

// ── Google OAuth ─────────────────────────────────────────────────

// Step 1: Redirect to Google
router.get('/google', (req, res) => {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) {
    return res.status(501).json({ error: 'Google OAuth not configured.' });
  }

  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;

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

    if (!code || !state || state !== req.session.oauthState) {
      return res.redirect('/#oauth-error');
    }
    delete req.session.oauthState;

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
      console.error('Google token exchange failed:', tokens);
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
    console.error('Google OAuth error:', err);
    res.redirect('/#oauth-error');
  }
});

// ── GitHub OAuth ─────────────────────────────────────────────────

// Step 1: Redirect to GitHub
router.get('/github', (req, res) => {
  const clientId = process.env.GITHUB_CLIENT_ID;
  if (!clientId) {
    return res.status(501).json({ error: 'GitHub OAuth not configured.' });
  }

  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;

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

    if (!code || !state || state !== req.session.oauthState) {
      return res.redirect('/#oauth-error');
    }
    delete req.session.oauthState;

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
      console.error('GitHub token exchange failed:', tokens);
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
    console.error('GitHub OAuth error:', err);
    res.redirect('/#oauth-error');
  }
});

// ── Status: check which providers are configured ─────────────────
router.get('/providers', (req, res) => {
  res.json({
    google: !!process.env.GOOGLE_CLIENT_ID,
    github: !!process.env.GITHUB_CLIENT_ID
  });
});

module.exports = router;
