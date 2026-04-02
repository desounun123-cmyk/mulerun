/**
 * Web Push — VAPID-based browser push notifications
 *
 * VAPID keys can be provided via environment variables:
 *   VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_EMAIL
 *
 * If not set, keys are auto-generated on first run and stored
 * in the database **encrypted at rest** (AES-256-GCM) so that a
 * database compromise does not expose the server's push identity.
 *
 * The encryption key is derived from SESSION_SECRET via PBKDF2.
 * If SESSION_SECRET is not set (dev mode), keys are stored in plaintext.
 */

const crypto = require('crypto');
const webpush = require('web-push');
const db = require('../db/db');
const log = require('./logger').child({ module: 'web-push' });

// ── Encryption helpers (AES-256-GCM) ─────────────────────────────
// Derive a 32-byte key from SESSION_SECRET using PBKDF2 with a fixed
// application-specific salt. The salt doesn't need to be secret — it
// just ensures this derivation is distinct from other uses of the secret.
const VAPID_ENC_SALT = 'oil-benchmarks:vapid-key-encryption';
const SESSION_SECRET = process.env.SESSION_SECRET;

function deriveKey() {
  if (!SESSION_SECRET) return null;
  return crypto.pbkdf2Sync(SESSION_SECRET, VAPID_ENC_SALT, 100_000, 32, 'sha256');
}

/**
 * Encrypt a plaintext string. Returns "aes-256-gcm:<iv>:<authTag>:<ciphertext>"
 * all hex-encoded. Returns null if no encryption key is available.
 */
function encrypt(plaintext) {
  const key = deriveKey();
  if (!key) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let enc = cipher.update(plaintext, 'utf8', 'hex');
  enc += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return `aes-256-gcm:${iv.toString('hex')}:${tag}:${enc}`;
}

/**
 * Decrypt a value produced by encrypt(). Returns the plaintext string.
 * Throws on tampered data or wrong key.
 */
function decrypt(encoded) {
  const key = deriveKey();
  if (!key) throw new Error('Cannot decrypt VAPID keys: SESSION_SECRET not set');
  const parts = encoded.split(':');
  // "aes-256-gcm" : iv : authTag : ciphertext
  if (parts.length !== 4 || parts[0] !== 'aes-256-gcm') {
    throw new Error('Unrecognised encryption format');
  }
  const iv = Buffer.from(parts[1], 'hex');
  const tag = Buffer.from(parts[2], 'hex');
  const ciphertext = parts[3];
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  let dec = decipher.update(ciphertext, 'hex', 'utf8');
  dec += decipher.final('utf8');
  return dec;
}

/** Returns true if the stored value is encrypted (vs legacy plaintext JSON). */
function isEncrypted(value) {
  return typeof value === 'string' && value.startsWith('aes-256-gcm:');
}

// ── VAPID key management ──────────────────────────────────────────

// Key-value config table (created if missing)
db.exec(`
  CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

function getOrCreateVapidKeys() {
  let publicKey = process.env.VAPID_PUBLIC_KEY;
  let privateKey = process.env.VAPID_PRIVATE_KEY;

  if (publicKey && privateKey) {
    return { publicKey, privateKey };
  }

  // Try loading from DB
  const row = db.prepare("SELECT value FROM config WHERE key = 'vapid_keys'").get();
  if (row) {
    let keys;
    if (isEncrypted(row.value)) {
      // Stored encrypted — decrypt
      const json = decrypt(row.value);
      keys = JSON.parse(json);
    } else {
      // Legacy plaintext — parse and upgrade to encrypted if possible
      keys = JSON.parse(row.value);
      const encrypted = encrypt(JSON.stringify(keys));
      if (encrypted) {
        db.prepare("UPDATE config SET value = ? WHERE key = 'vapid_keys'").run(encrypted);
        log.info('Upgraded VAPID keys from plaintext to encrypted storage');
      }
    }
    return keys;
  }

  // Generate new keys — store encrypted if SESSION_SECRET is available
  const keys = webpush.generateVAPIDKeys();
  const payload = encrypt(JSON.stringify(keys)) || JSON.stringify(keys);
  db.prepare("INSERT INTO config (key, value) VALUES ('vapid_keys', ?)").run(payload);
  log.info('Generated new VAPID keys');
  if (!SESSION_SECRET) {
    log.warn('SESSION_SECRET not set — VAPID keys stored in plaintext. Set SESSION_SECRET to enable encryption at rest.');
  }
  return keys;
}

const vapidKeys = getOrCreateVapidKeys();
const vapidEmail = process.env.VAPID_EMAIL || 'mailto:noreply@oilbenchmarks.com';

webpush.setVapidDetails(vapidEmail, vapidKeys.publicKey, vapidKeys.privateKey);

// ── Push subscriptions table ──────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS push_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    endpoint TEXT NOT NULL,
    keys_p256dh TEXT NOT NULL,
    keys_auth TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE UNIQUE INDEX IF NOT EXISTS idx_push_endpoint ON push_subscriptions(endpoint);
  CREATE INDEX IF NOT EXISTS idx_push_user ON push_subscriptions(user_id);
`);

// ── Per-user send mutex ───────────────────────────────────────────
// Serialises concurrent sendToUser() calls for the same userId so that:
//   1. Only one send loop iterates a user's subscription list at a time
//   2. Expired-subscription DELETEs from one call are visible to the next
//   3. No wasted network round-trips to already-removed endpoints
//   4. Sends to *different* users remain fully concurrent (independent chains)
//
// Implementation: a Map of userId → tail Promise. Each new send chains
// off the previous one for that user. Entries self-clean when the chain
// settles so the Map doesn't grow unbounded.
const _userSendLocks = new Map();

/**
 * Acquire the per-user lock, execute `fn`, then release.
 * Returns the result of `fn()`. If the lock holder throws, the error
 * propagates to the caller and the lock is still released for the next
 * queued send.
 */
function _withUserLock(userId, fn) {
  const prev = _userSendLocks.get(userId) || Promise.resolve();

  // Chain this call after whatever is currently running for this user.
  // Use .then() on the *previous* promise so we wait for it, but we
  // catch its errors to avoid short-circuiting our own work.
  const next = prev.catch(() => {}).then(fn);

  _userSendLocks.set(userId, next);

  // Self-clean: if this is still the tail when it settles, remove
  // the entry so the Map doesn't accumulate stale keys.
  next.finally(() => {
    if (_userSendLocks.get(userId) === next) {
      _userSendLocks.delete(userId);
    }
  });

  return next;
}

// ── In-flight push tracker ─────────────────────────────────────────
// Every sendToUser() call is tracked so that:
//   1. Graceful shutdown can await all pending deliveries via drain()
//   2. Under high load, we can observe how many pushes are in progress
//   3. Fire-and-forget callers get automatic error handling without
//      risking unhandled rejections
const _inflight = new Set();

/**
 * Track a promise in the in-flight set. Automatically removes itself
 * when the promise settles (fulfilled or rejected). Rejections are
 * caught here so untracked `.catch()` callers cannot produce
 * unhandled-rejection crashes.
 */
function _track(promise) {
  _inflight.add(promise);
  const cleanup = () => _inflight.delete(promise);
  promise.then(cleanup, (err) => {
    cleanup();
    // Already logged inside sendToUser — this catch only prevents
    // the rejection from becoming unhandled at the process level.
    log.warn({ err }, 'Tracked push delivery rejected');
  });
  return promise;
}

/**
 * Wait for all in-flight push notifications to settle.
 * Called during graceful shutdown so pending deliveries finish
 * before the process exits and the DB connection closes.
 *
 * @param {number} [timeoutMs=5000] — max time to wait before giving up
 * @returns {Promise<{ drained: number, timedOut: boolean }>}
 */
async function drain(timeoutMs = 5000) {
  const pending = _inflight.size;
  if (pending === 0) return { drained: 0, timedOut: false };

  log.info({ pending }, 'Draining in-flight push notifications');

  const allSettled = Promise.allSettled([..._inflight]);
  const timeout = new Promise((resolve) =>
    setTimeout(() => resolve('timeout'), timeoutMs)
  );

  const result = await Promise.race([allSettled, timeout]);
  const timedOut = result === 'timeout';
  const remaining = _inflight.size;

  if (timedOut) {
    log.warn({ pending, remaining, timeoutMs },
      'Push drain timed out — some notifications may not have been delivered');
  } else {
    log.info({ drained: pending }, 'All in-flight push notifications settled');
  }

  return { drained: pending - remaining, timedOut };
}

/**
 * Returns the number of push notifications currently in flight.
 */
function inflightCount() {
  return _inflight.size;
}

// ── Public API ────────────────────────────────────────────────────

/**
 * Returns the VAPID public key (needed by the frontend to subscribe).
 */
function getPublicKey() {
  return vapidKeys.publicKey;
}

/**
 * Save a push subscription for a user.
 * If the endpoint already exists, update the keys.
 */
function saveSubscription(userId, subscription) {
  const { endpoint, keys } = subscription;
  if (!endpoint || !keys || !keys.p256dh || !keys.auth) {
    throw new Error('Invalid push subscription object');
  }

  const existing = db.prepare('SELECT id, user_id FROM push_subscriptions WHERE endpoint = ?').get(endpoint);
  if (existing) {
    db.prepare('UPDATE push_subscriptions SET user_id = ?, keys_p256dh = ?, keys_auth = ? WHERE id = ?')
      .run(userId, keys.p256dh, keys.auth, existing.id);
  } else {
    // Enforce a per-user cap to prevent table flooding.
    const MAX_SUBSCRIPTIONS_PER_USER = 5;
    const count = db.prepare('SELECT COUNT(*) as c FROM push_subscriptions WHERE user_id = ?').get(userId).c;
    if (count >= MAX_SUBSCRIPTIONS_PER_USER) {
      // Evict the oldest subscription to make room for the new one.
      db.prepare(
        'DELETE FROM push_subscriptions WHERE id = (SELECT id FROM push_subscriptions WHERE user_id = ? ORDER BY id ASC LIMIT 1)'
      ).run(userId);
    }
    db.prepare('INSERT INTO push_subscriptions (user_id, endpoint, keys_p256dh, keys_auth) VALUES (?, ?, ?, ?)')
      .run(userId, endpoint, keys.p256dh, keys.auth);
  }
}

/**
 * Remove a push subscription by endpoint.
 */
function removeSubscription(endpoint) {
  db.prepare('DELETE FROM push_subscriptions WHERE endpoint = ?').run(endpoint);
}

/**
 * Remove all subscriptions for a user.
 */
function removeUserSubscriptions(userId) {
  db.prepare('DELETE FROM push_subscriptions WHERE user_id = ?').run(userId);
}

/**
 * Send a push notification to all subscriptions for a user.
 * Returns the number of successful deliveries.
 *
 * Serialised per-user: concurrent calls for the same userId are queued
 * so subscription-list reads and expired-endpoint DELETEs don't race.
 * Calls for different users run fully in parallel.
 *
 * The returned promise is automatically tracked in the in-flight set
 * so graceful shutdown can await it via drain().
 */
function sendToUser(userId, payload) {
  return _withUserLock(userId, () => _sendToUserInner(userId, payload));
}

/**
 * Inner implementation — must only be called via _withUserLock() to
 * guarantee exclusive access to a user's subscription list.
 */
async function _sendToUserInner(userId, payload) {
  const subs = db.prepare('SELECT * FROM push_subscriptions WHERE user_id = ?').all(userId);
  if (subs.length === 0) return 0;

  const body = JSON.stringify(payload);
  let sent = 0;

  for (const sub of subs) {
    const pushSub = {
      endpoint: sub.endpoint,
      keys: { p256dh: sub.keys_p256dh, auth: sub.keys_auth }
    };

    try {
      await webpush.sendNotification(pushSub, body);
      sent++;
    } catch (err) {
      if (err.statusCode === 404 || err.statusCode === 410) {
        // Subscription expired or unsubscribed — clean up
        db.prepare('DELETE FROM push_subscriptions WHERE id = ?').run(sub.id);
        log.info({ endpoint: sub.endpoint }, 'Removed expired push subscription');
      } else {
        log.error({ err, endpoint: sub.endpoint }, 'Push notification failed');
      }
    }
  }

  return sent;
}

/**
 * Fire-and-forget variant of sendToUser(). The call is:
 *   - Tracked in the in-flight set (so drain() awaits it at shutdown)
 *   - Guarded against unhandled rejections (errors are logged, not thrown)
 *
 * Use this from route handlers where you've already sent the HTTP
 * response and want to deliver push notifications asynchronously
 * without blocking or leaking promises.
 *
 * @param {number} userId
 * @param {object} payload
 * @returns {void} — intentionally returns nothing; the caller should
 *                    not await this (that's the whole point).
 */
function sendToUserAsync(userId, payload) {
  _track(sendToUser(userId, payload));
}

module.exports = {
  getPublicKey,
  saveSubscription,
  removeSubscription,
  removeUserSubscriptions,
  sendToUser,
  sendToUserAsync,
  drain,
  inflightCount,
};
