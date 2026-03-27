/**
 * Web Push — VAPID-based browser push notifications
 *
 * VAPID keys can be provided via environment variables:
 *   VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_EMAIL
 *
 * If not set, keys are auto-generated on first run and stored
 * in the database so they persist across restarts.
 */

const webpush = require('web-push');
const db = require('../db');
const log = require('./logger').child({ module: 'web-push' });

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
    const keys = JSON.parse(row.value);
    return keys;
  }

  // Generate new keys
  const keys = webpush.generateVAPIDKeys();
  db.prepare("INSERT INTO config (key, value) VALUES ('vapid_keys', ?)").run(JSON.stringify(keys));
  log.info('Generated new VAPID keys');
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
 */
async function sendToUser(userId, payload) {
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

module.exports = {
  getPublicKey,
  saveSubscription,
  removeSubscription,
  removeUserSubscriptions,
  sendToUser
};
