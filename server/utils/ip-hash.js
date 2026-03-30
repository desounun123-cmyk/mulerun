/**
 * Salted IP hashing utility.
 *
 * Uses HMAC-SHA256 with a server-side secret so that IP hashes
 * cannot be reversed via rainbow tables even if logs or the DB leak.
 *
 * The salt is derived from IP_HASH_SALT or SESSION_SECRET. If neither
 * is set, a random value is generated (hashes won't survive restarts,
 * which is acceptable for ephemeral analytics/session data).
 */
const crypto = require('crypto');

const salt = process.env.IP_HASH_SALT
  || process.env.SESSION_SECRET
  || crypto.randomBytes(32).toString('hex');

/**
 * Return a truncated HMAC-SHA256 hex digest of the given value.
 * @param {string} value — the raw IP (or IP + extras) to hash
 * @param {number} [len=12] — hex characters to keep
 */
function hashIP(value, len) {
  return crypto.createHmac('sha256', salt)
    .update(value)
    .digest('hex')
    .slice(0, len || 12);
}

module.exports = { hashIP };
