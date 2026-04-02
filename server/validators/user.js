/**
 * server/validators/user.js
 *
 * Zod schemas for user-facing endpoints:
 *   PUT    /api/user/profile
 *   PUT    /api/user/avatar-bg
 *   PUT    /api/user/settings
 *   POST   /api/user/alerts
 *   DELETE /api/user/alerts/:id
 *   POST   /api/user/alerts/check
 *   POST   /api/user/alerts/:id/reset
 *   PUT    /api/user/notifications/:id/read
 *   DELETE /api/user/notifications/:id
 *   POST   /api/user/push/subscribe
 *   POST   /api/user/push/unsubscribe
 *
 * Also contains the CSS injection prevention logic for avatar_bg,
 * which is security-critical and better kept alongside its schema
 * than in a generic utils file.
 */
'use strict';

const { z, userName } = require('./primitives');

// ── CSS injection prevention for avatar_bg ──────────────────────────
// The avatar_bg field accepts CSS color values and gradients, which are
// interpolated into a style attribute.  An attacker can try to inject
// arbitrary CSS (url() for data exfiltration, expression() for XSS in
// legacy IE, @import for stylesheet injection, etc.) by obfuscating
// the payload with bypass techniques:
//
//   CSS comments:          ur/**/l(evil)        → url(evil)
//   CSS escape sequences:  \75rl(evil)          → url(evil)
//   Zero-width Unicode:    u\u200Brl(evil)      → url(evil)
//   Null bytes:            u\0rl(evil)          → url(evil)
//   Mixed case + escapes:  UR\4C(evil)          → url(evil)
//
// Defence: normalise the input by stripping all obfuscation layers
// *before* running the denylist, then verify that only known-safe
// CSS functions appear in the value.

/** Strip CSS comments (including nested/broken attempts). */
function stripCssComments(str) {
  return str.replace(/\/\*[\s\S]*?(\*\/|$)/g, '');
}

/**
 * Decode CSS escape sequences:
 *   \XX to \XXXXXX (1-6 hex digits, optionally followed by one space)
 *   \<char>        (any non-hex character escaped with backslash)
 */
function decodeCssEscapes(str) {
  let result = str.replace(/\\([0-9a-fA-F]{1,6})\s?/g, (_, hex) => {
    const cp = parseInt(hex, 16);
    if (cp === 0 || cp > 0x10FFFF) return '\uFFFD';
    try { return String.fromCodePoint(cp); } catch { return '\uFFFD'; }
  });
  result = result.replace(/\\([^0-9a-fA-F])/g, '$1');
  return result;
}

/** Remove invisible / zero-width Unicode characters that CSS parsers ignore. */
function stripInvisibleChars(str) {
  // eslint-disable-next-line no-control-regex
  return str.replace(/[\x00\u00AD\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF\uFFF9-\uFFFB]/g, '');
}

/** Fully normalise a CSS value so no obfuscation layer survives. */
function normaliseCssValue(raw) {
  let v = raw;
  v = stripCssComments(v);
  v = decodeCssEscapes(v);
  v = stripInvisibleChars(v);
  v = v.toLowerCase();
  v = v.replace(/\s+/g, ' ').trim();
  return v;
}

/** Allowlisted CSS function names for avatar backgrounds. */
const ALLOWED_CSS_FUNCTIONS = new Set([
  'rgb', 'rgba', 'hsl', 'hsla', 'hwb', 'lab', 'lch', 'oklch', 'oklab',
  'color', 'color-mix', 'light-dark',
  'linear-gradient', 'radial-gradient', 'conic-gradient',
  'repeating-linear-gradient', 'repeating-radial-gradient', 'repeating-conic-gradient',
]);

/**
 * Validate an avatar background CSS value.
 * Returns true if safe, false if injection is detected.
 */
function isAvatarBgSafe(raw) {
  const v = normaliseCssValue(raw);

  // Hard denylist — these should never appear even after normalisation
  if (/url\s*\(|expression\s*\(|javascript:|data:|@import|behavior:|binding:|;|\{|\}/.test(v)) {
    return false;
  }

  // Verify every function call is in the allowlist
  const fnCalls = v.matchAll(/([a-z][\w-]*)\s*\(/g);
  for (const m of fnCalls) {
    if (!ALLOWED_CSS_FUNCTIONS.has(m[1])) {
      return false;
    }
  }

  // Length sanity check — gradients can be long but not unbounded
  if (v.length > 1000) return false;

  return true;
}

// ── Schemas ─────────────────────────────────────────────────────────

const updateProfile = z.object({
  name: userName,
});

const updateAvatarBg = z.object({
  avatarBg: z
    .string()
    .nullable()
    .optional()
    .refine(
      (val) => {
        if (val === null || val === undefined) return true;
        return isAvatarBgSafe(val);
      },
      { message: 'Invalid avatar background value.' }
    ),
});

const updateSettings = z.object({
  priceAlerts: z.boolean().optional(),
  weeklyNewsletter: z.boolean().optional(),
  darkMode: z.boolean().optional(),
  notifyEmail: z.boolean().optional(),
  notifyInapp: z.boolean().optional(),
  notifyPush: z.boolean().optional(),
});

const createAlert = z.object({
  product: z.enum(['WTI', 'BRENT', 'HO', 'GAS'], {
    errorMap: () => ({ message: 'Product must be one of: WTI, BRENT, HO, GAS' }),
  }),
  direction: z.enum(['above', 'below'], {
    errorMap: () => ({ message: 'Direction must be "above" or "below".' }),
  }),
  threshold: z
    .union([z.number(), z.string().transform(Number)])
    .pipe(
      z.number({ invalid_type_error: 'Threshold must be a positive number.' })
       .positive('Threshold must be a positive number.')
       .max(999999, 'Threshold must be at most 999999.')
    ),
});

const checkAlertPrices = z.object({
  prices: z
    .record(z.string(), z.union([z.number(), z.string().transform(Number)]))
    .refine((v) => v && typeof v === 'object', { message: 'prices object required.' }),
});

const pushSubscribe = z.object({
  subscription: z.object({
    endpoint: z.string().min(1),
    keys: z.object({}).passthrough(),
  }).passthrough(),
});

const pushUnsubscribe = z.object({
  endpoint: z.string().min(1, 'Endpoint is required.'),
});

// ── Exports ─────────────────────────────────────────────────────────
module.exports = {
  updateProfile,
  updateAvatarBg,
  updateSettings,
  createAlert,
  checkAlertPrices,
  pushSubscribe,
  pushUnsubscribe,

  // Exported for testing
  _isAvatarBgSafe: isAvatarBgSafe,
  _normaliseCssValue: normaliseCssValue,
};
