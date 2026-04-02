/**
 * Centralized request validation using Zod.
 *
 * Usage in route handlers:
 *   const { validate, schemas } = require('../utils/validate');
 *   router.post('/foo', validate(schemas.createAlert, 'body'), handler);
 *   router.get('/bar', validate(schemas.cursorQuery, 'query'), handler);
 *
 * On validation failure, responds with:
 *   { ok: false, error: "…first issue…", errors: [ { path, message }, … ] }
 */
const { z } = require('zod');

// ── Reusable primitives ──────────────────────────────────────────

// Positive integer (for IDs, parsed from string params)
const positiveInt = z
  .union([z.number().int().positive(), z.string().regex(/^\d+$/).transform(Number)])
  .pipe(z.number().int().positive());

// Cursor-based pagination query (shared by notifications, alerts, etc.)
const cursorQuery = z.object({
  cursor: z.string().regex(/^\d+$/).transform(Number).optional(),
  limit: z.string().regex(/^\d+$/).transform(Number).pipe(z.number().int().min(1).max(100)).optional(),
}).passthrough(); // allow extra query params like `page`

// Offset-based pagination query (legacy fallback)
const pageQuery = z.object({
  page: z.string().regex(/^\d+$/).transform(Number).pipe(z.number().int().min(1)).optional(),
  limit: z.string().regex(/^\d+$/).transform(Number).pipe(z.number().int().min(1).max(100)).optional(),
}).passthrough();

// Email — trimmed, lowercased, max 254 chars per RFC 5321
const email = z
  .string()
  .trim()
  .toLowerCase()
  .min(1, 'Email is required.')
  .max(254, 'Email must be 254 characters or fewer.')
  .email('Please provide a valid email address.');

// Password — min 8 chars
const password = z
  .string()
  .min(8, 'Password must be at least 8 characters.');

// Non-empty password (for fields that just need presence, length checked elsewhere)
const passwordRequired = z
  .string()
  .min(1, 'Password is required.');

// User-visible name — stripped of HTML, trimmed, 1-100 chars
const userName = z
  .string()
  .min(1, 'Name is required.')
  .max(200, 'Name is too long.') // raw limit before sanitize
  .transform(v => v.replace(/<[^>]*>/g, '').trim())
  .pipe(z.string().min(1, 'Name must contain valid characters.').max(100, 'Name must be 100 characters or fewer.'));

// TOTP 6-digit code
const totpCode = z
  .string()
  .regex(/^\d{6}$/, 'A valid 6-digit code is required.');

// ID path parameter (always a string from Express)
const idParam = z.object({
  id: z.string().regex(/^\d+$/, 'Invalid ID.').transform(Number),
});

// ── Auth schemas ─────────────────────────────────────────────────

const register = z.object({
  name: userName,
  email: email,
  password: password,
  captchaAnswer: z.union([z.number(), z.string()]).optional().nullable(),
});

const login = z.object({
  email: z.string().min(1, 'Email is required.'),
  password: z.string().min(1, 'Password is required.'),
  rememberMe: z.boolean().optional(),
  captchaAnswer: z.union([z.number(), z.string()]).optional().nullable(),
  totpToken: z.string().optional(),
});

const forgotPassword = z.object({
  email: z.string().min(1, 'Email is required.'),
});

const resetPassword = z.object({
  token: z.string().min(1, 'Token is required.'),
  newPassword: password,
});

const changePassword = z.object({
  currentPassword: z.string().min(1, 'Current password is required.'),
  newPassword: password,
});

const verifyToken = z.object({
  token: z.string().min(1, 'Verification token is required.'),
});

const totpVerify = z.object({
  token: totpCode,
});

const totpDisable = z.object({
  password: z.string().min(1, 'Password is required to disable 2FA.'),
});

// ── CSS injection prevention for avatar_bg ──────────────────────
// The avatar_bg field accepts CSS color values and gradients, which are
// interpolated into a style attribute.  An attacker can try to inject
// arbitrary CSS (url() for data exfiltration, expression() for XSS in
// legacy IE, @import for stylesheet injection, etc.) by obfuscating
// the payload with bypass techniques that the raw denylist regex misses:
//
//   CSS comments:          ur/**/l(evil)        → url(evil)
//   CSS escape sequences:  \75rl(evil)          → url(evil)   (\75 = 'u')
//   Zero-width Unicode:    u\u200Brl(evil)      → url(evil)
//   Null bytes:            u\0rl(evil)          → url(evil)
//   Mixed case + escapes:  UR\4C(evil)          → url(evil)
//
// Defence: normalise the input by stripping all obfuscation layers
// *before* running the denylist, then additionally verify that only
// known-safe CSS functions appear in the value.

/**
 * Strip CSS comments (including nested/broken attempts).
 * Handles: / *..* /, unclosed comments, and stacked comments.
 */
function stripCssComments(str) {
  return str.replace(/\/\*[\s\S]*?(\*\/|$)/g, '');
}

/**
 * Decode CSS escape sequences:
 *   \XX  to \XXXXXX  (1-6 hex digits, optionally followed by one space)
 *   \<char>          (any non-hex character escaped with backslash)
 *
 * This mirrors how CSS parsers resolve escape sequences so that
 * `\75rl(` is normalised to `url(` before the denylist runs.
 */
function decodeCssEscapes(str) {
  // 1. Hex escapes: backslash + 1-6 hex digits + optional trailing space
  let result = str.replace(/\\([0-9a-fA-F]{1,6})\s?/g, (_, hex) => {
    const cp = parseInt(hex, 16);
    // Replace unprintable / invalid code points with U+FFFD
    if (cp === 0 || cp > 0x10FFFF) return '\uFFFD';
    try { return String.fromCodePoint(cp); } catch { return '\uFFFD'; }
  });
  // 2. Character escapes: backslash + any non-hex-digit character
  result = result.replace(/\\([^0-9a-fA-F])/g, '$1');
  return result;
}

/**
 * Remove invisible / zero-width Unicode characters that CSS parsers
 * ignore but regex patterns don't account for.
 *
 * Covers: null, zero-width space, zero-width non-joiner, zero-width
 * joiner, BOM, soft hyphen, word joiner, zero-width no-break space,
 * left/right-to-left marks/overrides, and other format characters.
 */
function stripInvisibleChars(str) {
  // eslint-disable-next-line no-control-regex
  return str.replace(/[\x00\u00AD\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF\uFFF9-\uFFFB]/g, '');
}

/**
 * Fully normalise a CSS value so no obfuscation layer survives.
 * The output is safe to test against literal pattern matches.
 */
function normaliseCssValue(raw) {
  let v = raw;
  v = stripCssComments(v);      // ur/**/l(  →  url(
  v = decodeCssEscapes(v);      // \75rl(    →  url(
  v = stripInvisibleChars(v);   // u\u200Brl → url
  v = v.toLowerCase();          // URL(      →  url(
  v = v.replace(/\s+/g, ' ').trim();
  return v;
}

// Allowlisted CSS function names.  Only colour and gradient functions
// are legitimate for an avatar background.  Anything else is rejected.
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

  // Extract all function calls (word followed by opening paren) and
  // verify each one is in the allowlist.
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

// ── User schemas ─────────────────────────────────────────────────

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

// ── Middleware factory ────────────────────────────────────────────

/**
 * Express middleware that validates req[source] against a Zod schema.
 *
 * @param {z.ZodSchema} schema  — Zod schema to validate against
 * @param {'body'|'query'|'params'} source — which part of the request to validate
 * @returns {Function} Express middleware
 *
 * On success, replaces req[source] with the parsed (coerced/transformed) value.
 * On failure, responds 400 with structured error details.
 */
function validate(schema, source = 'body') {
  return (req, res, next) => {
    const result = schema.safeParse(req[source]);
    if (!result.success) {
      const issues = result.error.issues.map((i) => ({
        path: i.path.join('.'),
        message: i.message,
      }));
      return res.status(400).json({
        ok: false,
        error: issues[0].message,
        errors: issues,
      });
    }
    // Replace with parsed data (includes transforms like trim, toLowerCase)
    req[source] = result.data;
    next();
  };
}

// ── Exports ──────────────────────────────────────────────────────

const schemas = {
  // Auth
  register,
  login,
  forgotPassword,
  resetPassword,
  changePassword,
  verifyToken,
  totpVerify,
  totpDisable,

  // User
  updateProfile,
  updateAvatarBg,
  updateSettings,
  createAlert,
  checkAlertPrices,
  pushSubscribe,
  pushUnsubscribe,

  // Shared
  idParam,
  cursorQuery,
  pageQuery,
  positiveInt,
  email,
  password,
  userName,
  totpCode,
};

module.exports = { validate, schemas, z };
