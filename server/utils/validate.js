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
        const lower = val.toLowerCase().replace(/\s/g, '');
        return !/url\(|expression\(|javascript:|data:|@import|behavior:|;/.test(lower);
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
