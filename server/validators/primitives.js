/**
 * server/validators/primitives.js
 *
 * Reusable Zod primitives shared across all schema modules.
 * Keep field-level types here so auth.js, user.js, analytics.js,
 * and future modules can import without circular dependencies.
 */
'use strict';

const { z } = require('zod');

// ── Numeric helpers ────────────────────────────────────────────────

/** Positive integer — accepts number or numeric string, always outputs number */
const positiveInt = z
  .union([z.number().int().positive(), z.string().regex(/^\d+$/).transform(Number)])
  .pipe(z.number().int().positive());

// ── Pagination ─────────────────────────────────────────────────────

/** Cursor-based pagination query (?cursor=&limit=) */
const cursorQuery = z.object({
  cursor: z.string().regex(/^\d+$/).transform(Number).optional(),
  limit: z.string().regex(/^\d+$/).transform(Number)
    .pipe(z.number().int().min(1).max(100)).optional(),
}).passthrough();

/** Offset-based pagination query (?page=&limit=) */
const pageQuery = z.object({
  page: z.string().regex(/^\d+$/).transform(Number)
    .pipe(z.number().int().min(1)).optional(),
  limit: z.string().regex(/^\d+$/).transform(Number)
    .pipe(z.number().int().min(1).max(100)).optional(),
}).passthrough();

// ── Identity fields ────────────────────────────────────────────────

/** Email — trimmed, lowercased, max 254 chars per RFC 5321 */
const email = z
  .string()
  .trim()
  .toLowerCase()
  .min(1, 'Email is required.')
  .max(254, 'Email must be 254 characters or fewer.')
  .email('Please provide a valid email address.');

/** Password — min 8 chars */
const password = z
  .string()
  .min(8, 'Password must be at least 8 characters.');

/** Non-empty password (presence check only, length validated elsewhere) */
const passwordRequired = z
  .string()
  .min(1, 'Password is required.');

/** User-visible name — HTML stripped, trimmed, 1-100 chars */
const userName = z
  .string()
  .min(1, 'Name is required.')
  .max(200, 'Name is too long.')
  .transform(v => v.replace(/<[^>]*>/g, '').trim())
  .pipe(z.string().min(1, 'Name must contain valid characters.').max(100, 'Name must be 100 characters or fewer.'));

/** TOTP 6-digit code */
const totpCode = z
  .string()
  .regex(/^\d{6}$/, 'A valid 6-digit code is required.');

/** ID path parameter — numeric string from Express :id */
const idParam = z.object({
  id: z.string().regex(/^\d+$/, 'Invalid ID.').transform(Number),
});

// ── Generic sanitisers ─────────────────────────────────────────────

/**
 * Short free-text string — trimmed, HTML stripped, bounded length.
 * Useful for analytics fields, search terms, short user input.
 *
 * @param {number} max - max length after sanitisation (default 500)
 */
function safeString(max = 500) {
  return z
    .string()
    .max(max * 2) // raw limit before transform
    .transform(v => v.replace(/<[^>]*>/g, '').trim())
    .pipe(z.string().max(max));
}

/**
 * URL string — trimmed, max 2048 chars, must look like a URL.
 * Accepts both absolute and relative paths.
 */
const safeUrl = z
  .string()
  .trim()
  .max(2048, 'URL is too long.')
  .refine(
    v => v.startsWith('/') || v.startsWith('http://') || v.startsWith('https://'),
    { message: 'Must be a valid URL or path.' }
  );

/** Optional safe URL — allows null/undefined/empty */
const optionalSafeUrl = z
  .string()
  .trim()
  .max(2048)
  .optional()
  .nullable()
  .transform(v => (v === '' ? null : v));

/**
 * Clamped integer — accepts number or numeric string, clamps to [min, max].
 * Useful for screen dimensions, scores, etc. that should never cause errors.
 */
function clampedInt(min, max) {
  return z
    .union([z.number(), z.string().transform(Number)])
    .pipe(z.number().int())
    .transform(v => Math.max(min, Math.min(max, v)));
}

// ── Exports ────────────────────────────────────────────────────────
module.exports = {
  z,
  positiveInt,
  cursorQuery,
  pageQuery,
  email,
  password,
  passwordRequired,
  userName,
  totpCode,
  idParam,
  safeString,
  safeUrl,
  optionalSafeUrl,
  clampedInt,
};
