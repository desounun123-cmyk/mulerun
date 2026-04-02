/**
 * server/validators/analytics.js
 *
 * Zod schemas for analytics endpoints — previously unvalidated.
 *
 * These two POST endpoints accepted raw req.body with only inline
 * sanitisation (typeof checks, string truncation). Moving validation
 * to declarative Zod schemas provides:
 *   - Consistent error format ({ ok: false, error, errors })
 *   - Type coercion (string → number for screenW/screenH)
 *   - Automatic trimming and length enforcement
 *   - Rejection of unexpected fields (strip unknown)
 *   - Defence-in-depth alongside the existing sanitizeStr() calls
 *
 * Endpoints:
 *   POST /api/analytics/pageview
 *   POST /api/analytics/event
 */
'use strict';

const { z, safeString, optionalSafeUrl, clampedInt } = require('./primitives');

// ── POST /api/analytics/pageview ────────────────────────────────────
// Tracks a page view. Sent by the client on every navigation.
// All fields except `page` are optional — the server falls back to
// User-Agent parsing and defaults when they're absent.
const pageview = z.object({
  /** Page path, e.g. "/", "/history", "/settings" */
  page: z
    .string()
    .trim()
    .min(1, 'Page path is required.')
    .max(2048, 'Page path is too long.')
    .transform(v => {
      // Strip query string and fragment for storage normalisation
      // but keep the original for referrer tracking
      return v;
    }),

  /** Referrer URL (document.referrer). Optional, nullable. */
  referrer: optionalSafeUrl,

  /** Screen width in CSS pixels. Optional, clamped 0-10000. */
  screenW: z
    .union([z.number(), z.string().transform(Number)])
    .pipe(z.number().int().min(0).max(10000))
    .optional()
    .nullable(),

  /** Screen height in CSS pixels. Optional, clamped 0-10000. */
  screenH: z
    .union([z.number(), z.string().transform(Number)])
    .pipe(z.number().int().min(0).max(10000))
    .optional()
    .nullable(),

  /** Browser language (navigator.language). Optional, max 10 chars. */
  lang: z
    .string()
    .trim()
    .max(10)
    .optional()
    .nullable(),

  /**
   * Bot detection score from the client-side fingerprint.
   * 0 = definitely human, 1 = definitely bot.
   * Optional — not all clients send it.
   */
  botScore: z
    .union([z.number(), z.string().transform(Number)])
    .pipe(z.number().min(0).max(1))
    .optional()
    .nullable(),

  /** Client-side bot signal strings for server-side decision. */
  botSignals: z
    .array(z.string().max(100))
    .max(20)
    .optional()
    .nullable(),
}).strip(); // remove unknown fields

// ── POST /api/analytics/event ───────────────────────────────────────
// Tracks a named event (button click, feature toggle, etc.).
// The `event` field is the event name; `meta` is an optional
// JSON-serialisable bag of context (max 2 KB stringified).
const event = z.object({
  /** Event name, e.g. "chart_zoom", "dark_mode_toggle", "alert_create" */
  event: z
    .string()
    .trim()
    .min(1, 'Event name is required.')
    .max(100, 'Event name is too long.')
    .regex(/^[a-zA-Z0-9_.-]+$/, 'Event name may only contain letters, numbers, underscores, dots, and hyphens.'),

  /**
   * Arbitrary metadata object. Stored as JSON string in the DB.
   * Validated to prevent oversized payloads (max 2 KB serialised).
   */
  meta: z
    .union([z.string().max(2048), z.record(z.unknown())])
    .optional()
    .nullable()
    .transform(v => {
      if (v === null || v === undefined) return null;
      // If it's an object, stringify to check size, keep as object for the handler
      if (typeof v === 'object') {
        const str = JSON.stringify(v);
        if (str.length > 2048) return null; // silently truncate oversized meta
        return v;
      }
      // If it's already a string, parse to validate it's JSON
      try {
        const parsed = JSON.parse(v);
        return parsed;
      } catch {
        return null;
      }
    }),

  /** Bot detection score (same as pageview). */
  botScore: z
    .union([z.number(), z.string().transform(Number)])
    .pipe(z.number().min(0).max(1))
    .optional()
    .nullable(),
}).strip();

module.exports = {
  pageview,
  event,
};
