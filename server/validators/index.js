/**
 * server/validators/index.js
 *
 * Barrel module that re-exports all validation schemas and the
 * validate() middleware factory.
 *
 * Migration path from the monolithic utils/validate.js:
 *   Before:  const { validate, schemas } = require('../utils/validate');
 *   After:   const { validate, schemas } = require('../validators');
 *
 * Both import styles work — utils/validate.js can be updated to
 * re-export from this module for backwards compatibility:
 *   module.exports = require('../validators');
 *
 * Directory structure:
 *   validators/
 *     index.js         ← this file (barrel + middleware)
 *     primitives.js    ← reusable field types (email, password, etc.)
 *     auth.js          ← registration, login, password, TOTP schemas
 *     user.js          ← profile, settings, alerts, push, avatar-bg
 *     analytics.js     ← pageview, event (NEW — previously unvalidated)
 */
'use strict';

const { z } = require('zod');
const primitives = require('./primitives');
const authSchemas = require('./auth');
const userSchemas = require('./user');
const analyticsSchemas = require('./analytics');

// ── Middleware factory ──────────────────────────────────────────────

/**
 * Express middleware that validates req[source] against a Zod schema.
 *
 * @param {z.ZodSchema} schema  — Zod schema to validate against
 * @param {'body'|'query'|'params'} source — which part of the request to validate
 * @returns {Function} Express middleware
 *
 * On success, replaces req[source] with the parsed (coerced/transformed) value
 * so downstream handlers receive clean, typed data.
 *
 * On failure, responds 400 with structured error details:
 *   { ok: false, error: "first issue message", errors: [{ path, message }] }
 */
function validate(schema, source) {
  if (source === undefined) source = 'body';
  return function validationMiddleware(req, res, next) {
    var result = schema.safeParse(req[source]);
    if (!result.success) {
      var issues = result.error.issues.map(function (i) {
        return {
          path: i.path.join('.'),
          message: i.message,
        };
      });
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

// ── Unified schemas object ─────────────────────────────────────────
// Flat namespace so existing code like `schemas.register` keeps working.

var schemas = {
  // Auth
  register: authSchemas.register,
  login: authSchemas.login,
  forgotPassword: authSchemas.forgotPassword,
  resetPassword: authSchemas.resetPassword,
  changePassword: authSchemas.changePassword,
  verifyToken: authSchemas.verifyToken,
  totpVerify: authSchemas.totpVerify,
  totpDisable: authSchemas.totpDisable,

  // User
  updateProfile: userSchemas.updateProfile,
  updateAvatarBg: userSchemas.updateAvatarBg,
  updateSettings: userSchemas.updateSettings,
  createAlert: userSchemas.createAlert,
  checkAlertPrices: userSchemas.checkAlertPrices,
  pushSubscribe: userSchemas.pushSubscribe,
  pushUnsubscribe: userSchemas.pushUnsubscribe,

  // Analytics (NEW)
  pageview: analyticsSchemas.pageview,
  analyticsEvent: analyticsSchemas.event,

  // Shared primitives (for ad-hoc validation in route handlers)
  idParam: primitives.idParam,
  cursorQuery: primitives.cursorQuery,
  pageQuery: primitives.pageQuery,
  positiveInt: primitives.positiveInt,
  email: primitives.email,
  password: primitives.password,
  userName: primitives.userName,
  totpCode: primitives.totpCode,
};

// ── Exports ────────────────────────────────────────────────────────

module.exports = {
  /** Middleware factory: validate(schema, 'body'|'query'|'params') */
  validate: validate,

  /** All schemas in a flat namespace */
  schemas: schemas,

  /** Zod instance for custom one-off schemas in route handlers */
  z: z,

  // Module-level re-exports for granular imports
  auth: authSchemas,
  user: userSchemas,
  analytics: analyticsSchemas,
  primitives: primitives,
};
