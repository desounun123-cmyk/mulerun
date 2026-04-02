/**
 * server/utils/validate.js
 *
 * Backwards-compatible shim.
 *
 * All validation schemas and the validate() middleware factory now live in
 * server/validators/ (split by domain: auth, user, analytics, primitives).
 *
 * This file re-exports everything from the new module so that existing
 * imports continue to work without changes:
 *
 *   const { validate, schemas } = require('../utils/validate');   // still works
 *   const { validate, schemas } = require('../validators');       // preferred
 */
'use strict';

module.exports = require('../validators');
