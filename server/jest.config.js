/** @type {import('jest').Config} */
module.exports = {
  // ── Test discovery ──────────────────────────────────────────────
  // Only look for tests inside __tests__/, skip the shared helper module.
  roots: ['<rootDir>/__tests__'],
  testMatch: ['**/*.test.js', '**/*.spec.js'],
  testPathIgnorePatterns: [
    'helpers\\.js$',
    '/node_modules/',
  ],

  // ── Environment ─────────────────────────────────────────────────
  // The server is pure Node — no DOM needed.
  testEnvironment: 'node',

  // ── Babel transform ─────────────────────────────────────────────
  // db.js uses a top-level `return` (valid CommonJS, requires
  // sourceType: 'script').  babel.config.js handles the parser opts;
  // we just need babel-jest wired up.
  transform: {
    '\\.[jt]sx?$': ['babel-jest', { sourceType: 'script' }],
  },
  transformIgnorePatterns: ['/node_modules/'],

  // ── Setup ───────────────────────────────────────────────────────
  // helpers.js creates a per-worker temp SQLite database and
  // boots the Express app.  Importing it from every test file works,
  // but declaring it here as a setup module makes the dependency
  // explicit and guarantees it runs before any test in the worker.
  setupFilesAfterFramework: [],
  // NOTE: helpers.js is required directly by test files (it exports
  // app, db, request, loginAs, registerAndLogin).  If you want to
  // add global beforeAll / afterAll hooks that don't need exports,
  // create __tests__/setup.js and add it here:
  // setupFilesAfterFramework: ['<rootDir>/__tests__/setup.js'],

  // ── Timeouts ────────────────────────────────────────────────────
  // Default 5 s is tight when bcrypt hashing runs on slow CI runners
  // or when email transport initialisation takes a beat.
  testTimeout: 15000,

  // ── Module resolution ───────────────────────────────────────────
  // Short aliases so tests (and future code) can require('db')
  // instead of fragile relative paths like '../db/db'.
  moduleNameMapper: {
    '^@db$':       '<rootDir>/db/db',
    '^@db/(.*)$':  '<rootDir>/db/$1',
    '^@utils/(.*)$': '<rootDir>/utils/$1',
    '^@routes/(.*)$': '<rootDir>/routes/$1',
  },

  // ── Coverage ────────────────────────────────────────────────────
  collectCoverageFrom: [
    'routes/**/*.js',
    'utils/**/*.js',
    'db/**/*.js',
    'index.js',
    // Exclude vendored / generated files
    '!**/node_modules/**',
    '!**/__tests__/**',
    '!**/coverage/**',
  ],
  coverageDirectory: '<rootDir>/coverage',
  coverageReporters: ['text', 'text-summary', 'lcov', 'json-summary'],

  // Minimum coverage gates — these are starting-point floors.
  // Ratchet them upward as coverage improves; CI should fail if a
  // PR drops below these thresholds.
  coverageThreshold: {
    global: {
      branches:   40,
      functions:  50,
      lines:      50,
      statements: 50,
    },
    // Critical auth paths deserve a higher bar.
    './routes/auth.js': {
      branches:   60,
      functions:  70,
      lines:      70,
      statements: 70,
    },
  },

  // ── Parallelism ─────────────────────────────────────────────────
  // Each worker gets its own temp SQLite file (set up in helpers.js).
  // Running workers in band (sequentially) is safer for SQLite but
  // slower.  Parallel is fine because each worker has an isolated DB.
  // Set to 1 on memory-constrained CI if needed:
  //   maxWorkers: 1,

  // ── Diagnostics ─────────────────────────────────────────────────
  // Detect leaked timers, open DB handles, or lingering HTTP servers.
  // These flags are also passed via the npm script, but having them
  // here makes `npx jest` behave the same as `npm test`.
  detectOpenHandles: true,
  forceExit: true,

  // Surface slow tests so they can be optimised.
  slowTestThreshold: 3000,

  // ── Reporter ────────────────────────────────────────────────────
  // Default reporter with verbose output so CI logs show individual
  // test names (easier to spot regressions in long runs).
  verbose: true,
};
