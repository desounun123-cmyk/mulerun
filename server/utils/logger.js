/**
 * Structured logger powered by pino with automatic log rotation.
 *
 * Behaviour by environment:
 *
 *   Development (NODE_ENV != 'production')
 *     - Logs to stdout as JSON lines (pipe to `pino-pretty` for colour)
 *     - No file rotation (unnecessary in dev)
 *
 *   Production (NODE_ENV === 'production')
 *     - Logs to a rotating file via pino-roll
 *     - Rotation trigger: size (LOG_MAX_SIZE, default 10 MB) **or**
 *       time (LOG_ROTATION_INTERVAL, default daily)
 *     - Old log files are kept up to LOG_MAX_FILES (default 14)
 *     - A copy is also sent to stdout so container log collectors
 *       (Docker, CloudWatch, etc.) still work
 *
 * Environment variables:
 *   LOG_LEVEL              — pino level  (default: debug/dev, info/prod)
 *   LOG_DIR                — directory for log files  (default: ./logs)
 *   LOG_MAX_SIZE           — max bytes per file before rotation  (default: 10485760 = 10 MB)
 *   LOG_ROTATION_INTERVAL  — time-based rotation: "daily", "hourly", or seconds  (default: daily)
 *   LOG_MAX_FILES          — how many rotated files to retain  (default: 14)
 *
 * Usage:
 *   const log = require('./logger');
 *   log.info({ userId: 42 }, 'User logged in');
 *   log.error({ err }, 'Something broke');
 *
 * Child loggers for sub-modules:
 *   const log = require('./logger').child({ module: 'auth' });
 */
const path = require('path');
const fs = require('fs');
const pino = require('pino');

const isDev = (process.env.NODE_ENV || 'development') !== 'production';

// ── Shared options (used in both dev and prod) ──────────────────
const sharedOptions = {
  level: process.env.LOG_LEVEL || (isDev ? 'debug' : 'info'),

  // Redact sensitive fields so they never appear in logs
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'req.headers["x-csrf-token"]',
      'password',
      'newPassword',
      'currentPassword',
      'token',
    ],
    censor: '[REDACTED]',
  },

  // Base fields included in every log line
  base: { service: 'oil-benchmarks' },

  // ISO timestamps are easier to search & sort
  timestamp: pino.stdTimeFunctions.isoTime,

  // Serialise Error objects automatically
  serializers: {
    err: pino.stdSerializers.err,
    req: pino.stdSerializers.req,
    res: pino.stdSerializers.res,
  },
};

// ── Build transport ─────────────────────────────────────────────
function buildTransport() {
  if (isDev) {
    // Dev: plain JSON to stdout (pipe through `pino-pretty` if desired)
    return {
      target: 'pino/file',
      options: { destination: 1 },
    };
  }

  // Production: rotating file + stdout tee
  const logDir = process.env.LOG_DIR
    ? path.resolve(process.env.LOG_DIR)
    : path.join(__dirname, 'logs');

  // Ensure log directory exists
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }

  // Parse rotation interval
  const intervalEnv = (process.env.LOG_ROTATION_INTERVAL || 'daily').toLowerCase();
  let frequencyMs;
  if (intervalEnv === 'daily') {
    frequencyMs = 86400000;         // 24 h
  } else if (intervalEnv === 'hourly') {
    frequencyMs = 3600000;          // 1 h
  } else {
    const parsed = parseInt(intervalEnv, 10);
    frequencyMs = parsed > 0 ? parsed * 1000 : 86400000;
  }

  const maxSize = parseInt(process.env.LOG_MAX_SIZE, 10) || 10 * 1024 * 1024; // 10 MB
  const maxFiles = parseInt(process.env.LOG_MAX_FILES, 10) || 14;

  return {
    targets: [
      // 1. Rotating log files
      {
        target: 'pino-roll',
        options: {
          file: path.join(logDir, 'app.log'),
          frequency: frequencyMs,
          size: maxSize,
          limit: { count: maxFiles },
          mkdir: true,
          dateFormat: 'yyyy-MM-dd-HH-mm',
          extension: '.log',
        },
        level: sharedOptions.level,
      },
      // 2. Stdout (for container log collectors / docker logs)
      {
        target: 'pino/file',
        options: { destination: 1 },
        level: sharedOptions.level,
      },
    ],
  };
}

const logger = pino(sharedOptions, pino.transport(buildTransport()));

module.exports = logger;
