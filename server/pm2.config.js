/**
 * pm2.config.js — PM2 ecosystem file for OIL Benchmarks
 *
 * Provides automatic restarts, clustering, log management, and memory
 * limits for bare-metal / VM deployments where no PaaS process manager
 * is available.
 *
 * Usage:
 *   pm2 start pm2.config.js                    # start all apps
 *   pm2 start pm2.config.js --only oil-web     # start web only
 *   pm2 start pm2.config.js --env production   # use production env
 *   pm2 reload pm2.config.js                   # zero-downtime reload
 *   pm2 save                                   # persist process list
 *   pm2 startup                                # auto-start on boot
 *
 * Logs:
 *   pm2 logs oil-web
 *   pm2 logs oil-web --lines 200
 *
 * Monitoring:
 *   pm2 monit
 *   pm2 plus          (cloud dashboard)
 */
module.exports = {
  apps: [
    // ── Primary web server ───────────────────────────────────────
    {
      name: 'oil-web',
      script: './server/index.js',
      cwd: './',

      // ── Clustering ─────────────────────────────────────────────
      // SQLite is single-writer, so cluster mode requires care.
      // Use 1 instance for SQLite; scale with 'max' only if using
      // PostgreSQL (DATABASE_URL set).
      //
      // Override at start: pm2 start pm2.config.js -i 2
      instances: 1,
      exec_mode: 'fork',

      // ── Restart policy ─────────────────────────────────────────
      autorestart: true,
      watch: false,                        // don't watch in production
      max_restarts: 15,                    // within restart_delay window
      min_uptime: '10s',                   // must run 10s to count as "started"
      restart_delay: 3000,                 // 3s between crash restarts
      max_memory_restart: '512M',          // restart if RSS exceeds 512 MB
      kill_timeout: 10000,                 // 10s for graceful shutdown (matches app's SHUTDOWN_TIMEOUT_MS)
      listen_timeout: 8000,               // 8s to listen before considered errored
      shutdown_with_message: true,         // send 'shutdown' msg before SIGINT

      // ── Signals ────────────────────────────────────────────────
      // The app already handles SIGINT and SIGTERM gracefully
      // (drains connections, checkpoints WAL, closes DB).
      stop_signal: 'SIGTERM',

      // ── Logging ────────────────────────────────────────────────
      // PM2 captures stdout/stderr. pino already writes JSON logs,
      // so we just need rotation.
      log_date_format: 'YYYY-MM-DD HH:mm:ss.SSS',
      error_file: './logs/oil-web-error.log',
      out_file: './logs/oil-web-out.log',
      merge_logs: true,                    // single log per app (not per instance)
      log_type: 'json',                    // structured log output

      // ── Node.js flags ──────────────────────────────────────────
      node_args: [
        '--max-old-space-size=460',        // keep heap under memory limit
        '--enable-source-maps',            // useful stack traces in production
      ],

      // ── Environment — development (default) ────────────────────
      env: {
        NODE_ENV: 'development',
        PORT: 8080,
      },

      // ── Environment — production ───────────────────────────────
      // Activated with: pm2 start pm2.config.js --env production
      env_production: {
        NODE_ENV: 'production',
        PORT: 8080,
      },

      // ── Environment — staging ──────────────────────────────────
      env_staging: {
        NODE_ENV: 'staging',
        PORT: 8080,
      },

      // ── Exponential backoff restart strategy ───────────────────
      // If the process keeps crashing, wait progressively longer
      // between restarts to avoid CPU-thrashing loops.
      exp_backoff_restart_delay: 100,      // starts at 100ms, doubles up to 15s
    },
  ],

  // ── Deployment (optional) ────────────────────────────────────────
  // Configure if you use `pm2 deploy` for push-based deployments.
  // Uncomment and fill in your server details.
  //
  // deploy: {
  //   production: {
  //     user: 'deploy',
  //     host: ['your-server.example.com'],
  //     ref: 'origin/main',
  //     repo: 'git@github.com:your-org/oil-benchmarks.git',
  //     path: '/var/www/oil-benchmarks',
  //     'pre-deploy-local': '',
  //     'post-deploy': 'npm ci --omit=dev && pm2 reload pm2.config.js --env production',
  //     'pre-setup': 'mkdir -p /var/www/oil-benchmarks/logs',
  //     env: {
  //       NODE_ENV: 'production',
  //     },
  //   },
  // },
};
