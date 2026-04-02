/**
 * Shared nodemailer transporter.
 *
 * - Production: uses SMTP credentials from env vars (SMTP_HOST, etc.)
 * - Development: falls back to Ethereal test accounts (captured, not delivered)
 *
 * All transports are configured with connection, greeting, and socket
 * timeouts so a hung SMTP server cannot block callers indefinitely.
 *
 * Timeout env vars (all in milliseconds):
 *   SMTP_CONNECTION_TIMEOUT — TCP connect timeout     (default: 10 000)
 *   SMTP_GREETING_TIMEOUT  — wait for server greeting (default: 15 000)
 *   SMTP_SOCKET_TIMEOUT    — idle socket timeout      (default: 30 000)
 *
 * Usage:
 *   const { getTransporter } = require('./mailer');
 *   const transporter = await getTransporter();
 *   await transporter.sendMail({ ... });
 */
const nodemailer = require('nodemailer');
const log = require('./logger').child({ module: 'mailer' });

// ── SMTP timeout configuration ──────────────────────────────────
// connectionTimeout: how long to wait for the TCP connection to establish.
// greetingTimeout:   how long to wait for the server's initial greeting
//                    after the TCP connection is up (some servers are slow
//                    to respond, especially greylisting setups).
// socketTimeout:     how long the socket can remain idle before being
//                    torn down. Covers the entire send lifecycle — if any
//                    SMTP command takes longer than this, the connection
//                    is destroyed and sendMail() rejects with a timeout
//                    error.
const CONNECTION_TIMEOUT = parseInt(process.env.SMTP_CONNECTION_TIMEOUT, 10) || 10_000;
const GREETING_TIMEOUT   = parseInt(process.env.SMTP_GREETING_TIMEOUT, 10)  || 15_000;
const SOCKET_TIMEOUT     = parseInt(process.env.SMTP_SOCKET_TIMEOUT, 10)    || 30_000;

let mailTransporter = null;

async function getTransporter() {
  if (mailTransporter) return mailTransporter;

  // Shared timeout options applied to every transport
  const timeouts = {
    connectionTimeout: CONNECTION_TIMEOUT,
    greetingTimeout:   GREETING_TIMEOUT,
    socketTimeout:     SOCKET_TIMEOUT,
  };

  if (process.env.SMTP_HOST) {
    mailTransporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      },
      ...timeouts,
    });
    log.info({
      host: process.env.SMTP_HOST,
      connectionTimeout: CONNECTION_TIMEOUT,
      greetingTimeout: GREETING_TIMEOUT,
      socketTimeout: SOCKET_TIMEOUT,
    }, 'SMTP transporter created');
  } else {
    // Ethereal test account — emails are captured, not delivered
    const testAccount = await nodemailer.createTestAccount();
    mailTransporter = nodemailer.createTransport({
      host: 'smtp.ethereal.email',
      port: 587,
      secure: false,
      auth: { user: testAccount.user, pass: testAccount.pass },
      ...timeouts,
    });
    log.info('Using Ethereal test transporter (emails not delivered)');
  }

  return mailTransporter;
}

/**
 * Get the "from" address configured via env or use the default.
 */
function getFromAddress() {
  return process.env.SMTP_FROM || '"OIL Benchmarks" <noreply@oil-benchmarks.com>';
}

module.exports = { getTransporter, getFromAddress };
