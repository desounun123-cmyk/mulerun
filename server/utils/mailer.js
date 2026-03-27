/**
 * Shared nodemailer transporter.
 *
 * - Production: uses SMTP credentials from env vars (SMTP_HOST, etc.)
 * - Development: falls back to Ethereal test accounts (captured, not delivered)
 *
 * Usage:
 *   const { getTransporter } = require('./mailer');
 *   const transporter = await getTransporter();
 *   await transporter.sendMail({ ... });
 */
const nodemailer = require('nodemailer');
const log = require('./logger').child({ module: 'mailer' });

let mailTransporter = null;

async function getTransporter() {
  if (mailTransporter) return mailTransporter;

  if (process.env.SMTP_HOST) {
    mailTransporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
    log.info({ host: process.env.SMTP_HOST }, 'SMTP transporter created');
  } else {
    // Ethereal test account — emails are captured, not delivered
    const testAccount = await nodemailer.createTestAccount();
    mailTransporter = nodemailer.createTransport({
      host: 'smtp.ethereal.email',
      port: 587,
      secure: false,
      auth: { user: testAccount.user, pass: testAccount.pass }
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
