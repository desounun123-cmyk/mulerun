/**
 * Server-side price checker for email alert notifications.
 *
 * Periodically fetches live prices from the EIA API, compares them
 * against active (untriggered) alert rules, and sends email
 * notifications to users who have email alerts enabled.
 *
 * Configuration (env vars):
 *   PRICE_CHECK_INTERVAL_MIN  — check interval in minutes (default: 15)
 *   EIA_API_KEY               — EIA API key (default: DEMO_KEY)
 *   PRICE_CHECK_DISABLED      — set to 'true' to disable (default: false)
 */
const db = require('./db');
const log = require('./logger').child({ module: 'price-checker' });
const nodemailer = require('nodemailer');
const { getTransporter, getFromAddress } = require('./mailer');

// ── EIA API configuration ────────────────────────────────────────
const EIA_API_KEY = process.env.EIA_API_KEY || 'DEMO_KEY';
const EIA_BASE = 'https://api.eia.gov/v2/petroleum/pri/spt/data/';

// Product → EIA series ID mapping (matches frontend SOURCES)
const PRODUCT_SERIES = {
  WTI:   'RWTC',
  BRENT: 'RBRTE',
  HO:    'EER_EPD2F_PF4_Y35NY_DPG',
  GAS:   'EMM_EPMR_PTE_NUS_DPG'
};

/**
 * Fetch the latest price for a single product from EIA.
 * Returns the price as a number, or null on failure.
 */
async function fetchPrice(product) {
  const series = PRODUCT_SERIES[product];
  if (!series) return null;

  const url = EIA_BASE + '?api_key=' + EIA_API_KEY
    + '&frequency=daily&data[0]=value'
    + '&facets[series][]=' + series
    + '&sort[0][column]=period&sort[0][direction]=desc&length=1';

  try {
    const res = await fetch(url);
    if (!res.ok) {
      log.warn({ product, status: res.status }, 'EIA fetch failed');
      return null;
    }
    const json = await res.json();
    const data = json.response && json.response.data;
    if (data && data.length > 0) {
      const val = parseFloat(data[0].value);
      return isNaN(val) ? null : val;
    }
    return null;
  } catch (err) {
    log.warn({ err, product }, 'EIA fetch error');
    return null;
  }
}

/**
 * Fetch latest prices for all products.
 * Returns an object like { WTI: 72.5, BRENT: 76.1, ... }
 */
async function fetchAllPrices() {
  const products = Object.keys(PRODUCT_SERIES);
  const prices = {};

  // Fetch in parallel
  const results = await Promise.allSettled(
    products.map(async (p) => ({ product: p, price: await fetchPrice(p) }))
  );

  for (const r of results) {
    if (r.status === 'fulfilled' && r.value.price !== null) {
      prices[r.value.product] = r.value.price;
    }
  }

  return prices;
}

/**
 * Build a nicely formatted alert email (HTML + plain text).
 */
function buildAlertEmail(userName, triggeredAlerts, prices) {
  const rows = triggeredAlerts.map(a => {
    const unit = (a.product === 'HO' || a.product === 'GAS') ? '/gal' : '/bbl';
    const current = prices[a.product];
    return {
      product: a.product,
      direction: a.direction,
      threshold: '$' + a.threshold.toFixed(2) + unit,
      current: '$' + (current != null ? current.toFixed(2) : '?') + unit
    };
  });

  // Plain text
  const textLines = rows.map(r =>
    `  ${r.product}: now ${r.current} (${r.direction} ${r.threshold})`
  );
  const text = `Hi ${userName},\n\nYour price alert${rows.length > 1 ? 's' : ''} triggered:\n\n`
    + textLines.join('\n')
    + '\n\nThese alerts have been marked as triggered. '
    + 'You can re-arm them from your dashboard.\n\n'
    + '— OIL Benchmarks';

  // HTML
  const htmlRows = rows.map(r =>
    `<tr>
      <td style="padding:8px 12px;border-bottom:1px solid #282828;color:#c9a84c;font-weight:700">${r.product}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #282828">${r.direction} ${r.threshold}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #282828;font-weight:700">${r.current}</td>
    </tr>`
  ).join('');

  const html = `
    <div style="background:#0c0c0e;color:#e8e4dc;font-family:'Helvetica Neue',Arial,sans-serif;padding:24px;max-width:500px;margin:0 auto">
      <div style="border:1px solid #333;border-radius:8px;padding:20px;background:#111">
        <h2 style="color:#c9a84c;font-size:16px;margin:0 0 4px">Price Alert Triggered</h2>
        <p style="color:#888;font-size:12px;margin:0 0 16px">Hi ${userName}, your alert${rows.length > 1 ? 's' : ''} fired:</p>
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <tr>
            <th style="text-align:left;padding:6px 12px;border-bottom:2px solid #333;color:#666;font-size:10px;text-transform:uppercase">Product</th>
            <th style="text-align:left;padding:6px 12px;border-bottom:2px solid #333;color:#666;font-size:10px;text-transform:uppercase">Condition</th>
            <th style="text-align:left;padding:6px 12px;border-bottom:2px solid #333;color:#666;font-size:10px;text-transform:uppercase">Current</th>
          </tr>
          ${htmlRows}
        </table>
        <p style="color:#666;font-size:11px;margin:16px 0 0">These alerts have been marked as triggered. Re-arm them from your dashboard.</p>
      </div>
      <p style="color:#555;font-size:10px;margin-top:12px;text-align:center">OIL Benchmarks &mdash; Price Alert Notification</p>
    </div>`;

  return { text, html };
}

/**
 * Send an alert email to a user.
 */
async function sendAlertEmail(email, userName, triggeredAlerts, prices) {
  try {
    const transporter = await getTransporter();
    const { text, html } = buildAlertEmail(userName, triggeredAlerts, prices);

    const info = await transporter.sendMail({
      from: getFromAddress(),
      to: email,
      subject: `Price Alert: ${triggeredAlerts.map(a => a.product).join(', ')} — OIL Benchmarks`,
      text,
      html
    });

    // Log Ethereal preview URL in dev
    if (!process.env.SMTP_HOST) {
      const previewUrl = nodemailer.getTestMessageUrl(info);
      if (previewUrl) log.info({ previewUrl, email }, 'Alert email preview (Ethereal)');
    }

    log.info({ email, alertCount: triggeredAlerts.length }, 'Alert email sent');
    return true;
  } catch (err) {
    log.error({ err, email }, 'Failed to send alert email');
    return false;
  }
}

/**
 * Main check cycle: fetch prices → compare alerts → send emails.
 */
async function runCheck() {
  try {
    const prices = await fetchAllPrices();
    const fetchedProducts = Object.keys(prices);

    if (fetchedProducts.length === 0) {
      log.warn('No prices fetched from EIA — skipping alert check');
      return { checked: 0, triggered: 0, emailed: 0 };
    }

    log.debug({ prices }, 'Fetched EIA prices');

    // Find all active, untriggered alerts for fetched products
    const placeholders = fetchedProducts.map(() => '?').join(',');
    const alerts = db.prepare(
      `SELECT par.id, par.user_id, par.product, par.direction, par.threshold,
              u.email, u.name,
              us.price_alerts, us.notify_email
       FROM price_alert_rules par
       JOIN users u ON u.id = par.user_id
       LEFT JOIN user_settings us ON us.user_id = par.user_id
       WHERE par.active = 1 AND par.triggered = 0
         AND par.product IN (${placeholders})`
    ).all(...fetchedProducts);

    if (alerts.length === 0) {
      log.debug('No active alerts to check');
      return { checked: 0, triggered: 0, emailed: 0 };
    }

    const now = new Date().toISOString();
    // Group triggered alerts by user for batched emails
    const triggeredByUser = {};
    let totalTriggered = 0;

    for (const a of alerts) {
      const currentPrice = prices[a.product];
      if (currentPrice == null) continue;

      const hit = (a.direction === 'above' && currentPrice >= a.threshold) ||
                  (a.direction === 'below' && currentPrice <= a.threshold);

      if (hit) {
        // Mark as triggered in DB
        db.prepare(
          'UPDATE price_alert_rules SET triggered = 1, last_triggered_at = ? WHERE id = ?'
        ).run(now, a.id);

        totalTriggered++;

        // Only queue email if user has price_alerts AND notify_email enabled
        if (a.price_alerts && a.notify_email) {
          if (!triggeredByUser[a.user_id]) {
            triggeredByUser[a.user_id] = {
              email: a.email,
              name: a.name,
              alerts: []
            };
          }
          triggeredByUser[a.user_id].alerts.push(a);
        }
      }
    }

    // Send batched emails per user
    let emailsSent = 0;
    const userIds = Object.keys(triggeredByUser);
    for (const uid of userIds) {
      const u = triggeredByUser[uid];
      const ok = await sendAlertEmail(u.email, u.name, u.alerts, prices);
      if (ok) emailsSent++;
    }

    if (totalTriggered > 0) {
      log.info({ checked: alerts.length, triggered: totalTriggered, emailed: emailsSent },
        'Price alert check complete');
    }

    return { checked: alerts.length, triggered: totalTriggered, emailed: emailsSent };
  } catch (err) {
    log.error({ err }, 'Price check cycle failed');
    return { checked: 0, triggered: 0, emailed: 0 };
  }
}

/**
 * Start the periodic price checker.
 * @param {number} intervalMin — check interval in minutes
 */
function start(intervalMin) {
  const ms = intervalMin * 60 * 1000;

  // Run first check after a short delay (let server fully start)
  setTimeout(() => {
    runCheck();
    // Then run on the interval
    setInterval(runCheck, ms);
  }, 10000);

  log.info({ intervalMin }, 'Price checker started');
}

module.exports = { start, runCheck, fetchAllPrices };
