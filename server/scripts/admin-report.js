/**
 * Admin dashboard PDF report generator.
 *
 * Produces a branded, multi-section PDF report with summary stats,
 * user tables, settings overview, session data, and analytics
 * using PDFKit (no browser/Puppeteer required).
 *
 * Usage:
 *   const { generateReport } = require('./admin-report');
 *   const stream = generateReport();
 *   stream.pipe(res);
 */
const PDFDocument = require('pdfkit');
const adminRoutes = require('../routes/admin');
const log = require('../utils/logger').child({ module: 'admin-report' });

// ── Brand colours ────────────────────────────────────────────────
const C = {
  bg:        '#0c0c0e',
  gold:      '#c9a84c',
  goldDark:  '#85783c',
  text:      '#e8e4dc',
  muted:     '#888888',
  dim:       '#555555',
  border:    '#333333',
  green:     '#5ddc78',
  red:       '#e05040',
  blue:      '#6495ed',
  rowOdd:    '#141418',
  rowEven:   '#111111',
};

// ── Layout constants ─────────────────────────────────────────────
const PAGE = { width: 595.28, height: 841.89 }; // A4
const M = { top: 50, bottom: 50, left: 50, right: 50 };
const CONTENT_W = PAGE.width - M.left - M.right;

// ── Helpers ──────────────────────────────────────────────────────

function truncate(str, max) {
  if (!str) return '';
  return str.length > max ? str.slice(0, max - 1) + '...' : str;
}

function fmtDate(iso) {
  if (!iso) return '-';
  return iso.replace('T', ' ').slice(0, 19);
}

/**
 * Draw a horizontal rule.
 */
function hr(doc, y, color) {
  doc.strokeColor(color || C.border).lineWidth(0.5)
     .moveTo(M.left, y).lineTo(PAGE.width - M.right, y).stroke();
  return y + 8;
}

/**
 * Draw a section heading with gold underline.
 */
function sectionHeading(doc, title, y) {
  if (y > PAGE.height - 100) {
    doc.addPage();
    y = M.top;
  }
  doc.font('Helvetica-Bold').fontSize(13).fillColor(C.gold);
  doc.text(title, M.left, y, { width: CONTENT_W });
  y += 18;
  y = hr(doc, y, C.gold);
  return y;
}

/**
 * Ensure enough vertical space or add a page.
 */
function ensureSpace(doc, y, needed) {
  if (y + needed > PAGE.height - M.bottom) {
    doc.addPage();
    return M.top;
  }
  return y;
}

/**
 * Draw a simple data table.
 * @param {PDFDocument} doc
 * @param {number} startY
 * @param {string[]} headers
 * @param {string[][]} rows - array of arrays
 * @param {number[]} colWidths - pixel widths per column
 * @returns {number} new Y position
 */
function drawTable(doc, startY, headers, rows, colWidths) {
  const ROW_H = 16;
  const HEADER_H = 18;
  let y = startY;

  // Header
  y = ensureSpace(doc, y, HEADER_H + ROW_H);
  doc.font('Helvetica-Bold').fontSize(7).fillColor(C.muted);
  let x = M.left;
  for (let i = 0; i < headers.length; i++) {
    doc.text(headers[i].toUpperCase(), x + 4, y + 4, { width: colWidths[i] - 8, lineBreak: false });
    x += colWidths[i];
  }
  y += HEADER_H;
  y = hr(doc, y, C.border);

  // Rows
  for (let r = 0; r < rows.length; r++) {
    y = ensureSpace(doc, y, ROW_H + 2);
    const bgColor = r % 2 === 0 ? C.rowOdd : C.rowEven;
    doc.rect(M.left, y - 1, CONTENT_W, ROW_H).fill(bgColor);

    doc.font('Helvetica').fontSize(7).fillColor(C.text);
    x = M.left;
    for (let c = 0; c < rows[r].length; c++) {
      const val = String(rows[r][c] != null ? rows[r][c] : '-');
      doc.fillColor(c === 0 ? C.gold : C.text);
      doc.text(val, x + 4, y + 4, { width: colWidths[c] - 8, lineBreak: false });
      x += colWidths[c];
    }
    y += ROW_H;
  }

  return y + 6;
}

/**
 * Draw a stat card (inline).
 */
function statCard(doc, x, y, label, value, w) {
  const h = 44;
  doc.roundedRect(x, y, w, h, 4).lineWidth(0.5).strokeColor(C.border).fillAndStroke(C.rowOdd, C.border);
  doc.font('Helvetica-Bold').fontSize(18).fillColor(C.gold);
  doc.text(String(value), x, y + 6, { width: w, align: 'center' });
  doc.font('Helvetica').fontSize(7).fillColor(C.muted);
  doc.text(label.toUpperCase(), x, y + 28, { width: w, align: 'center' });
  return h;
}

// ── Main generator ───────────────────────────────────────────────

function generateReport() {
  // Gather all data synchronously (better-sqlite3 is sync)
  const summary = adminRoutes.getSummaryStats();
  const charts  = adminRoutes.getUserChartData();
  const analytics = adminRoutes.getSiteAnalytics();
  const users   = adminRoutes.getUsersTable();
  const settings = adminRoutes.getSettingsTable();
  const sessions = adminRoutes.getSessionsTable();

  const doc = new PDFDocument({
    size: 'A4',
    margins: { top: M.top, bottom: M.bottom, left: M.left, right: M.right },
    info: {
      Title: 'OIL Benchmarks — Admin Report',
      Author: 'OIL Benchmarks System',
      Subject: 'Admin Dashboard Export',
      CreationDate: new Date(),
    },
    bufferPages: true,
  });

  let y = M.top;

  // ── Cover / Title ────────────────────────────────────────────
  doc.rect(0, 0, PAGE.width, PAGE.height).fill(C.bg);
  doc.rect(0, 0, PAGE.width, 4).fill(C.gold);

  y = 60;
  doc.font('Helvetica-Bold').fontSize(22).fillColor(C.gold);
  doc.text('OIL Benchmarks', M.left, y, { width: CONTENT_W });
  y += 30;
  doc.font('Helvetica').fontSize(11).fillColor(C.muted);
  doc.text('Admin Dashboard Report', M.left, y);
  y += 18;
  doc.fontSize(8).fillColor(C.dim);
  doc.text('Generated: ' + new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC', M.left, y);
  y += 30;
  y = hr(doc, y, C.gold);
  y += 4;

  // ── Summary Stats Cards ──────────────────────────────────────
  const cardW = (CONTENT_W - 30) / 4;
  statCard(doc, M.left, y, 'Users', summary.userCount, cardW);
  statCard(doc, M.left + cardW + 10, y, 'Sessions', summary.sessionCount, cardW);
  statCard(doc, M.left + (cardW + 10) * 2, y, 'Tables', summary.tableCount, cardW);
  statCard(doc, M.left + (cardW + 10) * 3, y, 'DB Size', summary.dbSizeKB + ' KB', cardW);
  y += 56;

  // ── Feature Usage ────────────────────────────────────────────
  y = sectionHeading(doc, 'Feature Usage', y);
  const fu = charts.featureUsage;
  const features = [
    ['Price Alerts', fu.priceAlerts, fu.total],
    ['Newsletter', fu.newsletter, fu.total],
    ['Dark Mode', fu.darkMode, fu.total],
    ['Email Alerts', 0, fu.total], // placeholder — notify_email not yet in admin query
  ];
  for (const [name, count, total] of features) {
    y = ensureSpace(doc, y, 18);
    const pct = total > 0 ? ((count / total) * 100).toFixed(0) : 0;
    const barMax = CONTENT_W - 140;
    const barW = total > 0 ? (count / total) * barMax : 0;

    doc.font('Helvetica').fontSize(8).fillColor(C.text);
    doc.text(name, M.left, y + 2, { width: 90, lineBreak: false });

    // Bar background
    doc.rect(M.left + 95, y + 1, barMax, 10).fill(C.rowOdd);
    // Bar fill
    if (barW > 0) {
      doc.rect(M.left + 95, y + 1, barW, 10).fill(C.gold);
    }

    doc.fillColor(C.muted).fontSize(7);
    doc.text(count + '/' + total + ' (' + pct + '%)', M.left + 100 + barMax, y + 2, { width: 60, lineBreak: false });
    y += 16;
  }
  y += 6;

  // ── Plan Distribution ────────────────────────────────────────
  y = sectionHeading(doc, 'Plan Distribution', y);
  for (const p of charts.planDist) {
    y = ensureSpace(doc, y, 16);
    doc.font('Helvetica-Bold').fontSize(8).fillColor(C.gold);
    doc.text(p.plan, M.left, y, { width: 80, lineBreak: false });
    doc.font('Helvetica').fillColor(C.text);
    doc.text(String(p.count) + ' user' + (p.count !== 1 ? 's' : ''), M.left + 85, y, { width: 80, lineBreak: false });
    y += 14;
  }
  y += 6;

  // ── Registration Trends ──────────────────────────────────────
  if (charts.regTrends.length > 0) {
    y = sectionHeading(doc, 'Registration Trends (Daily)', y);
    const tHeaders = ['Date', 'New Users', 'Cumulative'];
    const tRows = charts.regTrends.map((r, i) => [
      r.day,
      String(r.count),
      String(charts.cumulativeData[i] ? charts.cumulativeData[i].total : ''),
    ]);
    y = drawTable(doc, y, tHeaders, tRows, [180, 110, 110]);
    y += 4;
  }

  // ── Site Analytics Summary ───────────────────────────────────
  y = sectionHeading(doc, 'Site Analytics (Last 30 Days)', y);
  y = ensureSpace(doc, y, 60);

  const halfW = (CONTENT_W - 10) / 2;
  statCard(doc, M.left, y, 'Total Views', analytics.totalViews, halfW);
  statCard(doc, M.left + halfW + 10, y, 'Unique Visitors', analytics.uniqueVisitors, halfW);
  y += 56;

  // Browsers
  if (analytics.browsers.length > 0) {
    y = ensureSpace(doc, y, 30);
    doc.font('Helvetica-Bold').fontSize(9).fillColor(C.text);
    doc.text('Browsers', M.left, y); y += 14;
    const bHeaders = ['Browser', 'Views'];
    const bRows = analytics.browsers.map(b => [b.name || 'Unknown', String(b.count)]);
    y = drawTable(doc, y, bHeaders, bRows, [CONTENT_W - 100, 100]);
  }

  // Devices
  if (analytics.devices.length > 0) {
    y = ensureSpace(doc, y, 30);
    doc.font('Helvetica-Bold').fontSize(9).fillColor(C.text);
    doc.text('Devices', M.left, y); y += 14;
    const dHeaders = ['Device', 'Views'];
    const dRows = analytics.devices.map(d => [d.name || 'Unknown', String(d.count)]);
    y = drawTable(doc, y, dHeaders, dRows, [CONTENT_W - 100, 100]);
  }

  // Top Referrers
  if (analytics.referrers.length > 0) {
    y = ensureSpace(doc, y, 30);
    doc.font('Helvetica-Bold').fontSize(9).fillColor(C.text);
    doc.text('Top Referrers', M.left, y); y += 14;
    const rHeaders = ['Source', 'Visits'];
    const rRows = analytics.referrers.map(r => [truncate(r.referrer, 60), String(r.count)]);
    y = drawTable(doc, y, rHeaders, rRows, [CONTENT_W - 80, 80]);
  }

  // Events
  if (analytics.events.length > 0) {
    y = ensureSpace(doc, y, 30);
    doc.font('Helvetica-Bold').fontSize(9).fillColor(C.text);
    doc.text('Feature Events', M.left, y); y += 14;
    const eHeaders = ['Event', 'Count'];
    const eRows = analytics.events.map(e => [e.event, String(e.count)]);
    y = drawTable(doc, y, eHeaders, eRows, [CONTENT_W - 80, 80]);
  }

  // ── Users Table ──────────────────────────────────────────────
  y = sectionHeading(doc, 'Users (' + users.length + ')', y);
  const uHeaders = ['ID', 'Name', 'Email', 'Plan', 'Logins', 'Last Login', 'Created'];
  const uColW = [30, 80, 130, 50, 40, 85, 80];
  const uRows = users.map(u => [
    String(u.id),
    truncate(u.name, 15),
    truncate(u.email, 25),
    u.plan,
    String(u.login_count || 0),
    fmtDate(u.last_login),
    fmtDate(u.created_at),
  ]);
  y = drawTable(doc, y, uHeaders, uRows, uColW);

  // ── User Settings Table ──────────────────────────────────────
  y = sectionHeading(doc, 'User Settings', y);
  const sHeaders = ['ID', 'Name', 'Email', 'Alerts', 'Newsletter', 'Dark Mode'];
  const sColW = [30, 80, 140, 65, 70, 65];
  const sRows = settings.map(s => [
    String(s.id),
    truncate(s.name, 15),
    truncate(s.email, 28),
    s.price_alerts ? 'ON' : 'OFF',
    s.weekly_newsletter ? 'ON' : 'OFF',
    s.dark_mode ? 'ON' : 'OFF',
  ]);
  y = drawTable(doc, y, sHeaders, sRows, sColW);

  // ── Sessions Table ───────────────────────────────────────────
  y = sectionHeading(doc, 'Active Sessions (' + sessions.length + ')', y);
  const sessHeaders = ['User', 'IP Hash', 'Last Seen', 'Expires', 'Status'];
  const sessColW = [110, 80, 110, 110, 50];
  const now = new Date();
  const sessRows = sessions.map(s => {
    const exp = s.expire ? new Date(s.expire) : null;
    const status = (exp && exp < now) ? 'expired' : 'active';
    return [
      s.userName || 'anonymous',
      s.ipHash || '-',
      s.lastSeen ? fmtDate(s.lastSeen) : '-',
      s.expire || '-',
      status,
    ];
  });
  y = drawTable(doc, y, sessHeaders, sessRows, sessColW);

  // ── Database Tables ──────────────────────────────────────────
  y = sectionHeading(doc, 'Database Tables', y);
  for (const t of summary.tables) {
    y = ensureSpace(doc, y, 14);
    doc.font('Helvetica').fontSize(8).fillColor(C.text);
    doc.text('  ' + t, M.left, y);
    y += 12;
  }
  y += 10;

  // ── Login Activity (Top 10) ──────────────────────────────────
  if (charts.loginActivity.length > 0) {
    y = sectionHeading(doc, 'Top Users by Logins', y);
    const laHeaders = ['User', 'Login Count'];
    const laRows = charts.loginActivity.map(u => [u.name, String(u.login_count)]);
    y = drawTable(doc, y, laHeaders, laRows, [CONTENT_W - 100, 100]);
  }

  // ── Page Views Per Day ───────────────────────────────────────
  if (analytics.viewsPerDay.length > 0) {
    y = sectionHeading(doc, 'Daily Page Views (Last 30 Days)', y);
    const pvHeaders = ['Date', 'Views', 'Visitors'];
    const pvRows = analytics.viewsPerDay.map(r => [r.day, String(r.views), String(r.visitors)]);
    y = drawTable(doc, y, pvHeaders, pvRows, [180, 110, 110]);
  }

  // ── Footer on every page ─────────────────────────────────────
  const pages = doc.bufferedPageRange();
  for (let i = 0; i < pages.count; i++) {
    doc.switchToPage(i);
    // Footer line
    doc.strokeColor(C.border).lineWidth(0.5)
       .moveTo(M.left, PAGE.height - 30)
       .lineTo(PAGE.width - M.right, PAGE.height - 30).stroke();
    // Footer text
    doc.font('Helvetica').fontSize(7).fillColor(C.dim);
    doc.text('OIL Benchmarks Admin Report', M.left, PAGE.height - 24, { width: CONTENT_W / 2, lineBreak: false });
    doc.text('Page ' + (i + 1) + ' of ' + pages.count,
      M.left + CONTENT_W / 2, PAGE.height - 24,
      { width: CONTENT_W / 2, align: 'right', lineBreak: false });
  }

  doc.end();
  return doc;
}

module.exports = { generateReport };
