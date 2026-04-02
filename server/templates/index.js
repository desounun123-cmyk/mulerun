/**
 * server/templates/index.js
 *
 * Lightweight email template renderer.
 *
 * Design goals:
 *   - Zero external dependencies (no Handlebars, EJS, Pug, etc.)
 *   - HTML templates live in this directory as plain .html files
 *   - Variables interpolated via {{variable}} syntax
 *   - All variables HTML-escaped by default; use {{{variable}}} for raw
 *   - Shared base layout via {{> content}} slot
 *   - Templates cached in memory after first read (invalidate on restart)
 *   - Both HTML and plain-text output for every email
 *
 * Usage:
 *   const { render } = require('../templates');
 *   const { html, text } = render('verify-email', {
 *     name: 'Alice',
 *     verifyUrl: 'https://oilbenchmarks.com/verify-email?token=abc',
 *   });
 *   transporter.sendMail({ ..., html, text });
 */
'use strict';

const fs = require('fs');
const path = require('path');

// ── HTML escaping ────────────────────────────────────────────────────

function escHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ── Template cache ───────────────────────────────────────────────────

const TEMPLATE_DIR = __dirname;
const cache = new Map();

function loadTemplate(name) {
  if (cache.has(name)) return cache.get(name);
  const filePath = path.join(TEMPLATE_DIR, name + '.html');
  const content = fs.readFileSync(filePath, 'utf8');
  cache.set(name, content);
  return content;
}

/** Clear the cache (useful in tests or after hot-reload). */
function clearCache() {
  cache.clear();
}

// ── Interpolation engine ─────────────────────────────────────────────

/**
 * Replace {{var}} with escaped value, {{{var}}} with raw value.
 * Supports dot notation: {{user.name}}
 */
function interpolate(template, vars) {
  // Raw (triple braces) first
  let result = template.replace(/\{\{\{(\s*[\w.]+\s*)\}\}\}/g, (_, key) => {
    const val = resolve(vars, key.trim());
    return val == null ? '' : String(val);
  });
  // Escaped (double braces)
  result = result.replace(/\{\{(\s*[\w.]+\s*)\}\}/g, (_, key) => {
    const val = resolve(vars, key.trim());
    return escHtml(val);
  });
  return result;
}

/** Resolve dotted path: "user.name" → vars.user.name */
function resolve(obj, dotPath) {
  return dotPath.split('.').reduce((o, k) => (o != null ? o[k] : undefined), obj);
}

// ── HTML → plain text conversion ─────────────────────────────────────

function htmlToText(html) {
  let text = html;
  // Convert <br> and block elements to newlines
  text = text.replace(/<br\s*\/?>/gi, '\n');
  text = text.replace(/<\/(p|div|h[1-6]|tr|li)>/gi, '\n');
  text = text.replace(/<(hr)\s*\/?>/gi, '\n---\n');
  // Convert links to "text (url)" format
  text = text.replace(/<a[^>]+href="([^"]*)"[^>]*>([^<]*)<\/a>/gi, '$2 ($1)');
  // Strip remaining tags
  text = text.replace(/<[^>]+>/g, '');
  // Decode common entities
  text = text.replace(/&amp;/g, '&');
  text = text.replace(/&lt;/g, '<');
  text = text.replace(/&gt;/g, '>');
  text = text.replace(/&quot;/g, '"');
  text = text.replace(/&#39;/g, "'");
  text = text.replace(/&nbsp;/g, ' ');
  // Clean up whitespace
  text = text.replace(/[ \t]+/g, ' ');
  text = text.replace(/\n{3,}/g, '\n\n');
  return text.trim();
}

// ── Public API ───────────────────────────────────────────────────────

/**
 * Render a named template with variables.
 *
 * @param {string} templateName  — file name without .html (e.g. 'verify-email')
 * @param {object} vars          — template variables
 * @returns {{ html: string, text: string, subject: string }}
 */
function render(templateName, vars) {
  const base = loadTemplate('base');
  const partial = loadTemplate(templateName);

  // Extract <!-- subject: ... --> from the partial
  let subject = '';
  const subjectMatch = partial.match(/<!--\s*subject:\s*(.+?)\s*-->/i);
  if (subjectMatch) {
    subject = interpolate(subjectMatch[1], vars);
  }

  // Merge: inject partial into base layout's {{{content}}} slot
  const merged = interpolate(base, {
    ...vars,
    content: partial,
    subject: subject,
    year: new Date().getFullYear(),
    appName: 'OIL Benchmarks',
    appUrl: vars.appUrl || process.env.APP_URL || 'https://oilbenchmarks.com',
    supportEmail: vars.supportEmail || process.env.SUPPORT_EMAIL || 'support@oilbenchmarks.com',
  });

  // Second pass to interpolate variables inside the injected partial
  const html = interpolate(merged, {
    ...vars,
    year: new Date().getFullYear(),
    appName: 'OIL Benchmarks',
    appUrl: vars.appUrl || process.env.APP_URL || 'https://oilbenchmarks.com',
    supportEmail: vars.supportEmail || process.env.SUPPORT_EMAIL || 'support@oilbenchmarks.com',
  });

  const text = htmlToText(html);

  return { html, text, subject };
}

/**
 * Render without the base layout (for previews or fragments).
 */
function renderPartial(templateName, vars) {
  const partial = loadTemplate(templateName);
  const html = interpolate(partial, vars);
  return { html, text: htmlToText(html) };
}

module.exports = {
  render,
  renderPartial,
  clearCache,
  escHtml,
};
