/**
 * Standardised API response helpers.
 *
 * Every JSON endpoint should use one of these instead of calling
 * `res.json()` / `res.status().json()` directly, so clients always
 * receive a predictable envelope:
 *
 *   Success  → { ok: true,  data, message? }
 *   Paginated→ { ok: true,  data[], pagination: { page, limit, total, totalPages } }
 *   Error    → { ok: false, error }
 *   Silent   → 204 No Content (no body)
 */

/** Success with optional data + message.  Status defaults to 200. */
function ok(res, data, message, status) {
  const body = { ok: true };
  if (data !== undefined && data !== null) body.data = data;
  if (message) body.message = message;
  return res.status(status || 200).json(body);
}

/**
 * Conditional success response with ETag / Last-Modified support.
 *
 * If the client sends `If-None-Match` matching our ETag, or
 * `If-Modified-Since` at or after our Last-Modified timestamp,
 * responds with 304 Not Modified (no body) to save bandwidth.
 *
 * @param {object}  req            Express request
 * @param {object}  res            Express response
 * @param {*}       data           Response payload (same as ok())
 * @param {object}  opts
 * @param {string}  [opts.etag]    ETag value (without quotes — we wrap it)
 * @param {Date|number} [opts.lastModified]  Date object or epoch ms
 * @param {string}  [opts.message] Optional message
 * @param {number}  [opts.maxAge]  Cache-Control max-age in seconds (default: 0)
 */
function conditionalOk(req, res, data, opts) {
  opts = opts || {};

  // ── Set ETag ──────────────────────────────────────────────────
  const etagVal = opts.etag ? '"' + opts.etag + '"' : null;
  if (etagVal) {
    res.setHeader('ETag', etagVal);
  }

  // ── Set Last-Modified ─────────────────────────────────────────
  let lastMod = null;
  if (opts.lastModified) {
    lastMod = opts.lastModified instanceof Date
      ? opts.lastModified
      : new Date(opts.lastModified);
    res.setHeader('Last-Modified', lastMod.toUTCString());
  }

  // ── Cache-Control ─────────────────────────────────────────────
  const maxAge = opts.maxAge || 0;
  res.setHeader('Cache-Control', 'private, max-age=' + maxAge + ', must-revalidate');

  // ── Check If-None-Match (ETag) ────────────────────────────────
  if (etagVal) {
    const clientEtag = req.headers['if-none-match'];
    if (clientEtag && (clientEtag === etagVal || clientEtag === 'W/' + etagVal)) {
      return res.status(304).end();
    }
  }

  // ── Check If-Modified-Since ───────────────────────────────────
  if (lastMod && !etagVal) {
    // Only check If-Modified-Since when there's no ETag (RFC 7232 §3.3:
    // If-None-Match takes precedence over If-Modified-Since)
    const ims = req.headers['if-modified-since'];
    if (ims) {
      const imsDate = new Date(ims);
      if (!isNaN(imsDate.getTime()) && lastMod.getTime() <= imsDate.getTime()) {
        return res.status(304).end();
      }
    }
  }

  // ── Send full response ────────────────────────────────────────
  return ok(res, data, opts.message);
}

/** 201 Created — convenience wrapper. */
function created(res, data, message) {
  return ok(res, data, message || 'Created.', 201);
}

/** Paginated list response. */
function paginated(res, items, opts) {
  return res.json({
    ok: true,
    data: items,
    pagination: {
      page:       opts.page,
      limit:      opts.limit,
      total:      opts.total,
      totalPages: opts.totalPages,
    },
  });
}

/** Error response.  `status` should be 4xx or 5xx. */
function fail(res, status, error) {
  return res.status(status).json({ ok: false, error: error });
}

/** 204 No Content — silent acknowledgement (analytics beacons, CSP reports). */
function noContent(res) {
  return res.status(204).end();
}

module.exports = { ok, conditionalOk, created, paginated, fail, noContent };
