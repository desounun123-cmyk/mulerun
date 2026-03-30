/**
 * Service Worker — OIL Benchmarks PWA
 *
 * Strategy:
 *   - Static shell (HTML, icons, manifest)     → Precached on install, stale-while-revalidate
 *   - Google Fonts CSS + font files             → Cache-first (immutable CDN resources)
 *   - Local API calls (/api/*)                  → Network-first with offline fallback
 *   - External data APIs (EIA, Yahoo, proxies)  → Network-first into dedicated data cache
 *   - Auth / admin routes                       → Network-only (session-sensitive)
 *   - All other same-origin assets              → Stale-while-revalidate
 *
 * Cache housekeeping:
 *   - Old cache versions are purged on activate
 *   - Data cache is capped at 80 entries (LRU eviction)
 *   - Font cache is capped at 30 entries
 */

// ── Cache names (bump CACHE_VERSION on each deploy to bust the shell cache) ──
const CACHE_VERSION = 6;
const SHELL_CACHE   = 'oil-shell-v' + CACHE_VERSION;
const DATA_CACHE    = 'oil-data-v' + CACHE_VERSION;
const FONT_CACHE    = 'oil-fonts-v1';  // fonts are immutable, no need to bust
const RUNTIME_CACHE = 'oil-runtime-v' + CACHE_VERSION;

const KNOWN_CACHES = [SHELL_CACHE, DATA_CACHE, FONT_CACHE, RUNTIME_CACHE];

// ── Precache manifest (app shell) ────────────────────────────────
const PRECACHE_URLS = [
  '/',
  '/index.html',
  '/offline.html',
  '/manifest.json',
  '/icons/favicon.svg',
  '/icons/icon-192.svg',
  '/icons/icon-512.svg',
  '/icons/icon-maskable.svg',
];

// Domains whose GET responses we cache for offline chart data
const DATA_DOMAINS = [
  'api.eia.gov',
  'query1.finance.yahoo.com',
  'query2.finance.yahoo.com',
  'corsproxy.io',
  'api.allorigins.win',
  'cors-anywhere.herokuapp.com',
];

// ── Limits ───────────────────────────────────────────────────────
const DATA_CACHE_MAX_ENTRIES = 80;
const FONT_CACHE_MAX_ENTRIES = 30;
const RUNTIME_CACHE_MAX_ENTRIES = 60;

// ── Install: precache shell assets ──────────────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(SHELL_CACHE)
      .then(cache => cache.addAll(PRECACHE_URLS))
      .then(() => self.skipWaiting())
  );
});

// ── Activate: clean up old caches ───────────────────────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(k => !KNOWN_CACHES.includes(k))
          .map(k => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

// ── Fetch: routing strategy ─────────────────────────────────────
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Skip non-GET requests (form submissions, analytics beacons, etc.)
  if (event.request.method !== 'GET') return;

  // Auth / admin routes — strategy depends on path
  // GET /admin (HTML shell) and GET /api/admin/* → network-first with cache fallback
  // POST/DELETE admin actions → already skipped above (non-GET)
  if (url.pathname.startsWith('/admin') ||
      url.pathname.startsWith('/reset-password')) {
    // Never cache password-reset routes
    if (url.pathname.startsWith('/reset-password')) return;
    // Cache the admin HTML shell and read-only API endpoints for offline viewing
    if (url.pathname === '/admin' ||
        url.pathname.startsWith('/api/admin/') ||
        url.pathname === '/admin/anomalies' ||
        url.pathname === '/admin/backups' ||
        url.pathname.startsWith('/admin/db/') ||
        url.pathname.startsWith('/admin/pitr/')) {
      event.respondWith(networkFirst(event.request, RUNTIME_CACHE));
      return;
    }
    // Admin vendor scripts (Chart.js) → stale-while-revalidate (effectively immutable)
    if (url.pathname.startsWith('/admin/vendor/')) {
      event.respondWith(staleWhileRevalidate(event.request));
      return;
    }
    // All other admin GET routes (report.pdf, exports) → network-only
    return;
  }

  // ── Low-bandwidth detection ──────────────────────────────────
  // Check Save-Data header and connection quality hints.
  // On slow connections, prefer cache-first for data APIs to reduce latency.
  const saveData = event.request.headers.get('Save-Data') === 'on';
  const isSlowConnection = saveData || _isSlowConnection();

  // Google Fonts CSS & font files → cache-first (immutable CDN)
  if (url.hostname === 'fonts.googleapis.com' || url.hostname === 'fonts.gstatic.com') {
    event.respondWith(googleFontsCacheFirst(event.request));
    return;
  }

  // External data APIs → on slow connections use cache-first, otherwise network-first
  if (DATA_DOMAINS.some(d => url.hostname === d || url.hostname.endsWith('.' + d))) {
    if (isSlowConnection) {
      event.respondWith(cacheFirstData(event.request));
    } else {
      event.respondWith(networkFirstData(event.request));
    }
    return;
  }

  // Local API routes → network-first with JSON offline fallback
  if (url.pathname.startsWith('/api/')) {
    if (isSlowConnection) {
      // On slow connections, use stale-while-revalidate for API calls
      event.respondWith(staleWhileRevalidateData(event.request));
    } else {
      event.respondWith(networkFirst(event.request, RUNTIME_CACHE));
    }
    return;
  }

  // Avatar thumbnails (_thumb.webp) → cache-first (small, rarely change, perfect as LQIP placeholders)
  if (url.pathname.startsWith('/uploads/') && url.pathname.includes('_thumb.')) {
    event.respondWith(cacheFirst(event.request, RUNTIME_CACHE));
    return;
  }

  // Full-res avatar uploads → stale-while-revalidate (may change on re-upload)
  if (url.pathname.startsWith('/uploads/')) {
    event.respondWith(staleWhileRevalidate(event.request));
    return;
  }

  // All same-origin static assets → stale-while-revalidate
  if (url.origin === self.location.origin) {
    event.respondWith(staleWhileRevalidate(event.request));
    return;
  }

  // Anything else (third-party scripts, CDN libs) → network with cache fallback
  event.respondWith(networkFirst(event.request, RUNTIME_CACHE));
});

// ── Strategies ──────────────────────────────────────────────────

/**
 * Stale-while-revalidate for same-origin static assets.
 * Returns the cached version immediately (fast), then updates the cache
 * in the background so the next load gets the fresh version.
 * Falls back to network if nothing is cached.
 */
async function staleWhileRevalidate(request) {
  const cache = await caches.open(SHELL_CACHE);
  const cached = await cache.match(request);

  // Always kick off a background fetch to refresh the cache
  const fetchPromise = fetch(request).then(response => {
    if (response.ok) {
      cache.put(request, response.clone());
    }
    return response;
  }).catch(() => null);

  // If we have a cached version, return it immediately
  if (cached) return cached;

  // Nothing cached — wait for network
  const networkResponse = await fetchPromise;
  if (networkResponse) return networkResponse;

  // Last resort: serve the offline fallback page for navigation requests,
  // or the app shell for sub-resource requests
  if (request.mode === 'navigate') {
    return caches.match('/offline.html') || new Response('Offline', { status: 503 });
  }
  return caches.match('/') || new Response('Offline', { status: 503 });
}

/**
 * Cache-first for Google Fonts.
 * Font CSS from fonts.googleapis.com contains versioned URLs to font files
 * on fonts.gstatic.com, so both are effectively immutable once cached.
 */
async function googleFontsCacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) return cached;

  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(FONT_CACHE);
      cache.put(request, response.clone());
      trimCache(FONT_CACHE, FONT_CACHE_MAX_ENTRIES);
    }
    return response;
  } catch (_) {
    // Font not available offline — return empty response so page still renders
    return new Response('', { status: 503 });
  }
}

/**
 * Generic cache-first strategy.
 * Returns cached response if available, otherwise fetches and caches.
 * Used for small, rarely-changing assets like avatar thumbnails.
 */
async function cacheFirst(request, cacheName) {
  const cached = await caches.match(request);
  if (cached) return cached;

  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(cacheName);
      cache.put(request, response.clone());
    }
    return response;
  } catch (_) {
    return new Response('', { status: 503, statusText: 'Offline' });
  }
}

/**
 * Network-first with cache fallback.
 * Used for local API calls and third-party scripts.
 */
async function networkFirst(request, cacheName) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(cacheName);
      cache.put(request, response.clone());
      trimCache(cacheName, RUNTIME_CACHE_MAX_ENTRIES);
    }
    return response;
  } catch (_) {
    const cached = await caches.match(request);
    if (cached) return cached;
    // Navigation requests get the offline fallback page
    if (request.mode === 'navigate') {
      const offlinePage = await caches.match('/offline.html');
      if (offlinePage) return offlinePage;
    }
    return new Response(JSON.stringify({ error: 'Offline' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

/**
 * Network-first for external data APIs.
 * Stores successful responses in a dedicated data cache with LRU eviction.
 */
async function networkFirstData(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(DATA_CACHE);
      cache.put(request, response.clone());
      trimCache(DATA_CACHE, DATA_CACHE_MAX_ENTRIES);
    }
    return response;
  } catch (_) {
    const cached = await caches.match(request);
    if (cached) return cached;
    return new Response(JSON.stringify({ error: 'Offline', offline: true }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// ── Cache housekeeping: LRU eviction ────────────────────────────
/**
 * Trims a cache to the given max number of entries.
 * Deletes the oldest entries first (FIFO, which approximates LRU
 * since Cache API stores entries in insertion order).
 */
async function trimCache(cacheName, maxEntries) {
  const cache = await caches.open(cacheName);
  const keys = await cache.keys();
  if (keys.length <= maxEntries) return;
  // Delete oldest entries until we're at the limit
  const excess = keys.length - maxEntries;
  for (let i = 0; i < excess; i++) {
    await cache.delete(keys[i]);
  }
}

// ── Connection quality detection (Service Worker context) ────────
/**
 * Checks the Network Information API (available in some browsers' SW scope)
 * to determine if the connection is slow.
 */
function _isSlowConnection() {
  if (typeof navigator === 'undefined' || !navigator.connection) return false;
  const conn = navigator.connection;
  const ect = conn.effectiveType || '4g';
  if (ect === 'slow-2g' || ect === '2g' || ect === '3g') return true;
  if (conn.saveData) return true;
  if (typeof conn.downlink === 'number' && conn.downlink < 1.5) return true;
  return false;
}

/**
 * Returns a speed tier string matching the client-side NetInfo tiers:
 * 'offline' | 'critical' | 'slow' | 'moderate' | 'fast'
 */
function _getSpeedTier() {
  if (typeof navigator === 'undefined' || !navigator.onLine) return 'offline';
  if (!navigator.connection) return 'fast';
  const conn = navigator.connection;
  if (conn.saveData) return 'critical';
  const ect = conn.effectiveType || '4g';
  if (ect === 'slow-2g' || ect === '2g') return 'critical';
  if (ect === '3g') return 'slow';
  const dl = typeof conn.downlink === 'number' ? conn.downlink : Infinity;
  if (dl < 1) return 'critical';
  if (dl < 2.5) return 'slow';
  if (dl < 10) return 'moderate';
  return 'fast';
}

/**
 * Cache-first for external data APIs on slow connections.
 * Returns cached data immediately if available; fetches in background to refresh.
 * Falls back to network if nothing is cached.
 */
async function cacheFirstData(request) {
  const cached = await caches.match(request);
  if (cached) {
    // Background refresh — don't block the response
    (async () => {
      try {
        const response = await fetch(request);
        if (response.ok) {
          const cache = await caches.open(DATA_CACHE);
          cache.put(request, response.clone());
          trimCache(DATA_CACHE, DATA_CACHE_MAX_ENTRIES);
        }
      } catch (_) { /* offline — cached version is fine */ }
    })();
    return cached;
  }
  // Nothing cached — fall back to network
  return networkFirstData(request);
}

/**
 * Stale-while-revalidate for local API calls on slow connections.
 * Returns cached response immediately, refreshes in background.
 */
async function staleWhileRevalidateData(request) {
  const cache = await caches.open(RUNTIME_CACHE);
  const cached = await cache.match(request);

  const fetchPromise = fetch(request).then(response => {
    if (response.ok) {
      cache.put(request, response.clone());
      trimCache(RUNTIME_CACHE, RUNTIME_CACHE_MAX_ENTRIES);
    }
    return response;
  }).catch(() => null);

  if (cached) return cached;

  const networkResponse = await fetchPromise;
  if (networkResponse) return networkResponse;

  return new Response(JSON.stringify({ error: 'Offline' }), {
    status: 503,
    headers: { 'Content-Type': 'application/json' },
  });
}

// ── Background Sync — replay queued settings mutations ──────────
// The main thread stores queued requests in localStorage under 'oil_sync_queue'.
// Because service workers can't access localStorage directly, we use
// a message channel to ask a client window to provide the queue and flush it.

// ── Web Push — display push notifications ───────────────────────
self.addEventListener('push', event => {
  if (!event.data) return;
  let payload;
  try { payload = event.data.json(); } catch (_) { payload = { title: 'OIL Benchmarks', body: event.data.text() }; }
  const title = payload.title || 'OIL Benchmarks';
  const options = {
    body: payload.body || '',
    icon: payload.icon || '/icons/icon-192.svg',
    badge: '/icons/favicon.svg',
    tag: payload.tag || 'oil-push',
    data: payload.data || {},
    vibrate: [100, 50, 100],
    actions: payload.actions || []
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

// ── Notification click — open the app or focus existing tab ─────
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
      // Focus an existing tab if one is open
      for (const client of clients) {
        if (client.url.includes(self.location.origin) && 'focus' in client) {
          return client.focus();
        }
      }
      // Otherwise open a new tab
      return self.clients.openWindow(url);
    })
  );
});

self.addEventListener('sync', event => {
  if (event.tag === 'sync-settings') {
    event.waitUntil(replayQueue());
  }
  if (event.tag === 'sync-analytics') {
    event.waitUntil(replayAnalyticsQueue());
  }
});

async function replayQueue() {
  // Ask any available client window to send us the queue
  const clients = await self.clients.matchAll({ type: 'window' });
  if (clients.length === 0) return;

  // Use MessageChannel for round-trip communication
  const queue = await new Promise(resolve => {
    const ch = new MessageChannel();
    ch.port1.onmessage = e => resolve(e.data);
    clients[0].postMessage({ type: 'GET_SYNC_QUEUE' }, [ch.port2]);
    // Timeout after 3s in case the page doesn't respond
    setTimeout(() => resolve([]), 3000);
  });

  if (!queue || !queue.length) return;

  const failed = [];
  for (const entry of queue) {
    try {
      const resp = await fetch(entry.url, {
        method: entry.method,
        headers: entry.headers,
        body: entry.body,
        credentials: 'same-origin',
      });
      if (!resp.ok && resp.status >= 500) {
        failed.push(entry);
      }
    } catch (_) {
      failed.push(entry);
    }
  }

  // Tell the client to save back any failed items
  if (clients.length > 0) {
    clients[0].postMessage({ type: 'SET_SYNC_QUEUE', queue: failed });
  }
}

/**
 * Replay queued analytics events via Background Sync.
 * Fetches the queue from the client page, sends each event to the server,
 * and returns any failures back to the client for re-queuing.
 */
async function replayAnalyticsQueue() {
  const clients = await self.clients.matchAll({ type: 'window' });
  if (clients.length === 0) return;

  // Ask the client for the analytics queue
  const queue = await new Promise(resolve => {
    const ch = new MessageChannel();
    ch.port1.onmessage = e => resolve(e.data);
    clients[0].postMessage({ type: 'GET_ANALYTICS_QUEUE' }, [ch.port2]);
    setTimeout(() => resolve([]), 3000);
  });

  if (!queue || !queue.length) return;

  const ENDPOINT = '/api/analytics/';
  const failed = [];

  for (const entry of queue) {
    try {
      const resp = await fetch(ENDPOINT + entry.path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(entry.data),
        credentials: 'same-origin',
      });
      if (!resp.ok && resp.status >= 500) {
        failed.push(entry);
      }
      // 4xx errors (bad data, rate-limited) are intentionally dropped
    } catch (_) {
      failed.push(entry);
    }
  }

  // Return failed items to the client for re-queuing
  if (failed.length > 0 && clients.length > 0) {
    clients[0].postMessage({ type: 'SET_ANALYTICS_QUEUE', queue: failed });
  }
}
