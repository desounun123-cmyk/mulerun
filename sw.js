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
const CACHE_VERSION = 4;
const SHELL_CACHE   = 'oil-shell-v' + CACHE_VERSION;
const DATA_CACHE    = 'oil-data-v' + CACHE_VERSION;
const FONT_CACHE    = 'oil-fonts-v1';  // fonts are immutable, no need to bust
const RUNTIME_CACHE = 'oil-runtime-v' + CACHE_VERSION;

const KNOWN_CACHES = [SHELL_CACHE, DATA_CACHE, FONT_CACHE, RUNTIME_CACHE];

// ── Precache manifest (app shell) ────────────────────────────────
const PRECACHE_URLS = [
  '/',
  '/index.html',
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

  // Auth / admin routes → network-only (session-sensitive, never cache)
  if (url.pathname.startsWith('/admin') ||
      url.pathname.startsWith('/reset-password')) {
    return;
  }

  // Google Fonts CSS & font files → cache-first (immutable CDN)
  if (url.hostname === 'fonts.googleapis.com' || url.hostname === 'fonts.gstatic.com') {
    event.respondWith(googleFontsCacheFirst(event.request));
    return;
  }

  // External data APIs → network-first into DATA_CACHE
  if (DATA_DOMAINS.some(d => url.hostname === d || url.hostname.endsWith('.' + d))) {
    event.respondWith(networkFirstData(event.request));
    return;
  }

  // Local API routes → network-first with JSON offline fallback
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(networkFirst(event.request, RUNTIME_CACHE));
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

  // Last resort: try to serve the app shell
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
    return cached || new Response(JSON.stringify({ error: 'Offline' }), {
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
