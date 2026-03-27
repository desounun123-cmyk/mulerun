/**
 * Service Worker — OIL Benchmarks PWA
 *
 * Strategy:
 *   - Static shell (HTML, CSS, JS, fonts, icons) → Cache-first
 *   - Local API calls (/api/*) → Network-first with offline fallback
 *   - External data APIs (EIA, Yahoo Finance, CORS proxies) → Network-first with offline fallback
 *   - Auth / admin routes → Network-only (session-sensitive)
 *   - Everything else → Cache-first
 */

const CACHE_NAME = 'oil-v2';
const DATA_CACHE_NAME = 'oil-data-v1'; // separate cache for API/chart data

const PRECACHE_URLS = [
  '/',
  '/manifest.json',
  '/icons/favicon.svg',
  '/icons/icon-192.svg',
  '/icons/icon-512.svg',
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

// ── Install: precache shell assets ──────────────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(PRECACHE_URLS))
      .then(() => self.skipWaiting())
  );
});

// ── Activate: clean up old caches ───────────────────────────────
self.addEventListener('activate', event => {
  const keepCaches = [CACHE_NAME, DATA_CACHE_NAME];
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(k => !keepCaches.includes(k))
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

  // External data APIs → network-first into DATA_CACHE_NAME
  if (DATA_DOMAINS.some(d => url.hostname === d || url.hostname.endsWith('.' + d))) {
    event.respondWith(networkFirstData(event.request));
    return;
  }

  // Local API routes → network-first
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(networkFirst(event.request));
    return;
  }

  // Auth / admin routes → network-only (session-sensitive)
  if (url.pathname.startsWith('/admin') ||
      url.pathname.startsWith('/login') ||
      url.pathname.startsWith('/register')) {
    return;
  }

  // Everything else → cache-first with network fallback
  event.respondWith(cacheFirst(event.request));
});

// ── Strategies ──────────────────────────────────────────────────

async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) return cached;

  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, response.clone());
    }
    return response;
  } catch (_) {
    return caches.match('/') || new Response('Offline', { status: 503 });
  }
}

async function networkFirst(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, response.clone());
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
 * Stores successful responses in a dedicated data cache.
 * On network failure, serves the last cached response.
 */
async function networkFirstData(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(DATA_CACHE_NAME);
      cache.put(request, response.clone());
    }
    return response;
  } catch (_) {
    const cached = await caches.match(request);
    if (cached) return cached;
    // Return an empty-but-valid JSON so the app degrades gracefully
    return new Response(JSON.stringify({ error: 'Offline', offline: true }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// ── Background Sync — replay queued settings mutations ──────
// The main thread stores queued requests in localStorage under 'oil_sync_queue'.
// Because service workers can't access localStorage directly, we use
// a message channel to ask a client window to provide the queue and flush it.

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
