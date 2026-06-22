// CyberSentinel Service Worker — stale-while-revalidate for API endpoints
// Shows cached data INSTANTLY on page open, refreshes in background.
// Cache lasts 2 minutes — stale data is always better than a blank screen.

const CACHE = 'cs-api-v1';
const MAX_AGE_MS = 120_000; // 2 minutes

// API paths to cache (fast-changing data with short TTL)
const CACHE_PATHS = [
  '/api/overview',
  '/api/resilience',
];

self.addEventListener('install', e => { self.skipWaiting(); });
self.addEventListener('activate', e => { e.waitUntil(clients.claim()); });

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // Only cache GET requests to our API paths
  if (e.request.method !== 'GET') return;
  const shouldCache = CACHE_PATHS.some(p => url.pathname.startsWith(p));
  if (!shouldCache) return;

  e.respondWith(
    caches.open(CACHE).then(async cache => {
      const cached = await cache.match(e.request);
      const now = Date.now();

      // Return cached immediately if fresh enough, fetch in background
      if (cached) {
        const age = now - Number(cached.headers.get('sw-cached-at') || 0);
        if (age < MAX_AGE_MS) {
          // Serve from cache instantly, revalidate silently in background
          fetch(e.request).then(fresh => {
            if (fresh && fresh.ok) _store(cache, e.request, fresh.clone());
          }).catch(() => {});
          return cached;
        }
      }

      // Cache miss or expired — fetch live, store, return
      try {
        const fresh = await fetch(e.request);
        if (fresh && fresh.ok) await _store(cache, e.request, fresh.clone());
        return fresh;
      } catch {
        // Network down — serve stale cache rather than error
        return cached || new Response(JSON.stringify({ error: 'offline' }), {
          headers: { 'Content-Type': 'application/json' }, status: 503
        });
      }
    })
  );
});

async function _store(cache, req, res) {
  const headers = new Headers(res.headers);
  headers.set('sw-cached-at', String(Date.now()));
  const body = await res.arrayBuffer();
  await cache.put(req, new Response(body, { status: res.status, headers }));
}
