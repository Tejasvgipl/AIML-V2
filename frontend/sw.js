// CyberSentinel Service Worker — KILL SWITCH.
//
// The previous SW cached /api/overview, /api/logs, /api/incidents and
// /api/resilience with a stale-while-revalidate strategy. Its respondWith
// handler intermittently rejected ("Failed to fetch"), which silently broke
// exactly those endpoints — most visibly Logs Explorer, which has no fallback
// and hung forever on "Loading logs…". It was also the cause of the recurring
// "hard refresh won't reload / stale dashboard" reports.
//
// The dashboard is already fast via server-side caching, so this SW now does
// the opposite of caching: it unregisters itself and purges every cache, so
// any browser that still has the old worker installed is healed on next load.

self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.map(k => caches.delete(k)));
    await self.registration.unregister();
    const clientList = await self.clients.matchAll({ type: 'window' });
    clientList.forEach(c => c.navigate(c.url));
  })());
});

// Never intercept any request — always go straight to the network.
