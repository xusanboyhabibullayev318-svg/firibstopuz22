const CACHE = 'firibstop-uz-secure-v39';
const ASSETS = [
  './',
  './index.html',
  './manifest.webmanifest',
  './icon.svg',
  './icon-192.png',
  './icon-512.png',
  './scams.json',
  './styles.css',
  './app.js',
  './antivirus.js',
  './runtime.js',
  './radar-dashboard.js',
  './data/world-land.geojson',
  './data/threats.json',
  './data/uzbekistan-regions-schematic.geojson'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE)
      .then((c) => c.addAll(ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;

  const u = new URL(event.request.url);

  if (u.pathname.includes('/api/')) return;

  const appShell =
    event.request.mode === 'navigate' ||
    u.pathname.endsWith('/index.html') ||
    u.pathname === '/' ||
    u.pathname.endsWith('/sw.js');

  if (appShell) {
    event.respondWith(
      fetch(event.request, { cache: 'no-store' })
        .then((response) => {
          if (
            response &&
            response.ok &&
            u.origin === location.origin &&
            !u.pathname.endsWith('/sw.js')
          ) {
            const copy = response.clone();
            caches.open(CACHE).then((c) => c.put(event.request, copy));
          }
          return response;
        })
        .catch(() =>
          caches.match(event.request).then((cached) => cached || caches.match('./index.html'))
        )
    );
    return;
  }

  event.respondWith(
    caches.match(event.request).then((cached) =>
      cached ||
      fetch(event.request)
        .then((response) => {
          if (response && response.ok && u.origin === location.origin) {
            const copy = response.clone();
            caches.open(CACHE).then((c) => c.put(event.request, copy));
          }
          return response;
        })
        .catch(() => caches.match('./index.html'))
    )
  );
});
