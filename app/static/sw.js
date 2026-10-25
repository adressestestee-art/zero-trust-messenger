const CACHE_NAME = 'zt-messenger-v1';
const ASSETS_TO_CACHE = [
  '/',
  '/styles.css',
  '/crypto.js?v=2.7',
  '/app.js?v=2.7',
  '/vendor/qrcode.min.js',
  '/vendor/jsQR.js',
  '/manifest.json'
];

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS_TO_CACHE))
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(
      keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
    )).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  // Ne jamais mettre en cache les requêtes de transit de paquets API E2EE
  if (event.request.url.includes('/api/')) {
    event.respondWith(fetch(event.request));
    return;
  }
  event.respondWith(
    caches.match(event.request).then((cached) => cached || fetch(event.request))
  );
});
