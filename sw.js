const CACHE_NAME = 'admin-panel-v1';
const URLS_TO_CACHE = [
  '/',
  '/admin.html',
  '/style.css',
  '/api.js',
  '/manifest.json',
  // Agrega aquí otros recursos estáticos si es necesario
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(URLS_TO_CACHE))
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
    ))
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request).then(response => {
      return response || fetch(event.request);
    })
  );
});
