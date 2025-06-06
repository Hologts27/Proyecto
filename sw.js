const CACHE_NAME = 'catalogo-v2';
const OFFLINE_URL = 'offline.html';
const urlsToCache = [
  '/',
  'index.html',
  'login.html',
  'register.html',
  'dash.html',
  'admin.html',
  'favoritos.html',
  'peliculas.html',
  'peliculass.html',
  'series.html',
  'manage.html',
  'todo.html',
  'style.css',
  'manifest.json',
  // Puedes agregar más recursos estáticos aquí
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll([...urlsToCache, OFFLINE_URL]))
  );
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  event.respondWith(
    fetch(event.request)
      .then(response => {
        // Si es válido, actualiza el caché en segundo plano
        const responseClone = response.clone();
        caches.open(CACHE_NAME).then(cache => {
          cache.put(event.request, responseClone);
        });
        return response;
      })
      .catch(() => {
        // Si falla la red, intenta servir desde caché
        return caches.match(event.request).then(response => {
          if (response) return response;
          // Si es una navegación HTML, muestra página offline
          if (event.request.headers.get('accept').includes('text/html')) {
            return caches.match(OFFLINE_URL);
          }
        });
      })
  );
});

// Página offline básica (si no existe, créala)
