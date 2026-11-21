/* =====================================================================
   Smart Security Monitor - Service Worker PWA (RFC compliant)
   Version: 1.0.0
   Règle de sécurité : Aucun cache pour les flux vidéo, API ou preuves sensibles.
   ===================================================================== */

const CACHE_NAME = 'ssm-pwa-v1.0.0';

const PRECACHE_ASSETS = [
  '/',
  '/static/css/style.css',
  '/static/js/dashboard.js',
  '/static/icons/icon.svg',
  '/offline'
];

// Liste noire stricte : ces routes NE DOIVENT JAMAIS ÊTRE MISES EN CACHE
const NEVER_CACHE_PATTERNS = [
  /\/api\//,
  /\/video/,
  /\/stream/,
  /\/recordings\//,
  /\/screenshots\//,
  /\/reports\//,
  /\/login/,
  /\/logout/,
  /\/auth\//
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(PRECACHE_ASSETS).catch((err) => {
        console.warn('[SW] Pré-cache partiel :', err);
      });
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            console.log('[SW] Suppression ancien cache :', key);
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // 1. Si la requête correspond à une route sensible ou dynamique, bypass complet du cache
  const isNeverCache = NEVER_CACHE_PATTERNS.some((pattern) => pattern.test(url.pathname));
  if (isNeverCache || event.request.method !== 'GET') {
    return; // Passer directement au réseau sans interférence du Service Worker
  }

  // 2. Requête de navigation (pages HTML) : Network First avec fallback Offline
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).catch(() => {
        return caches.match('/offline').then((res) => {
          return res || caches.match('/');
        });
      })
    );
    return;
  }

  // 3. Ressources statiques (CSS, JS, SVG) : Stale-While-Revalidate
  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      const fetchPromise = fetch(event.request).then((networkResponse) => {
        if (networkResponse && networkResponse.status === 200 && networkResponse.type === 'basic') {
          const responseToCache = networkResponse.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseToCache);
          });
        }
        return networkResponse;
      }).catch(() => cachedResponse);

      return cachedResponse || fetchPromise;
    })
  );
});

// Écoute des notifications Push distantes (Web Push VAPID)
self.addEventListener('push', (event) => {
  let data = {
    title: '🛡️ ALERTE SMART SECURITY MONITOR',
    body: 'Incident de sécurité détecté sur le système.',
    icon: '/static/icons/icon.svg',
    badge: '/static/icons/icon.svg'
  };

  if (event.data) {
    try {
      data = Object.assign(data, event.data.json());
    } catch (e) {
      data.body = event.data.text();
    }
  }

  event.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: data.icon,
      badge: data.badge,
      vibrate: [200, 100, 200],
      data: { url: '/' }
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windowClients) => {
      for (let client of windowClients) {
        if (client.url.includes(self.location.origin) && 'focus' in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) {
        return clients.openWindow('/');
      }
    })
  );
});
