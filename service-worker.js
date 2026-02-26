const CACHE = "cashhome-admin-v1";
const ASSETS = [
  "/admin_login.php",
  "/manifest.webmanifest",
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", (event) => {
  // 네트워크 우선 + 실패 시 캐시
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});