/* Branchly service worker: يخلّي التطبيق يفتح بدون إنترنت ويتحدث تلقائياً */
const V='bl-v1',SHELL=['./','index.html','manifest.webmanifest','icon-192.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(V).then(c=>c.addAll(SHELL)).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==V).map(k=>caches.delete(k)))).then(()=>self.clients.claim()))});
self.addEventListener('fetch',e=>{
  const r=e.request,u=new URL(r.url);
  if(r.method!=='GET')return;
  if(u.hostname.endsWith('.supabase.co'))return;              // بيانات حيّة: لا كاش
  if(u.origin===location.origin){                              // الصفحة: الشبكة أولاً ثم الكاش
    e.respondWith(fetch(r).then(x=>{const c=x.clone();caches.open(V).then(k=>k.put(r,c));return x}).catch(()=>caches.match(r).then(m=>m||caches.match('index.html'))));
    return;
  }
  if(/cdnjs|jsdelivr|unpkg|fonts\.(googleapis|gstatic)/.test(u.hostname)){   // مكتبات وخطوط: الكاش أولاً
    e.respondWith(caches.match(r).then(m=>m||fetch(r).then(x=>{const c=x.clone();caches.open(V).then(k=>k.put(r,c));return x})));
  }
});
