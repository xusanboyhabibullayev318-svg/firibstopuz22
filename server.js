// FiribStop UZ 2.7.9 — hardened cybersecurity news proxy
// Node.js 18+; zero external dependencies.
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { URL } = require('node:url');
const { buildAssetLinks } = require('./assetlinks');
const { fetchRadarData, fetchSiteSecurityEvents } = require('./cloudflare-threats');

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const CACHE_MS = 10 * 60 * 1000; // 10 minutes
const MAX_FEED_BYTES = 2 * 1024 * 1024;
const MAX_GEO_BYTES = 5 * 1024 * 1024;
const RATE_WINDOW_MS = 60 * 1000;
const RATE_LIMIT = 120;
const RATE_LIMIT_REFRESH = 8;
const corsAllowlist = new Set(String(process.env.CORS_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean));
const requestCounts = new Map();

let newsCache = { items: [], sources: [], updatedAt: null, fetchedAt: 0 };
let geoCache = null;
const urlhausCache = new Map();

const FEEDS = [
  { name: 'UZCERT — официальные новости Узбекистана', url: 'https://uzcert.uz/ru/feed', official: true },
  { name: 'SecurityLab — новости ИБ', url: 'https://www.securitylab.ru/_services/export/rss/news/', official: false },
  { name: 'Securelist — аналитика киберугроз', url: 'https://securelist.ru/feed/', official: false },
  { name: 'Kaspersky — блог и новости ИБ', url: 'https://www.kaspersky.ru/blog/feed/', official: false },
  { name: 'Anti-Malware.ru — новости ИБ', url: 'https://www.anti-malware.ru/rss.xml', official: false }
];

const TYPES = [
  ['ransomware', /ransomware|ransom|шифровальщик|вымогател/i],
  ['уязвимости', /vulnerabilit|cve-|zero.day|уязвимост|эксплуатац/i],
  ['фишинг', /phish|scam|fraud|фишинг|мошеннич/i],
  ['утечка данных', /data breach|leak|exposed data|утечк/i],
  ['вредоносное ПО', /malware|trojan|botnet|вредоносн|троян/i],
  ['кибератака / инцидент', /cyber.?attack|hack(ed|ing)?|incident|attack|кибератак|взлом|инцидент/i]
];

function decode(s = '') {
  return String(s)
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&#x([\da-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16)))
    .replace(/\s+/g, ' ')
    .trim();
}

function tag(block, names) {
  for (const name of names) {
    const re = new RegExp('<' + name + '(?:\\s[^>]*)?>([\\s\\S]*?)<\\/' + name + '\\s*>', 'i');
    const m = block.match(re);
    if (m) return m[1];
  }
  return '';
}

function classify(text) {
  for (const [name, re] of TYPES) if (re.test(text)) return name;
  return 'кибербезопасность';
}

function cleanUrl(raw) {
  const s = decode(raw);
  try {
    const u = new URL(s);
    return ['http:', 'https:'].includes(u.protocol) ? u.href : '';
  } catch {
    return '';
  }
}

function parseFeed(xml, feed) {
  const blocks = xml.match(/<(?:item|entry)(?:\s[^>]*)?>[\s\S]*?<\/(?:item|entry)\s*>/gi) || [];
  return blocks.map((b) => {
    const title = decode(tag(b, ['title']));
    let link = tag(b, ['link']);
    if (!link) {
      const m = b.match(/<link\s+[^>]*href=["']([^"']+)["'][^>]*\/?\s*>/i);
      if (m) link = m[1];
    }
    let url = cleanUrl(link);
    if (!url) {
      const m = b.match(/<guid[^>]*>([\s\S]*?)<\/guid>/i);
      if (m) url = cleanUrl(m[1]);
    }
    const description = decode(tag(b, ['description', 'summary', 'content:encoded', 'content'])).slice(0, 700);
    const date = decode(tag(b, ['pubDate', 'published', 'updated', 'dc:date', 'date']));
    const parsedDate = date && !Number.isNaN(Date.parse(date)) ? new Date(date).toISOString() : null;
    if (!title || !url) return null;
    const text = title + ' ' + description;
    return {
      id: Buffer.from(url).toString('base64url').slice(0, 80),
      title,
      description,
      url,
      date: parsedDate,
      source: feed.name,
      category: classify(text),
      important: /critical|actively exploited|zero.day|ransomware|data breach|кибератак|критическ|активно эксплуат/i.test(text),
      official: feed.official,
      region: null,
      confidence: 'Источник публикации; географическая привязка не подтверждена'
    };
  }).filter(Boolean);
}

async function readResponseTextLimited(response, maxBytes) {
  const advertised = Number(response.headers.get('content-length') || 0);
  if (advertised > maxBytes) throw new Error(`Upstream response exceeds ${maxBytes} bytes`);
  if (!response.body || typeof response.body.getReader !== 'function') {
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > maxBytes) throw new Error(`Upstream response exceeds ${maxBytes} bytes`);
    return text;
  }
  const reader = response.body.getReader();
  const chunks = []; let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) { await reader.cancel().catch(() => {}); throw new Error(`Upstream response exceeds ${maxBytes} bytes`); }
      chunks.push(Buffer.from(value));
    }
  } finally { try { reader.releaseLock(); } catch {} }
  return Buffer.concat(chunks, size).toString('utf8');
}

function checkOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return { allowed: true, origin: null };
  let sameOrigin = false;
  try {
    const proto = String(req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http')).split(',')[0].trim();
    const host = String(req.headers.host || '').split(',')[0].trim();
    sameOrigin = !!host && new URL(origin).origin === `${proto}://${host}`;
  } catch {}
  const allowed = sameOrigin || corsAllowlist.has(origin);
  if (allowed) return { allowed: true, origin };
  return { allowed: false, origin };
}

function clientKey(req) {
  // Trust forwarded client IP only when enabled for a known hosting proxy.
  if ((process.env.TRUST_PROXY === '1' || process.env.RENDER === 'true') && req.headers['x-forwarded-for']) {
    const chain = String(req.headers['x-forwarded-for']).split(',').map(x => x.trim()).filter(Boolean);
    if (chain.length) return chain[chain.length - 1];
  }
  return req.socket.remoteAddress || 'unknown';
}

async function readRequestBodyLimited(req, maxBytes) {
  const advertised = Number(req.headers['content-length'] || 0);
  if (advertised > maxBytes) throw Object.assign(new Error('Request body too large'), { statusCode: 413 });
  const chunks = []; let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw Object.assign(new Error('Request body too large'), { statusCode: 413 });
    chunks.push(chunk);
  }
  if (!size) throw Object.assign(new Error('Request body is empty'), { statusCode: 400 });
  try { return JSON.parse(Buffer.concat(chunks, size).toString('utf8')); }
  catch { throw Object.assign(new Error('Request body must be valid JSON'), { statusCode: 400 }); }
}

function rateLimit(req, res, refresh = false) {
  const now = Date.now(), key = clientKey(req), entry = requestCounts.get(key);
  if (!entry || now - entry.started >= RATE_WINDOW_MS) requestCounts.set(key, { started: now, count: 1, refresh: refresh ? 1 : 0 });
  else { entry.count++; if (refresh) entry.refresh++; }
  const current = requestCounts.get(key);
  if (current.count > RATE_LIMIT || current.refresh > RATE_LIMIT_REFRESH) {
    res.setHeader('retry-after', String(Math.max(1, Math.ceil((RATE_WINDOW_MS - (now - current.started)) / 1000))));
    send(res, 429, { error: 'Слишком много запросов. Попробуйте позже.' });
    return false;
  }
  if (requestCounts.size > 5000) for (const [k, v] of requestCounts) if (now - v.started > RATE_WINDOW_MS * 2) requestCounts.delete(k);
  return true;
}

async function fetchFeed(feed) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 9000);
  try {
    const r = await fetch(feed.url, {
      signal: controller.signal,
      headers: {
        'user-agent': 'FiribStop-Community-Security-News/2.5',
        'accept': 'application/rss+xml, application/atom+xml, application/xml, text/xml, */*'
      }
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const xml = await readResponseTextLimited(r, MAX_FEED_BYTES);
    if (!xml.includes('<')) throw new Error('Ответ не похож на XML');
    const items = parseFeed(xml, feed);
    return { items, status: { name: feed.name, ok: true, count: items.length } };
  } finally {
    clearTimeout(timer);
  }
}

const { loadNews: loadSharedNews } = require('./news-feed');
async function loadNews(force = false) {
  const d = await loadSharedNews(force);
  newsCache = d;
  return d;
}

async function loadGeo() {
  if (geoCache) return geoCache;
  const urls = [
    'https://raw.githubusercontent.com/akbartus/GeoJSON-Uzbekistan/main/geojson/uzbekistan_regional.geojson',
    'https://raw.githubusercontent.com/negeloT/uzbekistan_borders/main/GEOJSON_LVL/uzbekistan_lvl2.geojson'
  ];
  for (const url of urls) {
    try {
      const r = await fetch(url, {
        headers: { 'user-agent': 'FiribStop-Community-Map/2.5' },
        signal: AbortSignal.timeout(3000)
      });
      if (!r.ok) continue;
      const j = JSON.parse(await readResponseTextLimited(r, MAX_GEO_BYTES));
      if (j && j.type === 'FeatureCollection' && Array.isArray(j.features) && j.features.length >= 10) {
        geoCache = j;
        return j;
      }
    } catch {
      // try next
    }
  }
  // Reliable offline fallback: the app has a bundled schematic cartogram.
  // It is clearly marked as schematic and is not presented as official boundaries.
  try {
    const fallbackPath = path.join(ROOT, 'data', 'uzbekistan-regions-schematic.geojson');
    const fallback = JSON.parse(fs.readFileSync(fallbackPath, 'utf8'));
    if (fallback && fallback.type === 'FeatureCollection' && Array.isArray(fallback.features) && fallback.features.length >= 10 && fallback.metadata?.schematic === true) {
      geoCache = fallback;
      return fallback;
    }
  } catch { /* fall through to diagnostic error */ }
  throw new Error('Геоданные и встроенная схема регионов недоступны');
}

const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'x-frame-options': 'SAMEORIGIN',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin'
};

function send(res, code, data, type = 'application/json; charset=utf-8') {
  const body = type.startsWith('application/json') ? JSON.stringify(data) : data;
  const headers = {
    'content-type': type,
    'cache-control': type.startsWith('application/json') ? 'no-store' : 'public, max-age=3600',
    ...SECURITY_HEADERS
  };
  // Light CSP for HTML responses
  if (type.includes('text/html')) {
    headers['content-security-policy'] = [
      "default-src 'self'",
      "script-src 'self'",
      "script-src-attr 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https: blob:",
      "connect-src 'self' https:",
      "frame-src 'self' https://cyberattackmap.net",
      "font-src 'self'",
      "frame-ancestors 'self'",
      "base-uri 'self'",
      "form-action 'self'",
      "object-src 'none'",
      "upgrade-insecure-requests"
    ].join('; ');
  }
  res.writeHead(code, headers);
  res.end(res.req && res.req.method === 'HEAD' ? undefined : body);
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.geojson': 'application/geo+json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.webmanifest': 'application/manifest+json',
  '.txt': 'text/plain; charset=utf-8',
  '.ico': 'image/x-icon'
};

const server = http.createServer(async (req, res) => {
  if (req.method === 'HEAD' || req.method === 'GET') {
    // HEAD handled like GET below with empty body where needed
  }

  const originCheck = checkOrigin(req);
  if (!originCheck.allowed) return send(res, 403, { error: 'Origin is not allowed' });
  if (originCheck.origin) {
    res.setHeader('access-control-allow-origin', originCheck.origin);
    res.setHeader('vary', 'Origin');
    res.setHeader('access-control-allow-methods', 'GET, HEAD, OPTIONS');
    res.setHeader('access-control-allow-headers', 'Content-Type, Accept');
  }
  if (req.method === 'OPTIONS') {
    if (!originCheck.origin) return send(res, 204, '');
    return send(res, 204, '');
  }
  let u;
  try { u = new URL(req.url, 'http://localhost'); }
  catch { return send(res, 400, { error: 'Invalid request URL' }); }
  const isUrlhausLookup = req.method === 'POST' && u.pathname === '/api/intel/urlhaus';
  if (!['GET', 'HEAD'].includes(req.method) && !isUrlhausLookup) return send(res, 405, { error: 'Method not allowed' });
  const isApi = u.pathname.startsWith('/api/');
  if (isApi && !rateLimit(req, res, u.pathname === '/api/news' && u.searchParams.get('refresh') === '1')) return;

  try {
    if ((req.method === 'GET' || req.method === 'HEAD') && u.pathname === '/api/health') {
      return send(res, 200, {
        ok: true,
        service: 'FiribStop live threat news',
        version: '2.7.9',
        now: new Date().toISOString(),
        cacheMinutes: CACHE_MS / 60000
      });
    }

    if (req.method === 'GET' && u.pathname === '/api/radar-data') {
      const data = await fetchRadarData({ force: u.searchParams.get('refresh') === '1' });
      return send(res, data.status === 'upstream_error' ? 502 : 200, data);
    }

    if (req.method === 'GET' && u.pathname === '/api/site-security-events') {
      const data = await fetchSiteSecurityEvents({ force: u.searchParams.get('refresh') === '1' });
      return send(res, 200, data);
    }

    if (req.method === 'GET' && u.pathname === '/api/news') {
      const d = await loadNews(u.searchParams.get('refresh') === '1');
      return send(res, 200, {
        items: d.items,
        sources: d.sources,
        updatedAt: d.updatedAt,
        stale: Boolean(d.stale)
      });
    }

    if (req.method === 'GET' && u.pathname === '/api/analytics') {
      const d = await loadNews(false);
      const categories = {};
      const sources = {};
      const months = {};
      for (const n of d.items) {
        categories[n.category] = (categories[n.category] || 0) + 1;
        sources[n.source] = (sources[n.source] || 0) + 1;
        if (n.date) {
          const m = n.date.slice(0, 7);
          months[m] = (months[m] || 0) + 1;
        }
      }
      return send(res, 200, {
        total: d.items.length,
        important: d.items.filter((x) => x.important).length,
        categories,
        sources,
        months,
        updatedAt: d.updatedAt,
        method: 'Статистика публикаций из RSS, не статистика всех кибератак.'
      });
    }

    if (req.method === 'GET' && u.pathname === '/api/attacks') {
      const d = await loadNews(false);
      return send(res, 200, {
        items: d.items.filter((x) =>
          /кибератак \/ инцидент|вредоносное ПО|утечка данных|фишинг|ransomware|уязвимости/i.test(x.category)
        ),
        updatedAt: d.updatedAt,
        notice: 'Это сообщения СМИ и бюллетени безопасности, не подтверждённый глобальный поток атак.'
      });
    }

    
    if (req.method === 'POST' && u.pathname === '/api/intel/urlhaus') {
      let lookupBody;
      try { lookupBody = await readRequestBodyLimited(req, 4096); }
      catch (e) { return send(res, e.statusCode || 400, { error: e.message || 'Invalid request body' }); }
      const target = String(lookupBody.url || '').trim();
      if (!target || target.length > 2048) return send(res, 400, { error: 'Укажите один URL длиной до 2048 символов.' });
      let parsed;
      try { parsed = new URL(target); } catch { return send(res, 400, { error: 'Некорректный URL.' }); }
      if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return send(res, 400, { error: 'Разрешены только HTTP/HTTPS URL без встроенных логина и пароля.' });
      if (!process.env.URLHAUS_AUTH_KEY) return send(res, 503, { error: 'Онлайн-проверка не настроена. Добавьте URLHAUS_AUTH_KEY в переменные окружения хостинга. Локальная проверка доступна без ключа.', source: 'URLhaus (abuse.ch)' });
      const now = Date.now(), cacheKey = parsed.href;
      const cached = urlhausCache.get(cacheKey);
      if (cached && cached.expiresAt > now) return send(res, 200, { ...cached.value, cached: true });
      try {
        const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
          method: 'POST',
          headers: { 'Auth-Key': process.env.URLHAUS_AUTH_KEY, 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'FiribStop-Community/2.7.9' },
          body: new URLSearchParams({ url: parsed.href }),
          signal: AbortSignal.timeout(7000),
          redirect: 'error'
        });
        const payloadText = await readResponseTextLimited(response, 512 * 1024);
        if (!response.ok) return send(res, response.status === 401 || response.status === 403 ? 503 : 502, { error: `URLhaus ответил HTTP ${response.status}. Проверьте API-ключ и доступность сервиса.` });
        const payload = JSON.parse(payloadText);
        const value = {
          source: 'URLhaus (abuse.ch)', checkedAt: new Date().toISOString(), validUntil: new Date(now + 5 * 60 * 1000).toISOString(),
          queryStatus: String(payload.query_status || 'unknown'),
          url: String(payload.url || parsed.href),
          urlStatus: payload.url_status ? String(payload.url_status) : null,
          threat: payload.threat ? String(payload.threat) : null,
          tags: Array.isArray(payload.tags) ? payload.tags.map(String).slice(0, 20) : [],
          dateAdded: payload.date_added ? String(payload.date_added) : null,
          reference: payload.urlhaus_reference ? String(payload.urlhaus_reference) : 'https://urlhaus.abuse.ch/'
        };
        urlhausCache.set(cacheKey, { value, expiresAt: now + 5 * 60 * 1000 });
        if (urlhausCache.size > 100) urlhausCache.delete(urlhausCache.keys().next().value);
        return send(res, 200, { ...value, cached: false });
      } catch (e) {
        return send(res, 502, { error: 'Не удалось проверить URL через URLhaus. Попробуйте позже.', detail: String(e.message || e).slice(0, 120), source: 'URLhaus (abuse.ch)' });
      }
    }

    if (req.method === 'GET' && u.pathname === '/api/threats') {
      const threatsPath = path.join(ROOT, 'data', 'threats.json');
      try {
        const raw = fs.readFileSync(threatsPath, 'utf8');
        const data = JSON.parse(raw);
        return send(res, 200, data);
      } catch (e) {
        return send(res, 404, { error: 'Threat database not found' });
      }
    }

    if (req.method === 'GET' && u.pathname === '/api/regions') {
      const g = await loadGeo();
      return send(res, 200, g);
    }

    if ((req.method === 'GET' || req.method === 'HEAD') && u.pathname === '/.well-known/assetlinks.json') {
      const links = buildAssetLinks();
      return links ? send(res, 200, links) : send(res, 404, { error: 'ANDROID_PACKAGE / ANDROID_SHA256_CERTS are not set' });
    }

    if (req.method === 'GET' || req.method === 'HEAD') {
      let p;
      try { p = decodeURIComponent(u.pathname); } catch { return send(res, 400, { error: 'Invalid path encoding' }); }
      if (p === '/') p = '/index.html';
      const full = path.resolve(ROOT, '.' + p);
      const relative = path.relative(ROOT, full).replace(/\\/g, '/');
      const blockedFiles = new Set(['server.js','package.json','README.md','DEPLOY.txt','.gitignore','render.yaml','known_apk_hashes.template.json','news-feed.js','cloudflare-threats.js','assetlinks.js']);
      if (relative.startsWith('.') || relative.split('/').some(part => part.startsWith('.')) || blockedFiles.has(relative) || relative.startsWith('tests/') || relative.startsWith('scripts/') || relative.startsWith('js/') || relative.startsWith('css/')) return send(res, 404, { error: 'Not found' });
      if (!full.startsWith(ROOT + path.sep) && full !== path.join(ROOT, 'index.html')) {
        return send(res, 403, { error: 'Forbidden' });
      }
      fs.readFile(full, (err, data) => {
        if (err) return send(res, 404, { error: 'Not found' });
        const ext = path.extname(full);
        send(res, 200, data, MIME[ext] || 'application/octet-stream');
      });
      return;
    }

    return send(res, 405, { error: 'Method not allowed' });
  } catch (e) {
    return send(res, 502, {
      error: e.message || 'Upstream source unavailable',
      items: [],
      sources: [],
      updatedAt: newsCache.updatedAt || null
    });
  }
});

server.headersTimeout = 15_000;
server.requestTimeout = 20_000;
server.keepAliveTimeout = 5_000;
server.maxRequestsPerSocket = 100;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`FiribStop UZ 2.7.9 listening on http://0.0.0.0:${PORT}`);
});
