'use strict';

// Shared RSS reader for the Node server and Netlify Functions.
// It returns only real source entries; feed failures are surfaced in `sources`.
const FEEDS = [
  { name: 'UZCERT — официальные новости Узбекистана', url: 'https://uzcert.uz/ru/feed', official: true },
  { name: 'SecurityLab — новости ИБ', url: 'https://www.securitylab.ru/_services/export/rss/news/', official: false },
  { name: 'Securelist — аналитика киберугроз', url: 'https://securelist.ru/feed/', official: false },
  { name: 'Kaspersky — блог и новости ИБ', url: 'https://www.kaspersky.ru/blog/feed/', official: false },
  { name: 'Anti-Malware.ru — новости ИБ', url: 'https://www.anti-malware.ru/rss.xml', official: false }
];
const MAX_FEED_BYTES = 2 * 1024 * 1024;
const CACHE_MS = 5 * 60 * 1000;
const FAIL_CACHE_MS = 30 * 1000; // do not pin an all-failed result for the full 5 minutes
const FEED_TIMEOUT_MS = 6500;
const BROWSER_UA = 'Mozilla/5.0 (compatible; FiribStopNewsBot/2.8; +https://uzcert.uz) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';
let cache = { items: [], sources: [], updatedAt: null, fetchedAt: 0, ttl: CACHE_MS };

function decode(s = '') {
  return String(s)
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => { const k = Number(n); try { return Number.isFinite(k) ? String.fromCodePoint(k) : ''; } catch { return ''; } })
    .replace(/&#x([\da-f]+);/gi, (_, n) => { const k = parseInt(n, 16); try { return Number.isFinite(k) ? String.fromCodePoint(k) : ''; } catch { return ''; } })
    .replace(/\s+/g, ' ').trim();
}
function tag(block, names) {
  for (const name of names) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const m = block.match(new RegExp('<' + escaped + '(?:\\s[^>]*)?>([\\s\\S]*?)<\\/' + escaped + '\\s*>', 'i'));
    if (m) return m[1];
  }
  return '';
}
function cleanUrl(raw) {
  try { const u = new URL(decode(raw)); return ['http:', 'https:'].includes(u.protocol) ? u.href : ''; }
  catch { return ''; }
}
function classify(text) {
  const types = [
    ['ransomware', /ransomware|ransom|шифровальщик|вымогател/i],
    ['уязвимости', /vulnerabilit|cve-|zero.day|уязвимост|эксплуатац/i],
    ['фишинг', /phish|scam|fraud|фишинг|мошеннич/i],
    ['утечка данных', /data breach|leak|exposed data|утечк/i],
    ['вредоносное ПО', /malware|trojan|botnet|вредоносн|троян/i],
    ['кибератака / инцидент', /cyber.?attack|hack(ed|ing)?|incident|attack|кибератак|взлом|инцидент/i]
  ];
  for (const [name, re] of types) if (re.test(text)) return name;
  return 'кибербезопасность';
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
    if (!url) { const m = b.match(/<guid[^>]*>([\s\S]*?)<\/guid>/i); if (m) url = cleanUrl(m[1]); }
    const description = decode(tag(b, ['description', 'summary', 'content:encoded', 'content'])).slice(0, 700);
    const rawDate = decode(tag(b, ['pubDate', 'published', 'updated', 'dc:date', 'date']));
    const timestamp = rawDate ? Date.parse(rawDate) : NaN;
    const date = Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : null;
    if (!title || !url) return null;
    const text = title + ' ' + description;
    return {
      id: Buffer.from(url).toString('base64url').slice(0, 80), title, description, url, date,
      source: feed.name, category: classify(text),
      important: /critical|actively exploited|zero.day|ransomware|data breach|кибератак|критическ|активно эксплуат/i.test(text),
      official: feed.official, region: null,
      confidence: 'Источник публикации; географическая привязка не подтверждена'
    };
  }).filter(Boolean);
}
async function readLimited(response) {
  const declared = Number(response.headers.get('content-length') || 0);
  if (declared > MAX_FEED_BYTES) throw new Error('Ответ RSS слишком большой');
  const buf = Buffer.from(await response.arrayBuffer());
  if (buf.length > MAX_FEED_BYTES) throw new Error('Ответ RSS слишком большой');
  // Detect charset from header, then from the XML declaration (some RU feeds use windows-1251).
  let charset = (String(response.headers.get('content-type') || '').match(/charset=([\w-]+)/i) || [])[1];
  if (!charset) charset = (buf.subarray(0, 200).toString('latin1').match(/<\?xml[^>]*encoding=["']([\w-]+)["']/i) || [])[1];
  let text;
  try { text = new TextDecoder(charset || 'utf-8').decode(buf); }
  catch { text = buf.toString('utf8'); }
  text = text.replace(/^\uFEFF/, '').trimStart();
  if (!text.includes('<')) throw new Error('Ответ не похож на XML');
  if (/^<!doctype html|^<html/i.test(text)) throw new Error('Источник вернул HTML вместо RSS (возможна блокировка)');
  return text;
}
async function fetchFeedOnce(feed) {
  const response = await fetch(feed.url, {
    signal: AbortSignal.timeout(FEED_TIMEOUT_MS),
    redirect: 'follow',
    headers: {
      'user-agent': BROWSER_UA,
      'accept': 'application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.9, */*;q=0.5',
      'accept-language': 'ru,en;q=0.8'
    }
  });
  if (!response.ok) throw new Error('HTTP ' + response.status);
  const items = parseFeed(await readLimited(response), feed);
  if (!items.length) throw new Error('В ленте нет записей');
  return { items, status: { name: feed.name, ok: true, count: items.length } };
}
async function fetchFeed(feed) {
  try { return await fetchFeedOnce(feed); }
  catch (first) {
    // One quick retry for transient network errors / 5xx; skip for hard 4xx.
    if (/HTTP 4\d\d/.test(String(first?.message))) throw first;
    await new Promise((r) => setTimeout(r, 400));
    return await fetchFeedOnce(feed);
  }
}
async function loadNews(force = false) {
  if (!force && cache.fetchedAt && Date.now() - cache.fetchedAt < (cache.ttl || CACHE_MS)) return cache;
  const results = await Promise.all(FEEDS.map(async (feed) => {
    try { return await fetchFeed(feed); }
    catch (error) { return { items: [], status: { name: feed.name, ok: false, error: String(error?.message || error).slice(0, 120), count: 0 } }; }
  }));
  const seen = new Set();
  const fresh = results.flatMap((result) => result.items).filter((item) => {
    const key = item.url.toLowerCase(); if (seen.has(key)) return false; seen.add(key); return true;
  }).sort((a, b) => (Date.parse(b.date) || 0) - (Date.parse(a.date) || 0)).slice(0, 160);
  const sources = results.map((result) => result.status);
  if (!fresh.length && cache.items.length) {
    // Every feed failed: serve the last good copy (marked stale) and retry soon.
    cache = { ...cache, sources, fetchedAt: Date.now(), ttl: FAIL_CACHE_MS, stale: true };
    return cache;
  }
  cache = { items: fresh, sources, updatedAt: new Date().toISOString(), fetchedAt: Date.now(), ttl: fresh.length ? CACHE_MS : FAIL_CACHE_MS, stale: false };
  return cache;
}
module.exports = { loadNews };
