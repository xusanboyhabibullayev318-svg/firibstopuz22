'use strict';

const RADAR_BASE = 'https://api.cloudflare.com/client/v4/radar';
const GRAPHQL_URL = 'https://api.cloudflare.com/client/v4/graphql';
const RADAR_CACHE_MS = 5 * 60 * 1000;
const SITE_CACHE_MS = 2 * 60 * 1000;
let radarCache = { expiresAt: 0, value: null, pending: null };
let siteCache = { expiresAt: 0, value: null, pending: null };

function safeText(value, max = 120) {
  return String(value == null ? '' : value).replace(/[\u0000-\u001f\u007f]/g, '').slice(0, max);
}

async function fetchJson(url, headers, timeoutMs = 8000) {
  const response = await fetch(url, {
    method: 'GET',
    headers,
    signal: AbortSignal.timeout(timeoutMs),
    redirect: 'error',
    cache: 'no-store'
  });
  const text = await response.text();
  let body;
  try { body = JSON.parse(text); } catch { throw new Error(`Источник вернул не JSON (HTTP ${response.status})`); }
  if (!response.ok) {
    const message = body && Array.isArray(body.errors) && body.errors[0] && body.errors[0].message;
    throw new Error(`Cloudflare Radar HTTP ${response.status}${message ? `: ${safeText(message, 140)}` : ''}`);
  }
  if (body && body.success === false) {
    const message = Array.isArray(body.errors) && body.errors[0] && body.errors[0].message;
    throw new Error(`Cloudflare Radar: ${safeText(message || 'API rejected the request', 140)}`);
  }
  return body;
}

function metaOf(body) {
  return body && body.result && body.result.meta ? body.result.meta : {};
}

function countryRows(body, kind) {
  const result = body && body.result ? body.result : {};
  const arrays = Object.keys(result).filter(key => /^top_\d+$/.test(key) && Array.isArray(result[key])).map(key => result[key]);
  const rows = arrays.flat();
  const codeKeys = kind === 'origin'
    ? ['originCountryAlpha2', 'originLocationAlpha2', 'originCountryCode', 'origin']
    : ['targetCountryAlpha2', 'targetLocationAlpha2', 'targetCountryCode', 'target'];
  const nameKeys = kind === 'origin'
    ? ['originCountryName', 'originLocationName', 'originName']
    : ['targetCountryName', 'targetLocationName', 'targetName'];
  return rows.map(row => {
    if (!row || typeof row !== 'object') return null;
    const code = codeKeys.map(k => row[k]).find(v => typeof v === 'string' && /^[A-Za-z]{2}$/.test(v));
    const name = nameKeys.map(k => row[k]).find(v => typeof v === 'string');
    const value = Number(row.value ?? row.percentage ?? row.count ?? row.attacks);
    if (!code || !Number.isFinite(value)) return null;
    return { code: code.toUpperCase(), name: safeText(name || code.toUpperCase(), 80), value: Math.max(0, value) };
  }).filter(Boolean).sort((a, b) => b.value - a.value).slice(0, 20);
}

function summaryRows(body) {
  const result = body && body.result ? body.result : {};
  const summary = result.summary_0 && typeof result.summary_0 === 'object' ? result.summary_0 : {};
  const meta = metaOf(body);
  const unit = Array.isArray(meta.units) && meta.units[0] ? safeText(meta.units[0].value, 40) : '';
  const normalization = safeText(meta.normalization || '', 40);
  return Object.entries(summary).map(([label, value]) => ({
    label: safeText(label, 70),
    value: Number(value),
    normalization, unit
  })).filter(x => Number.isFinite(x.value)).sort((a, b) => b.value - a.value).slice(0, 12);
}

function bestLastUpdated(bodies) {
  const dates = bodies.map(metaOf).map(m => m.lastUpdated).filter(Boolean).map(v => ({ raw: v, time: Date.parse(v) })).filter(v => Number.isFinite(v.time)).sort((a, b) => b.time - a.time);
  return dates.length ? dates[0].raw : null;
}

async function fetchRadarData(options = {}) {
  const token = safeText(options.token ?? process.env.CLOUDFLARE_RADAR_API_TOKEN, 4096).trim();
  const now = Date.now();
  if (!token) {
    return {
      configured: false,
      status: 'not_configured',
      source: 'Cloudflare Radar API',
      fetchedAt: new Date(now).toISOString(),
      sourceUpdatedAt: null,
      period: '24h',
      message: 'Добавьте CLOUDFLARE_RADAR_API_TOKEN в переменные окружения Netlify или сервера. Токен хранится на сервере и не передаётся в браузер.',
      topOrigins: [], topTargets: [], vectors: [], protocols: [],
      sourceLink: 'https://radar.cloudflare.com/security-and-attacks',
      documentation: 'https://developers.cloudflare.com/radar/get-started/first-request/'
    };
  }
  if (!options.force && radarCache.value && radarCache.expiresAt > now) return { ...radarCache.value, cached: true };
  if (!options.force && radarCache.pending) return radarCache.pending;

  radarCache.pending = (async () => {
    const headers = { Authorization: `Bearer ${token}`, Accept: 'application/json', 'User-Agent': 'FiribStop-UZ-Real-Radar/2.7.7' };
    const specs = [
      ['origins', '/attacks/layer3/top/locations/origin?dateRange=1d&limit=15&format=JSON'],
      ['targets', '/attacks/layer3/top/locations/target?dateRange=1d&limit=15&format=JSON'],
      ['vectors', '/attacks/layer3/summary/VECTOR?dateRange=1d&format=JSON'],
      ['protocols', '/attacks/layer3/summary/PROTOCOL?dateRange=1d&format=JSON']
    ];
    const settled = await Promise.all(specs.map(async ([key, endpoint]) => {
      try { return { key, body: await fetchJson(`${RADAR_BASE}${endpoint}`, headers) }; }
      catch (error) { return { key, error: safeText(error.message || error, 180) }; }
    }));
    const found = Object.fromEntries(settled.filter(x => x.body).map(x => [x.key, x.body]));
    const errors = settled.filter(x => x.error).map(x => ({ dataset: x.key, message: x.error }));
    if (!Object.keys(found).length) {
      const response = {
        configured: true, status: 'upstream_error', source: 'Cloudflare Radar API', fetchedAt: new Date().toISOString(),
        sourceUpdatedAt: null, period: '24h', topOrigins: [], topTargets: [], vectors: [], protocols: [], errors,
        message: 'Cloudflare Radar не вернул доступные наборы данных. Проверьте разрешения токена и повторите запрос.',
        sourceLink: 'https://radar.cloudflare.com/security-and-attacks',
        documentation: 'https://developers.cloudflare.com/radar/get-started/first-request/'
      };
      radarCache = { expiresAt: now + 45_000, value: response, pending: null };
      return response;
    }
    const successfulBodies = Object.values(found);
    const response = {
      configured: true,
      status: errors.length ? 'partial' : 'ok',
      source: 'Cloudflare Radar API',
      fetchedAt: new Date().toISOString(),
      sourceUpdatedAt: bestLastUpdated(successfulBodies),
      period: '24h',
      topOrigins: found.origins ? countryRows(found.origins, 'origin') : [],
      topTargets: found.targets ? countryRows(found.targets, 'target') : [],
      vectors: found.vectors ? summaryRows(found.vectors) : [],
      protocols: found.protocols ? summaryRows(found.protocols) : [],
      confidence: successfulBodies.map(metaOf).map(m => m.confidenceInfo && m.confidenceInfo.level).filter(v => v !== undefined),
      dateRange: successfulBodies.map(metaOf).map(m => m.dateRange).find(Boolean) || null,
      errors,
      message: 'Агрегированная статистика сетевых атак за 24 часа по данным Cloudflare Radar; не поток каждого отдельного пакета и не оценка атак именно на Узбекистан.',
      sourceLink: 'https://radar.cloudflare.com/security-and-attacks',
      documentation: 'https://developers.cloudflare.com/radar/get-started/first-request/'
    };
    radarCache = { expiresAt: now + RADAR_CACHE_MS, value: response, pending: null };
    return response;
  })().catch(error => {
    radarCache.pending = null;
    throw error;
  });
  return radarCache.pending;
}

async function fetchSiteSecurityEvents(options = {}) {
  const env = options.env || process.env;
  const zoneId = safeText(options.zoneId ?? env.CLOUDFLARE_ZONE_ID, 64).trim();
  const token = safeText(options.token ?? env.CLOUDFLARE_ZONE_API_TOKEN, 4096).trim();
  const now = Date.now();
  const base = { source: 'Cloudflare Firewall Events', fetchedAt: new Date(now).toISOString(), period: 'last 24 hours', events: [], byCountry: [], byAction: [], totalEvents: 0 };
  if (!/^[a-f0-9]{32}$/i.test(zoneId) || !token) {
    return { ...base, configured: false, status: 'not_configured', message: 'Нужен собственный домен, проксируемый через Cloudflare, CLOUDFLARE_ZONE_ID и CLOUDFLARE_ZONE_API_TOKEN с правом чтения аналитики зоны. Netlify-поддомен сам по себе не даёт доступ к событиям Cloudflare.' };
  }
  if (!options.force && siteCache.value && siteCache.expiresAt > now) return { ...siteCache.value, cached: true };
  if (!options.force && siteCache.pending) return siteCache.pending;
  siteCache.pending = (async () => {
    const start = new Date(now - 24 * 60 * 60 * 1000).toISOString();
    const end = new Date(now).toISOString();
    // Only aggregate action/country/time. Individual IP addresses and user agents are never requested or returned.
    const query = `query FiribStopSecurityEvents { viewer { zones(filter: { zoneTag: "${zoneId}" }) { firewallEventsAdaptiveGroups(filter: { datetime_gt: "${start}", datetime_lt: "${end}" }, limit: 500, orderBy: [datetimeHour_DESC]) { count dimensions { action clientCountryName datetimeHour } } } } }`;
    const response = await fetch(GRAPHQL_URL, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json', 'User-Agent': 'FiribStop-UZ-Site-Security/2.7.7' },
      body: JSON.stringify({ query }),
      signal: AbortSignal.timeout(8000),
      redirect: 'error',
      cache: 'no-store'
    });
    const raw = await response.text();
    let body;
    try { body = JSON.parse(raw); } catch { throw new Error(`Cloudflare Analytics вернул не JSON (HTTP ${response.status})`); }
    if (!response.ok || body.errors || !body.data) {
      const error = body.errors && body.errors[0] && body.errors[0].message;
      throw new Error(`Cloudflare Analytics: ${safeText(error || `HTTP ${response.status}`, 180)}`);
    }
    const zone = (body.data.viewer && body.data.viewer.zones || [])[0];
    const rows = zone && Array.isArray(zone.firewallEventsAdaptiveGroups) ? zone.firewallEventsAdaptiveGroups : [];
    const byCountryMap = new Map(), byActionMap = new Map();
    let total = 0;
    const events = rows.slice(0, 500).map(row => {
      const count = Math.max(0, Number(row.count) || 0), d = row.dimensions || {};
      const action = safeText(d.action || 'unknown', 40), country = safeText(d.clientCountryName || 'Не определено', 60), hour = safeText(d.datetimeHour || '', 40);
      total += count;
      byCountryMap.set(country, (byCountryMap.get(country) || 0) + count);
      byActionMap.set(action, (byActionMap.get(action) || 0) + count);
      return { count, action, country, hour };
    });
    const value = {
      ...base, configured: true, status: 'ok', fetchedAt: new Date().toISOString(),
      periodStart: start, periodEnd: end, totalEvents: total, events,
      byCountry: [...byCountryMap].map(([country, count]) => ({ country, count })).sort((a, b) => b.count - a.count).slice(0, 12),
      byAction: [...byActionMap].map(([action, count]) => ({ action, count })).sort((a, b) => b.count - a.count).slice(0, 12),
      message: 'Сгруппированные события Cloudflare Firewall за последние 24 часа. Адаптивная выборка может применяться; событие защиты не всегда означает подтверждённую атаку. IP-адреса не запрашиваются.'
    };
    siteCache = { expiresAt: now + SITE_CACHE_MS, value, pending: null };
    return value;
  })().catch(error => {
    siteCache.pending = null;
    throw error;
  });
  return siteCache.pending;
}

function resetCachesForTests() {
  radarCache = { expiresAt: 0, value: null, pending: null };
  siteCache = { expiresAt: 0, value: null, pending: null };
}

module.exports = { fetchRadarData, fetchSiteSecurityEvents, resetCachesForTests };
