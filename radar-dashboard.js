(function () {
  'use strict';
  const REFRESH_MS = 5 * 60 * 1000;
  let loading = false;
  let siteLoading = false;
  let refreshTimer = null;
  let cachedRadarData = null;
  let worldGeo = null;

  const countryCoords = {
    US:[-98,39],CA:[-106,56],MX:[-102,23],GT:[-90,15],CR:[-84,10],PA:[-80,9],CU:[-80,22],DO:[-70,19],JM:[-77,18],CO:[-73,4],VE:[-66,8],EC:[-78,-1],PE:[-75,-10],BO:[-64,-17],CL:[-71,-33],AR:[-64,-34],UY:[-56,-33],PY:[-58,-23],BR:[-51,-10],GB:[-2,54],IE:[-8,53],IS:[-19,65],PT:[-8,39],ES:[-4,40],FR:[2,46],BE:[4.5,50.5],NL:[5.3,52],LU:[6,49.8],DE:[10,51],CH:[8,47],AT:[14,47],IT:[12.5,42.5],DK:[10,56],NO:[10,62],SE:[15,62],FI:[26,64],EE:[26,59],LV:[24,57],LT:[24,56],PL:[19,52],CZ:[15,50],SK:[19.5,48.7],HU:[19,47],SI:[14.8,46],HR:[16,45],BA:[18,44],RS:[21,44],ME:[19.3,42.7],AL:[20,41],MK:[21.7,41.6],GR:[22,39],RO:[25,46],BG:[25,43],MD:[28.5,47],UA:[31,49],BY:[28,53],RU:[100,60],TR:[35,39],GE:[43.5,42],AM:[45,40],AZ:[47.5,40],KZ:[68,48],UZ:[64,41],TM:[59,39],KG:[75,41],TJ:[71,39],AF:[66,34],PK:[69,30],IN:[79,22],NP:[84,28],BD:[90,24],LK:[81,7],MM:[96,21],TH:[101,15],LA:[103,19],KH:[105,13],VN:[108,16],MY:[102,4],SG:[104,1.35],ID:[117,-2],PH:[122,13],BN:[114.7,4.5],TL:[126,-8.8],CN:[104,35],MN:[103,46],KP:[127,40],KR:[127.5,36],JP:[138,37],TW:[121,24],HK:[114,22.3],MO:[113.5,22.2],AU:[134,-25],NZ:[172,-41],PG:[145,-6],FJ:[178,-18],SA:[45,24],AE:[54,24],QA:[51,25],BH:[50.5,26],KW:[47.5,29.3],OM:[57,21],YE:[48,15],IR:[53,32],IQ:[44,33],IL:[35,31],PS:[35.2,31.9],JO:[36,31],LB:[35.8,33.8],SY:[38,35],EG:[30,26],LY:[17,25],TN:[9,34],DZ:[3,28],MA:[-7,32],SD:[30,13],ET:[40,9],KE:[38,0],UG:[32,1],TZ:[35,-6],RW:[30,-2],GH:[-2,8],NG:[8,10],CI:[-5,7.5],SN:[-14,14],CM:[12,6],CD:[23,-3],AO:[18,-12],ZM:[28,-14],ZW:[30,-19],MZ:[35,-18],ZA:[24,-29],MG:[47,-20],MU:[57,-20],UA:[31,49],CY:[33,35],MT:[14,36],LI:[9.5,47.2],MC:[7.4,43.7],AD:[1.6,42.5],SM:[12.5,43.9],VA:[12.45,41.9],XK:[21,42.6]
  };
  const toNum = v => Number.isFinite(Number(v)) ? Number(v) : 0;
  const esc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const isUz = () => document.documentElement.lang === 'uz';
  const text = (ru, uz) => isUz() ? uz : ru;
  const fmtTime = v => {
    if (!v) return text('не предоставлено', 'berilmagan');
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? text('не предоставлено', 'berilmagan') : d.toLocaleString(isUz() ? 'uz-UZ' : 'ru-RU', { dateStyle: 'short', timeStyle: 'short' });
  };

  async function fetchLocalJson(path, options = {}) {
    const response = await fetch(path, { cache: 'no-store', headers: { Accept: 'application/json' }, ...options });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  }

  async function fetchRadar(force = false) {
    const suffix = force ? '?refresh=1' : '';
    // Netlify maps /api routes to Functions. The same paths are implemented by server.js for Node hosting.
    return fetchLocalJson(`/api/radar-data${suffix}`);
  }

  async function fetchSiteSecurity(force = false) {
    const suffix = force ? '?refresh=1' : '';
    return fetchLocalJson(`/api/site-security-events${suffix}`);
  }

  function setStatus(id, message, kind = 'info') {
    const node = document.getElementById(id);
    if (!node) return;
    node.textContent = message;
    node.className = `${id === 'radarStatus' || id === 'siteSecurityStatus' ? 'radar-status' : ''} radar-status-${kind}`.trim();
  }

  function drawRankings(id, rows, kind) {
    const box = document.getElementById(id);
    if (!box) return;
    if (!Array.isArray(rows) || !rows.length) {
      box.innerHTML = `<p class="mu">${text('Нет данных от источника.', 'Manbadan ma’lumot yo‘q.')}</p>`;
      return;
    }
    const max = Math.max(1, ...rows.map(x => toNum(x.value ?? x.count)));
    box.innerHTML = rows.slice(0, 12).map(row => {
      const value = toNum(row.value ?? row.count);
      const valueText = kind === 'percent'
        ? `${value.toLocaleString(isUz() ? 'uz-UZ' : 'ru-RU', { maximumFractionDigits: 2 })}%`
        : kind === 'count'
          ? value.toLocaleString(isUz() ? 'uz-UZ' : 'ru-RU', { maximumFractionDigits: 0 })
          : (row.normalization === 'PERCENTAGE' ? `${value.toLocaleString(isUz() ? 'uz-UZ' : 'ru-RU', { maximumFractionDigits: 2 })}%` : `${value.toLocaleString(isUz() ? 'uz-UZ' : 'ru-RU', { maximumFractionDigits: 2 })}${row.unit ? ` ${esc(row.unit)}` : ''}`);
      const label = row.name || row.country || row.action || row.label || '—';
      const width = Math.max(2, Math.min(100, (value / max) * 100));
      return `<div class="radar-rank-row"><div class="radar-rank-label"><span>${esc(label)}</span><b>${valueText}</b></div><div class="radar-rank-track"><i style="width:${width.toFixed(1)}%"></i></div></div>`;
    }).join('');
  }

  function project(lon, lat, width = 960, height = 460) {
    const clampedLat = Math.max(-84, Math.min(84, lat));
    return { x: (lon + 180) / 360 * width, y: (84 - clampedLat) / 168 * height };
  }

  function pathFromRing(ring, width, height) {
    if (!Array.isArray(ring) || ring.length < 4) return '';
    const projected = [];
    for (let i = 0; i < ring.length; i++) {
      const coord = ring[i];
      if (!Array.isArray(coord) || coord.length < 2) continue;
      const p = project(toNum(coord[0]), toNum(coord[1]), width, height);
      projected.push(`${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`);
    }
    return projected.length ? projected.join(' ') + ' Z' : '';
  }

  async function loadWorldGeo() {
    if (worldGeo) return worldGeo;
    const candidates = ['./data/world-land.geojson', '/data/world-land.geojson'];
    let lastError;
    for (const url of candidates) {
      try {
        const geo = await fetchLocalJson(url);
        if (geo && geo.type === 'FeatureCollection' && Array.isArray(geo.features)) {
          worldGeo = geo;
          return worldGeo;
        }
      } catch (e) { lastError = e; }
    }
    throw lastError || new Error('World map data unavailable');
  }

  function geoPaths(geo, width, height) {
    const paths = [];
    for (const feature of (geo.features || [])) {
      const geometry = feature && feature.geometry;
      if (!geometry) continue;
      const polygons = geometry.type === 'Polygon' ? [geometry.coordinates] : geometry.type === 'MultiPolygon' ? geometry.coordinates : [];
      for (const polygon of polygons) {
        if (!Array.isArray(polygon)) continue;
        const rings = polygon.map(ring => pathFromRing(ring, width, height)).filter(Boolean);
        if (rings.length) paths.push(`<path class="radar-land" fill-rule="evenodd" d="${rings.join(' ')}"></path>`);
      }
    }
    return paths.join('');
  }

  function drawMap(data) {
    const host = document.getElementById('radarMap');
    const note = document.getElementById('radarMapNote');
    if (!host) return Promise.resolve();
    const ready = data && data.configured && ['ok', 'partial'].includes(data.status);
    return loadWorldGeo().then(geo => {
      const width = 960, height = 460;
      const grid = [];
      for (let lon = -150; lon <= 150; lon += 30) {
        const x = project(lon, 0, width, height).x;
        grid.push(`<path class="radar-gridline" d="M${x},0 V${height}"></path>`);
      }
      for (let lat = -60; lat <= 60; lat += 30) {
        const y = project(0, lat, width, height).y;
        grid.push(`<path class="radar-gridline" d="M0,${y} H${width}"></path>`);
      }
      const markers = [];
      const addMarkers = (rows, type) => (rows || []).forEach(row => {
        const code = String(row.code || '').toUpperCase(), coords = countryCoords[code];
        if (!coords) return;
        const p = project(coords[0], coords[1], width, height);
        const value = Math.max(0, toNum(row.value));
        const r = Math.max(4.4, Math.min(10.5, 4 + Math.sqrt(value) * 1.1));
        const title = `${row.name || code}: ${value.toLocaleString(isUz() ? 'uz-UZ' : 'ru-RU', { maximumFractionDigits: 2 })}%`;
        markers.push(`<g class="radar-marker ${type}"><title>${esc(title)}</title><circle class="radar-marker-halo" cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${(r * 2.2).toFixed(1)}"></circle><circle class="radar-marker-core" cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${r.toFixed(1)}"></circle><text x="${(p.x + 9).toFixed(1)}" y="${(p.y - 7).toFixed(1)}">${esc(code)}</text></g>`);
      });
      if (ready) { addMarkers(data.topOrigins, 'origin'); addMarkers(data.topTargets, 'target'); }
      host.innerHTML = `<svg class="radar-world-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="${text('Мировая карта. Маркеры основаны на данных Cloudflare Radar.', 'Dunyo xaritasi. Belgilar Cloudflare Radar ma’lumotlariga asoslangan.')}" preserveAspectRatio="xMidYMid meet"><defs><linearGradient id="radarSea" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#10283b"/><stop offset="1" stop-color="#071522"/></linearGradient><radialGradient id="radarGlow"><stop offset="0" stop-color="#143c4b"/><stop offset="1" stop-color="#071522"/></radialGradient></defs><rect width="${width}" height="${height}" rx="14" fill="url(#radarGlow)"></rect>${grid.join('')}${geoPaths(geo,width,height)}${markers.join('')}</svg>`;
      if (note) note.textContent = ready && markers.length
        ? text(`Показано маркеров: ${markers.length}. Цвет обозначает место в рейтинге источников или целей за последние 24 часа; это не координаты отдельных машин.`, `Belgilar soni: ${markers.length}. Rang so‘nggi 24 soatdagi manba yoki maqsad reytingidagi o‘rinni bildiradi; bu alohida qurilmalar koordinatasi emas.`)
        : text('Маркеров нет: это не означает отсутствие угроз. Настройте API или дождитесь ответа источника.', 'Belgilar yo‘q: bu tahdidlar yo‘qligini anglatmaydi. API sozlang yoki manba javobini kuting.');
    }).catch(() => {
      host.innerHTML = `<div class="radar-map-loading">${text('Не удалось загрузить локальную географию карты. Обновите проект и проверьте файл data/world-land.geojson.', 'Xaritaning mahalliy geografiyasini yuklab bo‘lmadi. Loyihani yangilang va data/world-land.geojson faylini tekshiring.')}</div>`;
      if (note) note.textContent = text('Географическая основа карты недоступна.', 'Xarita geografik asosi mavjud emas.');
    });
  }

  function renderRadar(data) {
    cachedRadarData = data;
    const status = document.getElementById('radarStatus');
    if (!status) return;
    document.getElementById('radarFetchedAt').textContent = fmtTime(data.fetchedAt);
    document.getElementById('radarSourceUpdatedAt').textContent = fmtTime(data.sourceUpdatedAt);
    const ok = data && data.configured && ['ok', 'partial'].includes(data.status);
    status.className = `radar-status ${ok ? 'radar-status-good' : data.status === 'not_configured' ? 'radar-status-warn' : 'radar-status-error'}`;
    status.textContent = data.message || data.error || text('Не удалось загрузить статистику.', 'Statistikani yuklab bo‘lmadi.');
    if (data.status === 'not_configured') {
      status.innerHTML = `${esc(data.message || '')} <br><b>${text('Нужна переменная окружения:', 'Kerakli muhit o‘zgaruvchisi:')} <code>CLOUDFLARE_RADAR_API_TOKEN</code></b>`;
    } else if (data.errors && data.errors.length) {
      status.textContent += ` ${text('Некоторые наборы недоступны:', 'Ba’zi to‘plamlar mavjud emas:')} ${data.errors.map(x => `${x.dataset}: ${x.message}`).join('; ')}`;
    }
    drawRankings('radarOrigins', data.topOrigins, 'percent');
    drawRankings('radarTargets', data.topTargets, 'percent');
    drawRankings('radarVectors', data.vectors, 'auto');
    drawRankings('radarProtocols', data.protocols, 'auto');
    drawMap(data);
  }

  async function load(force = false) {
    if (!document.getElementById('radarStatus') || loading) return;
    loading = true;
    if (!cachedRadarData) setStatus('radarStatus', text('Подключение к Cloudflare Radar API…', 'Cloudflare Radar API’ga ulanmoqda…'));
    try {
      const data = await fetchRadar(force);
      renderRadar(data);
      await loadSiteSecurity(false);
    } catch (error) {
      const missingFn = /HTTP 404/.test(error.message || '');
      const message = missingFn
        ? text('API-функция не найдена. Разверните проект через связанный Git-репозиторий или Netlify CLI, чтобы работали Netlify Functions.', 'API-funksiya topilmadi. Netlify Functions ishlashi uchun loyihani Git-repozitoriy yoki Netlify CLI orqali joylashtiring.')
        : text('Не удалось получить данные. Проверьте настройки API и соединение; реальные цифры не подставляются автоматически.', 'Ma’lumotlarni olib bo‘lmadi. API sozlamalari va ulanishni tekshiring; haqiqiy bo‘lmagan raqamlar avtomatik qo‘yilmaydi.');
      setStatus('radarStatus', message, 'error');
      drawMap(null);
    } finally {
      loading = false;
      if (!refreshTimer) refreshTimer = window.setInterval(() => {
        if (document.getElementById('radarStatus') && !document.hidden) load(false);
      }, REFRESH_MS);
    }
  }

  async function loadSiteSecurity(force = false) {
    if (!document.getElementById('siteSecurityStatus') || siteLoading) return;
    siteLoading = true;
    try {
      const data = await fetchSiteSecurity(force);
      const node = document.getElementById('siteSecurityStatus');
      if (!node) return;
      const ok = data.configured && data.status === 'ok';
      node.className = `radar-status ${ok ? 'radar-status-good' : data.configured ? 'radar-status-error' : 'radar-status-warn'}`;
      node.textContent = data.message || text('Источник не настроен.', 'Manba sozlanmagan.');
      const summary = document.getElementById('siteSecuritySummary');
      if (summary) summary.innerHTML = `<article class="radar-stat"><span>${text('События за 24 часа', '24 soatdagi hodisalar')}</span><b>${ok ? Number(data.totalEvents || 0).toLocaleString(isUz() ? 'uz-UZ' : 'ru-RU') : '—'}</b></article><article class="radar-stat"><span>${text('Групп событий', 'Hodisalar guruhlari')}</span><b>${ok ? Number((data.events || []).length).toLocaleString(isUz() ? 'uz-UZ' : 'ru-RU') : '—'}</b></article>`;
      drawRankings('siteSecurityCountries', ok ? data.byCountry : [], 'count');
      drawRankings('siteSecurityActions', ok ? data.byAction : [], 'count');
    } catch (error) {
      setStatus('siteSecurityStatus', text('Не удалось загрузить данные защиты сайта. Проверьте настройки Cloudflare и повторите попытку.', 'Sayt himoyasi ma’lumotlarini yuklab bo‘lmadi. Cloudflare sozlamalarini tekshirib, qayta urinib ko‘ring.'), 'error');
    } finally {
      siteLoading = false;
    }
  }

  window.FiribStopRadar = { load, refresh: force => load(!!force), refreshSite: force => loadSiteSecurity(!!force) };
})();
