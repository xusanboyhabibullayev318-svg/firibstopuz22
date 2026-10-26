/**
 * FiribStop Security Engine 2.7.0
 * Full offline-capable scanner for browser/PWA environment.
 * Honest about limitations: this is NOT a replacement for desktop AV.
 */
(function (global) {
  'use strict';

  const DB_KEY = 'fs_av_threat_db_v2';
  const HIST_KEY = 'fs_av_scan_history';
  const QUAR_KEY = 'fs_av_quarantine';
  const SETTINGS_KEY = 'fs_av_settings';
  const MAX_HISTORY = 80;
  const MAX_QUARANTINE = 40;
  const MAX_FILE_SCAN_BYTES = 25 * 1024 * 1024; // cap deep heuristics at 25 MiB
  const MAX_HASH_FILE_BYTES = 50 * 1024 * 1024; // avoid huge ArrayBuffers on low-memory phones
  const MAX_IMPORT_BYTES = 2 * 1024 * 1024;
  const MAX_HASH_ENTRIES = 20000;
  const MAX_DOMAIN_ENTRIES = 5000;
  const ALLOWED_SEVERITIES = new Set(['test', 'low', 'medium', 'suspicious', 'high', 'malicious', 'miner', 'leak']);

  const DEFAULT_DB = {
    schemaVersion: 2,
    name: 'FiribStop Built-in',
    updatedAt: '2026-10-24',
    hashes: {},
    domains: {},
    suspiciousTlds: ['zip', 'mov', 'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'icu', 'cyou', 'click', 'loan', 'work'],
    dangerousExtensions: {
      '.apk': { risk: 'high', note: 'Android-пакет. Устанавливайте только из Google Play или официального сайта.' },
      '.exe': { risk: 'high', note: 'Исполняемый файл Windows.' },
      '.msi': { risk: 'high', note: 'Установщик Windows.' },
      '.bat': { risk: 'high', note: 'Пакетный скрипт.' },
      '.cmd': { risk: 'high', note: 'Командный скрипт.' },
      '.js': { risk: 'medium', note: 'JavaScript — может быть вредоносным вне браузера.' },
      '.vbs': { risk: 'high', note: 'VBScript.' },
      '.ps1': { risk: 'high', note: 'PowerShell-скрипт.' },
      '.scr': { risk: 'high', note: 'Screensaver — частая маскировка malware.' },
      '.jar': { risk: 'medium', note: 'Java-архив.' },
      '.docm': { risk: 'medium', note: 'Word с макросами.' },
      '.xlsm': { risk: 'medium', note: 'Excel с макросами.' },
      '.hta': { risk: 'high', note: 'HTML Application.' },
      '.lnk': { risk: 'medium', note: 'Ярлык Windows.' }
    },
    contentPatterns: [
      { id: 'eicar', re: /X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE/, severity: 'test', label: 'EICAR test signature' },
      { id: 'base64_pe', re: /TVqQAAMAAAAEAAAA/, severity: 'suspicious', label: 'Возможный base64-encoded PE (MZ)' },
      { id: 'ps_enc', re: /powershell.*(-enc|-e\s+|FromBase64String)/i, severity: 'suspicious', label: 'PowerShell с закодированной командой' },
      { id: 'eval_js', re: /eval\s*\(|document\.write\s*\(\s*unescape/i, severity: 'suspicious', label: 'Подозрительный JS eval/unescape' },
      { id: 'miner', re: /coinhive|cryptonight|xmrig|minergate/i, severity: 'miner', label: 'Признаки криптомайнера' }
    ],
    tips: [
      'Не устанавливайте APK из мессенджеров и неизвестных сайтов.',
      'Не переходите по сокращённым ссылкам из SMS.',
      'Банки не просят коды из SMS по телефону.',
      'Обновляйте приложения только из официальных магазинов.',
      'Включите 2FA на важных аккаунтах.'
    ]
  };

  // Seed known test / educational hashes
  DEFAULT_DB.hashes['275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'] = {
    label: 'EICAR test file',
    severity: 'test',
    source: 'eicar.org'
  };

  let runtimeDB = null;
  let lastScanResult = null;

  function ld(key, fallback) {
    try {
      const v = localStorage.getItem(key);
      return v == null ? fallback : JSON.parse(v);
    } catch {
      return fallback;
    }
  }
  function sv(key, val) {
    try {
      localStorage.setItem(key, JSON.stringify(val));
    } catch (e) {
      console.warn('AV storage', e);
    }
  }

  function getSettings() {
    return Object.assign(
      { realtimeHints: true, autoAddToHistory: true, notifyOnThreat: true },
      ld(SETTINGS_KEY, {})
    );
  }

  function loadDB() {
    if (runtimeDB) return runtimeDB;
    const stored = ld(DB_KEY, null);
    runtimeDB = mergeDB(DEFAULT_DB, stored);
    return runtimeDB;
  }

  function mergeDB(base, extra) {
    const out = JSON.parse(JSON.stringify(base));
    if (!extra || typeof extra !== 'object' || Array.isArray(extra)) return out;
    const importedAt = new Date().toISOString();
    const source = cleanMeta(extra.source || extra.name || 'import');
    const updatedAt = validDate(extra.updatedAt) ? new Date(extra.updatedAt).toISOString() : importedAt;
    const defaultExpiry = validDate(extra.validUntil) ? new Date(extra.validUntil).toISOString() : null;
    const hashes = Array.isArray(extra.hashes) ? extra.hashes : (extra.hashes && typeof extra.hashes === 'object' ? Object.entries(extra.hashes).map(([sha256, value]) => ({ sha256, ...(value || {}) })) : []);
    for (const h of hashes.slice(0, MAX_HASH_ENTRIES)) {
      if (!h || !/^[a-f0-9]{64}$/i.test(String(h.sha256 || ''))) continue;
      const severity = ALLOWED_SEVERITIES.has(String(h.severity || 'malicious').toLowerCase()) ? String(h.severity || 'malicious').toLowerCase() : 'malicious';
      out.hashes[String(h.sha256).toLowerCase()] = {
        label: cleanMeta(h.label || 'Совпадение с импортированной базой', 160), severity,
        source: cleanMeta(h.source || source, 120),
        updatedAt: validDate(h.updatedAt) ? new Date(h.updatedAt).toISOString() : updatedAt,
        expiresAt: validDate(h.expiresAt) ? new Date(h.expiresAt).toISOString() : (validDate(h.validUntil) ? new Date(h.validUntil).toISOString() : defaultExpiry)
      };
    }
    const domains = Array.isArray(extra.domains) ? extra.domains : (extra.domains && typeof extra.domains === 'object' ? Object.entries(extra.domains).map(([domain, value]) => ({ domain, ...(value || {}) })) : []);
    for (const d of domains.slice(0, MAX_DOMAIN_ENTRIES)) {
      if (!d || typeof d.domain !== 'string') continue;
      const domain = d.domain.toLowerCase().trim().replace(/^https?:\/\//, '').split(/[/:?#]/)[0];
      if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(domain)) continue;
      out.domains[domain] = { severity: d.severity === 'shortener' ? 'shortener' : (ALLOWED_SEVERITIES.has(String(d.severity || 'high').toLowerCase()) ? String(d.severity || 'high').toLowerCase() : 'high'), note: cleanMeta(d.note || 'Домен из импортированной базы', 240), source: cleanMeta(d.source || source, 120), updatedAt: validDate(d.updatedAt) ? new Date(d.updatedAt).toISOString() : updatedAt, expiresAt: validDate(d.expiresAt) ? new Date(d.expiresAt).toISOString() : (validDate(d.validUntil) ? new Date(d.validUntil).toISOString() : defaultExpiry) };
    }
    if (Array.isArray(extra.suspiciousTlds)) {
      const tlds = extra.suspiciousTlds.map(x => String(x).toLowerCase().replace(/^\./, '')).filter(x => /^[a-z0-9-]{2,24}$/.test(x)).slice(0, 100);
      out.suspiciousTlds = [...new Set([...out.suspiciousTlds, ...tlds])];
    }
    if (extra.updatedAt && validDate(extra.updatedAt)) out.updatedAt = new Date(extra.updatedAt).toISOString();
    if (extra.name) out.name = cleanMeta(extra.name, 100);
    out.importedAt = extra.importedAt || importedAt;
    out.source = source;
    out.validUntil = validDate(extra.validUntil) ? new Date(extra.validUntil).toISOString() : null;
    return out;
  }

  function cleanMeta(value, max = 160) {
    return String(value == null ? '' : value).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);
  }
  function validDate(value) {
    return typeof value === 'string' && value.length <= 40 && !Number.isNaN(Date.parse(value));
  }
  function assertThreatDB(data) {
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Корень базы должен быть JSON-объектом');
    if (data.schemaVersion != null && ![1, 2, 3].includes(Number(data.schemaVersion))) throw new Error('Неподдерживаемая версия схемы базы');
    if (data.updatedAt != null && !validDate(data.updatedAt)) throw new Error('Поле updatedAt должно содержать дату');
    if (data.validUntil != null && !validDate(data.validUntil)) throw new Error('Поле validUntil должно содержать дату');
    const hashes = Array.isArray(data.hashes) ? data.hashes : (data.hashes && typeof data.hashes === 'object' ? Object.entries(data.hashes).map(([sha256, v]) => ({sha256, ...(v || {})})) : []);
    if (hashes.length > MAX_HASH_ENTRIES) throw new Error(`Слишком много хешей: максимум ${MAX_HASH_ENTRIES}`);
    for (const h of hashes) {
      if (!h || !/^[a-f0-9]{64}$/i.test(String(h.sha256 || ''))) throw new Error('Каждый SHA-256 должен содержать ровно 64 шестнадцатеричных символа');
      if (h.severity != null && !ALLOWED_SEVERITIES.has(String(h.severity).toLowerCase())) throw new Error('Недопустимое значение severity в хеше');
      if (h.expiresAt != null && !validDate(h.expiresAt)) throw new Error('Некорректная expiresAt у хеша');
    }
    const domains = Array.isArray(data.domains) ? data.domains : (data.domains && typeof data.domains === 'object' ? Object.entries(data.domains).map(([domain, v]) => ({domain, ...(v || {})})) : []);
    if (domains.length > MAX_DOMAIN_ENTRIES) throw new Error(`Слишком много доменов: максимум ${MAX_DOMAIN_ENTRIES}`);
    for (const d of domains) {
      if (!d || typeof d.domain !== 'string' || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(d.domain.trim())) throw new Error('Некорректное доменное имя в базе');
      if (d.expiresAt != null && !validDate(d.expiresAt)) throw new Error('Некорректная expiresAt у домена');
    }
    if (data.suspiciousTlds != null && (!Array.isArray(data.suspiciousTlds) || data.suspiciousTlds.length > 100)) throw new Error('suspiciousTlds должен быть массивом до 100 элементов');
    return { hashes, domains };
  }

  async function importThreatJSON(json) {
    if (typeof json === 'string' && json.length > MAX_IMPORT_BYTES) throw new Error('Файл базы больше 2 МиБ — импорт отклонён');
    let data;
    try { data = typeof json === 'string' ? JSON.parse(json) : json; }
    catch { throw new Error('Файл не содержит корректный JSON'); }
    const checked = assertThreatDB(data);
    const merged = mergeDB(loadDB(), data);
    merged.importedAt = new Date().toISOString();
    runtimeDB = merged;
    const toStore = {
      schemaVersion: 3, name: cleanMeta(data.name || 'Imported', 100), source: cleanMeta(data.source || 'user', 120),
      updatedAt: validDate(data.updatedAt) ? new Date(data.updatedAt).toISOString() : new Date().toISOString(),
      validUntil: validDate(data.validUntil) ? new Date(data.validUntil).toISOString() : null,
      importedAt: merged.importedAt, hashes: checked.hashes, domains: checked.domains,
      suspiciousTlds: Array.isArray(data.suspiciousTlds) ? data.suspiciousTlds.map(x => String(x).toLowerCase().replace(/^\./, '')).filter(x => /^[a-z0-9-]{2,24}$/.test(x)).slice(0, 100) : []
    };
    sv(DB_KEY, toStore);
    return { ok: true, entries: checked.hashes.length + checked.domains.length, hashes: checked.hashes.length, domains: checked.domains.length, source: toStore.source, updatedAt: toStore.updatedAt, validUntil: toStore.validUntil, importedAt: merged.importedAt };
  }

  async function tryLoadBundledDB() {
    try {
      const r = await fetch('./data/threats.json', { cache: 'no-cache' });
      if (!r.ok) return false;
      const data = await r.json();
      await importThreatJSON(data);
      return true;
    } catch {
      return false;
    }
  }

  function dbStats() {
    const db = loadDB();
    return {
      hashCount: Object.keys(db.hashes).length,
      domainCount: Object.keys(db.domains).length,
      tldCount: (db.suspiciousTlds || []).length,
      patternCount: (db.contentPatterns || []).length,
      updatedAt: db.updatedAt,
      importedAt: db.importedAt || null,
      name: db.name, source: db.source || 'built-in', validUntil: db.validUntil || null, stale: !!(db.validUntil && Date.parse(db.validUntil) < Date.now())
    };
  }

  async function sha256Buffer(buffer) {
    const hash = await crypto.subtle.digest('SHA-256', buffer);
    return Array.from(new Uint8Array(hash))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  async function sha256File(file) {
    if (file.size > MAX_HASH_FILE_BYTES) throw new Error(`Файл больше лимита хеширования ${Math.round(MAX_HASH_FILE_BYTES / 1024 / 1024)} МиБ`);
    return sha256Buffer(await file.arrayBuffer());
  }

  function addFinding(findings, type, severity, title, detail) {
    if (!findings.some(f => f.type === type && f.title === title)) findings.push({ type, severity, title, detail });
  }

  function inspectFileSignature(bytes, ext, findings) {
    if (bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a) addFinding(findings, 'signature', ['.exe','.dll','.scr','.sys'].includes(ext) ? 'medium' : 'suspicious', 'Обнаружена сигнатура Windows PE (MZ)', ext === '.exe' || ext === '.dll' ? 'Файл начинается с сигнатуры исполняемого PE-файла. Это определение формата, не доказательство вредоносности.' : 'Содержимое похоже на исполняемый файл Windows, хотя расширение отличается.');
    if (bytes.length >= 4 && bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) addFinding(findings, 'signature', 'medium', 'Обнаружена сигнатура ELF', 'Файл похож на исполняемый ELF для Linux/Unix. Проверьте, соответствует ли содержимое расширению.');
    if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && [3,5,7].includes(bytes[2]) && [4,6,8].includes(bytes[3])) return 'zip';
    if (bytes.length >= 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46 && ext !== '.pdf') addFinding(findings, 'signature', 'medium', 'Содержимое PDF при другом расширении', 'Расширение не совпадает с сигнатурой PDF. Не открывайте файл до проверки происхождения.');
    return '';
  }

  async function inflateRawBounded(bytes, maxOutputBytes) {
    if (typeof DecompressionStream !== 'function') return null;
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
    const reader = stream.getReader(); const chunks = []; let total = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maxOutputBytes) { await reader.cancel().catch(() => {}); return null; }
        chunks.push(value);
      }
    } finally { try { reader.releaseLock(); } catch {} }
    const output = new Uint8Array(total); let offset = 0;
    for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.byteLength; }
    return output;
  }


  // ---------- APK manifest analysis (permissions) ----------
  const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;
  function readAxmlStringPool(dv, bytes, pos, size) {
    const out = [];
    if (pos + 28 > bytes.length) return out;
    const count = dv.getUint32(pos + 8, true);
    const flags = dv.getUint32(pos + 16, true);
    const stringsStart = dv.getUint32(pos + 20, true);
    if (count > 20000) return out;
    const utf8 = (flags & 0x100) !== 0;
    const end = pos + size;
    const offsetsAt = pos + dv.getUint16(pos + 2, true);
    for (let i = 0; i < count; i++) {
      if (offsetsAt + i * 4 + 4 > end) { out.push(''); continue; }
      let p = pos + stringsStart + dv.getUint32(offsetsAt + i * 4, true);
      if (p < pos || p + 2 > end) { out.push(''); continue; }
      try {
        if (utf8) {
          let chars = bytes[p++]; if (chars & 0x80) { chars = ((chars & 0x7f) << 8) | bytes[p++]; }
          let len = bytes[p++]; if (len & 0x80) { len = ((len & 0x7f) << 8) | bytes[p++]; }
          if (p + len > end || len > 4096) { out.push(''); continue; }
          out.push(new TextDecoder('utf-8').decode(bytes.subarray(p, p + len)));
        } else {
          let len = dv.getUint16(p, true); p += 2;
          if (len & 0x8000) { len = ((len & 0x7fff) << 16) | dv.getUint16(p, true); p += 2; }
          if (p + len * 2 > end || len > 4096) { out.push(''); continue; }
          out.push(new TextDecoder('utf-16le').decode(bytes.subarray(p, p + len * 2)));
        }
      } catch (_) { out.push(''); }
    }
    return out;
  }

  // Minimal reader for Android binary XML. Reads only what is needed; never executes anything.
  function parseBinaryManifest(bytes) {
    if (!bytes || bytes.length < 16) return null;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (dv.getUint16(0, true) !== 0x0003) return null;
    const total = Math.min(dv.getUint32(4, true) || bytes.length, bytes.length);
    const info = { package: '', permissions: [], componentPermissions: [], debuggable: false };
    let strings = [], pos = dv.getUint16(2, true) || 8, guard = 0;
    while (pos + 8 <= total && guard++ < 100000) {
      const type = dv.getUint16(pos, true), size = dv.getUint32(pos + 4, true);
      if (size < 8 || pos + size > total) break;
      if (type === 0x0001) {
        strings = readAxmlStringPool(dv, bytes, pos, size);
      } else if (type === 0x0102 && pos + 36 <= total) {
        const element = strings[dv.getUint32(pos + 20, true)] || '';
        const attrStart = dv.getUint16(pos + 24, true), attrSize = dv.getUint16(pos + 26, true) || 20, attrCount = Math.min(dv.getUint16(pos + 28, true), 200);
        const attrs = {};
        for (let i = 0; i < attrCount; i++) {
          const a = pos + 16 + attrStart + i * attrSize;
          if (a + 20 > pos + size) break;
          const key = strings[dv.getUint32(a + 4, true)];
          if (!key) continue;
          const raw = dv.getUint32(a + 8, true), dataType = bytes[a + 15], data = dv.getUint32(a + 16, true);
          attrs[key] = raw !== 0xffffffff ? strings[raw] : (dataType === 0x03 ? strings[data] : (dataType === 0x12 ? data !== 0 : data));
        }
        if (element === 'manifest' && typeof attrs.package === 'string') info.package = attrs.package.slice(0, 200);
        else if ((element === 'uses-permission' || element === 'uses-permission-sdk-23') && typeof attrs.name === 'string') info.permissions.push(attrs.name.slice(0, 200));
        else if (element === 'application' && attrs.debuggable === true) info.debuggable = true;
        else if (['service', 'receiver', 'activity'].includes(element) && typeof attrs.permission === 'string') info.componentPermissions.push(attrs.permission.slice(0, 200));
        if (info.permissions.length > 500) break;
      }
      pos += size;
    }
    return info;
  }

  const BRAND_TOKENS = ['payme', 'click', 'uzum', 'paynet', 'humo', 'uzcard', 'kapitalbank', 'ipoteka', 'xalqbank', 'nbu', 'asaka', 'hamkor', 'davr', 'agrobank', 'anorbank', 'tbcbank', 'my.uzcard', 'milliy'];

  function analyzeApkManifest(info, findings) {
    if (!info) return;
    const short = (n) => String(n).replace(/^android\.permission\./, '');
    const perms = new Set(info.permissions.map(short));
    const comp = new Set(info.componentPermissions.map(short));
    const has = (...names) => names.some(n => perms.has(n));
    const smsRead = has('READ_SMS', 'RECEIVE_SMS', 'RECEIVE_MMS', 'RECEIVE_WAP_PUSH');
    const smsSend = has('SEND_SMS', 'WRITE_SMS');
    const net = has('INTERNET');
    const accessibility = comp.has('BIND_ACCESSIBILITY_SERVICE');
    const overlay = has('SYSTEM_ALERT_WINDOW');
    const admin = comp.has('BIND_DEVICE_ADMIN');
    const install = has('REQUEST_INSTALL_PACKAGES', 'INSTALL_PACKAGES');
    const calls = has('READ_CALL_LOG', 'WRITE_CALL_LOG', 'PROCESS_OUTGOING_CALLS', 'ANSWER_PHONE_CALLS', 'CALL_PHONE');
    const listener = comp.has('BIND_NOTIFICATION_LISTENER_SERVICE');
    const hits = [];
    if (smsRead && (smsSend || net)) { addFinding(findings, 'apk-permissions', 'high', 'Приложение может читать SMS и передавать их', 'Права на чтение SMS вместе с отправкой SMS или доступом в интернет — типичный набор банковских троянов: они перехватывают коды подтверждения. Если это не приложение для SMS, не устанавливайте его.'); hits.push('sms'); }
    else if (smsRead || smsSend) { addFinding(findings, 'apk-permissions', 'medium', 'Приложение запрашивает доступ к SMS', 'Обычным приложениям доступ к SMS не нужен. Убедитесь, что это почтовое/SMS-приложение из официального магазина.'); hits.push('sms'); }
    if (accessibility) { addFinding(findings, 'apk-permissions', 'high', 'Использует службу специальных возможностей', 'Это одна из главных лазеек Android-вредоносов: приложение может видеть экран и нажимать кнопки за вас' + (overlay ? ', а вместе с показом поверх других окон — подменять банковские формы.' : '.')); hits.push('a11y'); }
    if (overlay && !accessibility) { addFinding(findings, 'apk-permissions', 'medium', 'Может показывать окна поверх других приложений', 'Мошенники используют это для поддельных окон ввода пароля или карты поверх настоящих банковских приложений.'); hits.push('overlay'); }
    if (admin) { addFinding(findings, 'apk-permissions', 'high', 'Запрашивает права администратора устройства', 'Вредоносные приложения используют это, чтобы мешать удалению. Настоящим приложениям это нужно редко (корпоративные, защитные).'); hits.push('admin'); }
    if (install) { addFinding(findings, 'apk-permissions', 'medium', 'Может устанавливать другие приложения', 'Права на установку пакетов используют «дропперы», которые скачивают и ставят вредоносные программы после первого запуска.'); hits.push('install'); }
    if (listener) { addFinding(findings, 'apk-permissions', 'medium', 'Читает уведомления', 'Через уведомления можно перехватывать коды из банковских приложений и мессенджеров.'); hits.push('notify'); }
    if (calls) { addFinding(findings, 'apk-permissions', 'low', 'Запрашивает доступ к звонкам', 'Нужен звонилкам. В остальных приложениях это повод насторожиться.'); }
    if (perms.size >= 20) addFinding(findings, 'apk-permissions', 'low', `Очень много запрошенных прав (${perms.size})`, 'Чем больше прав, тем больше возможностей у приложения. Проверьте, нужны ли они его назначению.');
    if (info.debuggable) addFinding(findings, 'apk-permissions', 'low', 'Приложение собрано в режиме отладки', 'Для приложений из магазина это нехарактерно.');
    const pkg = (info.package || '').toLowerCase();
    if (pkg) {
      const brand = BRAND_TOKENS.find(b => pkg.includes(b));
      if (brand) addFinding(findings, 'apk-package', hits.length ? 'medium' : 'low', `Имя пакета содержит «${brand}»: проверьте источник`, `Пакет «${cleanMeta(info.package, 80)}». Поддельные приложения банков и платёжных сервисов часто используют такие названия. Скачивайте только из Google Play или с официального сайта.`);
    }
  }

  async function readZipEntryBytes(file, entry, maxBytes) {
    if (![0, 8].includes(entry.method) || entry.uncompressed > maxBytes || entry.compressed > maxBytes) return null;
    const header = await file.slice(entry.localOffset, entry.localOffset + 30).arrayBuffer();
    if (header.byteLength !== 30) return null;
    const lv = new DataView(header);
    if (lv.getUint32(0, true) !== 0x04034b50) return null;
    const start = entry.localOffset + 30 + lv.getUint16(26, true) + lv.getUint16(28, true);
    const packed = new Uint8Array(await file.slice(start, start + entry.compressed).arrayBuffer());
    return entry.method === 0 ? packed : inflateRawBounded(packed, maxBytes);
  }

  async function inspectZip(file, ext, findings, db) {
    const tailLen = Math.min(file.size, 65557);
    const tailStart = file.size - tailLen;
    const tail = new Uint8Array(await file.slice(tailStart).arrayBuffer());
    const view = new DataView(tail.buffer, tail.byteOffset, tail.byteLength);
    let eocd = -1;
    for (let i = tail.length - 22; i >= Math.max(0, tail.length - 65557); i--) {
      if (view.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) {
      addFinding(findings, 'archive', ext === '.apk' ? 'high' : 'medium', 'ZIP-структура не подтверждена', 'Сигнатура похожа на ZIP, но конец центрального каталога не найден. Архив может быть повреждён или использует ZIP64.');
      return;
    }
    const entries = view.getUint16(eocd + 10, true);
    const centralSize = view.getUint32(eocd + 12, true);
    const centralOffset = view.getUint32(eocd + 16, true);
    if (entries > 5000 || centralSize > 2 * 1024 * 1024 || centralOffset + centralSize > file.size) {
      addFinding(findings, 'archive-limit', 'medium', 'Архив слишком сложный для разбора в браузере', 'Ограничение: до 5000 записей и 2 МиБ центрального каталога. Извлечение и запуск файлов не выполняются.');
      return;
    }
    const central = new Uint8Array(await file.slice(centralOffset, centralOffset + centralSize).arrayBuffer());
    const cv = new DataView(central.buffer, central.byteOffset, central.byteLength);
    const names = [], entriesInfo = []; let offset = 0, totalUncompressed = 0, totalCompressed = 0;
    for (let n = 0; n < entries && offset + 46 <= central.length; n++) {
      if (cv.getUint32(offset, true) !== 0x02014b50) break;
      const method = cv.getUint16(offset + 10, true);
      const compressed = cv.getUint32(offset + 20, true), uncompressed = cv.getUint32(offset + 24, true);
      const localOffset = cv.getUint32(offset + 42, true);
      const nameLen = cv.getUint16(offset + 28, true), extraLen = cv.getUint16(offset + 30, true), commentLen = cv.getUint16(offset + 32, true);
      if (offset + 46 + nameLen + extraLen + commentLen > central.length) break;
      const name = new TextDecoder().decode(central.slice(offset + 46, offset + 46 + nameLen)).replace(/\\/g, '/');
      names.push(name); entriesInfo.push({ name, method, compressed, uncompressed, localOffset }); totalUncompressed += uncompressed; totalCompressed += compressed; offset += 46 + nameLen + extraLen + commentLen;
    }
    if (!names.length && entries) addFinding(findings, 'archive', 'medium', 'Не удалось прочитать список файлов архива', 'Центральный каталог повреждён или имеет нестандартный формат.');
    if (names.some(n => n.startsWith('/') || /(^|\/)\.\.(\/|$)/.test(n))) addFinding(findings, 'archive-path', 'high', 'Подозрительные пути внутри архива', 'Есть записи с абсолютными путями или сегментами ../. Риск возникает при распаковке небезопасным архиватором.');
    const executables = names.filter(n => /\.(exe|dll|scr|bat|cmd|ps1|vbs|js|hta|lnk|msi)$/i.test(n));
    if (executables.length) addFinding(findings, 'archive-executable', 'medium', 'В архиве есть исполняемые или скриптовые файлы', `${executables.slice(0, 5).join(', ')}${executables.length > 5 ? ` и ещё ${executables.length - 5}` : ''}. Это повод проверить источник архива, но не доказательство заражения.`);
    if (names.some(n => /(^|\/)vbaProject\.bin$/i.test(n))) addFinding(findings, 'archive-macro', 'high', 'В архиве обнаружен компонент VBA-макросов', 'Макросы Office могут выполнять действия при открытии документа. Открывайте только доверенные документы и не включайте макросы без необходимости.');

    // Inspect a small number of embedded text/script entries, never extract to disk or execute.
    const textFileExt = /\.(txt|log|csv|json|xml|html?|js|mjs|cjs|ps1|bat|cmd|vbs|hta|svg|sh|py|php|md|ya?ml|ini|conf)$/i;
    let inspectedTextEntries = 0;
    for (const entry of entriesInfo) {
      if (inspectedTextEntries >= 12) break;
      if (!textFileExt.test(entry.name) || entry.compressed > 256 * 1024 || entry.uncompressed > 512 * 1024) continue;
      if (![0, 8].includes(entry.method)) continue;
      try {
        const localHeaderBuffer = await file.slice(entry.localOffset, entry.localOffset + 30).arrayBuffer();
        if (localHeaderBuffer.byteLength !== 30) continue;
        const lv = new DataView(localHeaderBuffer);
        if (lv.getUint32(0, true) !== 0x04034b50) continue;
        const dataStart = entry.localOffset + 30 + lv.getUint16(26, true) + lv.getUint16(28, true);
        const packed = new Uint8Array(await file.slice(dataStart, dataStart + entry.compressed).arrayBuffer());
        let embedded = null;
        if (entry.method === 0) embedded = packed.length <= 512 * 1024 ? packed : null;
        else embedded = await inflateRawBounded(packed, 512 * 1024);
        if (!embedded) continue;
        const decoded = new TextDecoder('utf-8', { fatal: false }).decode(embedded);
        if (decoded.includes('\u0000')) continue;
        inspectedTextEntries++;
        for (const pattern of (db && db.contentPatterns) || []) {
          try {
            if (pattern.re && pattern.re.test(decoded)) addFinding(findings, 'archive-content', pattern.severity || 'suspicious', `В архиве: ${pattern.label || pattern.id || 'подозрительный шаблон'}`, `Шаблон найден внутри ${entry.name}. Содержимое не запускалось и не сохранялось на диск.`);
          } catch (_) {}
        }
        if (/powershell.{0,120}-(?:enc|encodedcommand)\b|FromBase64String\s*\(/i.test(decoded)) addFinding(findings, 'archive-content', 'suspicious', 'Подозрительная команда внутри архива', `В файле ${entry.name} найдены признаки закодированной команды PowerShell. Это эвристика, не доказательство заражения.`);
      } catch (_) { /* Unsupported compressor or malformed entry: continue with bounded metadata scan. */ }
    }
    const ratio = totalCompressed > 0 ? totalUncompressed / totalCompressed : (totalUncompressed > 0 ? Infinity : 1);
    if (totalUncompressed > 100 * 1024 * 1024 || ratio > 200) addFinding(findings, 'archive-ratio', 'high', 'Подозрительно высокая степень сжатия', `Размер после распаковки по каталогу около ${(totalUncompressed / 1048576).toFixed(1)} МиБ; коэффициент ${Number.isFinite(ratio) ? ratio.toFixed(1) : '∞'}. Возможен архив-бомба; не распаковывайте автоматически.`);
    if (ext === '.apk') {
      const hasManifest = names.some(n => n === 'AndroidManifest.xml');
      const hasDex = names.some(n => /^classes(?:\d+)?\.dex$/i.test(n));
      if (!hasManifest) addFinding(findings, 'apk-structure', 'high', 'В APK не найден AndroidManifest.xml', 'Для обычного Android APK ожидается AndroidManifest.xml. Файл может быть неполным или иметь неверное расширение.');
      if (!hasDex && !names.some(n => /^lib\//.test(n))) addFinding(findings, 'apk-structure', 'medium', 'В APK не найдены типичные исполняемые компоненты', 'Не найден classes.dex или папка lib/. Это эвристика: некоторые типы пакетов устроены иначе.');
      const manifestEntry = entriesInfo.find(e => e.name === 'AndroidManifest.xml');
      if (manifestEntry) {
        try {
          const manifestBytes = await readZipEntryBytes(file, manifestEntry, MAX_MANIFEST_BYTES);
          if (manifestBytes) analyzeApkManifest(parseBinaryManifest(manifestBytes), findings);
          else addFinding(findings, 'apk-manifest', 'low', 'Не удалось прочитать AndroidManifest.xml', 'Права приложения не проверены: манифест сжат неподдерживаемым способом или слишком большой.');
        } catch (_) {
          addFinding(findings, 'apk-manifest', 'low', 'Не удалось разобрать AndroidManifest.xml', 'Права приложения не проверены. Это может быть признаком нестандартной или защищённой сборки.');
        }
      }
    }
  }

  function extOf(name) {
    const i = String(name || '').lastIndexOf('.');
    return i >= 0 ? String(name).slice(i).toLowerCase() : '';
  }

  function riskLevelFromFindings(findings) {
    if (!findings.length) return 'clean';
    const order = { clean: 0, test: 1, low: 2, medium: 3, suspicious: 3, high: 4, malicious: 5, miner: 4 };
    let max = 0;
    let level = 'clean';
    for (const f of findings) {
      const s = f.severity || 'medium';
      const v = order[s] ?? 2;
      if (v > max) {
        max = v;
        level = s === 'test' ? 'test' : s === 'malicious' ? 'high' : s === 'miner' ? 'high' : s;
      }
    }
    if (level === 'malicious') level = 'high';
    return level;
  }

  function levelLabel(level) {
    return (
      {
        clean: 'Чисто',
        test: 'Тестовая угроза',
        low: 'Низкий риск',
        medium: 'Средний риск',
        suspicious: 'Подозрительно',
        high: 'Высокий риск',
        malicious: 'Угроза'
      }[level] || level
    );
  }

  function levelColor(level) {
    return (
      {
        clean: 'var(--lo)',
        test: '#7c3aed',
        low: 'var(--me)',
        medium: 'var(--me)',
        suspicious: 'var(--me)',
        high: 'var(--hi)',
        malicious: 'var(--hi)'
      }[level] || 'var(--mu)'
    );
  }

  async function scanFile(file, opts = {}) {
    if (!file || typeof file.size !== 'number' || typeof file.slice !== 'function') throw new Error('Не удалось прочитать файл. Выберите файл ещё раз.');
    const db = loadDB(), findings = [];
    const name = cleanMeta(file.name || 'file', 240) || 'file';
    const size = Math.max(0, Number(file.size) || 0), ext = extOf(name);
    if (size === 0) addFinding(findings, 'empty', 'low', 'Пустой файл', 'В файле нет данных. Это не признак вредоносности, но проверить его содержимое невозможно.');
    const extInfo = db.dangerousExtensions[ext];
    if (extInfo) addFinding(findings, 'extension', extInfo.risk || 'medium', `Проверить файл типа ${ext}`, extInfo.note || 'Тип файла может выполнять код или содержать активное содержимое. Само расширение не доказывает заражение.');
    const hashLimitExceeded = size > MAX_HASH_FILE_BYTES;
    let hash = '';
    if (!hashLimitExceeded) {
      try {
        hash = await sha256File(file);
        const known = db.hashes[hash];
        const expired = known && validDate(known.expiresAt) && Date.parse(known.expiresAt) < Date.now();
        if (known && !expired) {
          const testSignature = known.severity === 'test';
          addFinding(findings, 'hash', known.severity || 'malicious', testSignature ? (known.label || 'Учебная тестовая сигнатура') : (known.label || 'Совпадение с базой угроз'), `SHA-256 совпал с записью базы. Источник: ${known.source || 'локальная база'}. ${known.updatedAt ? `Дата записи: ${known.updatedAt.slice(0,10)}.` : ''}${known.expiresAt ? ` Действует до: ${known.expiresAt.slice(0,10)}.` : ''}`);
        } else if (known && expired) {
          addFinding(findings, 'stale-hash', 'low', 'Найдено устаревшее совпадение', `Запись из источника «${known.source || 'неизвестен'}» истекла ${known.expiresAt.slice(0,10)} и не используется как подтверждение угрозы.`);
        }
      } catch (e) {
        addFinding(findings, 'hash-error', 'low', 'Не удалось вычислить SHA-256', cleanMeta(e.message || 'Ошибка чтения файла', 240));
      }
    } else {
      addFinding(findings, 'hash-limit', 'low', 'Хеширование пропущено: файл слишком большой', `Размер ${(size / 1048576).toFixed(1)} МиБ превышает безопасный лимит браузерного хеширования ${Math.round(MAX_HASH_FILE_BYTES / 1048576)} МиБ. Файл не загружается на сервер и не читается целиком в память.`);
    }

    // Read only a bounded sample; skip text heuristics for likely binary samples.
    if (size > 0 && size <= MAX_FILE_SCAN_BYTES) {
      try {
        const sample = new Uint8Array(await file.slice(0, Math.min(size, 1024 * 1024)).arrayBuffer());
        const signatureType = inspectFileSignature(sample, ext, findings);
        const isLikelyZip = signatureType === 'zip' || ext === '.zip' || ext === '.apk' || ext === '.jar' || ext === '.docx' || ext === '.xlsx' || ext === '.pptx' || ext === '.docm' || ext === '.xlsm' || ext === '.pptm' || ext === '.odt' || ext === '.ods' || ext === '.odp';
        if (isLikelyZip) await inspectZip(file, ext, findings, db);
        const binaryPrefix = sample.slice(0, Math.min(sample.length, 8192));
        const hasNull = binaryPrefix.some(b => b === 0);
        const textExts = new Set(['.txt','.log','.csv','.json','.xml','.html','.htm','.js','.mjs','.cjs','.ps1','.bat','.cmd','.vbs','.hta','.svg','.sh','.py','.php','.md','.yml','.yaml','.ini','.conf']);
        if (!hasNull && (textExts.has(ext) || !ext || ext === '.txt')) {
          const textSample = new TextDecoder('utf-8', { fatal: false }).decode(sample);
          for (const p of db.contentPatterns || []) {
            try {
              if (p.re && p.re.test(textSample)) addFinding(findings, 'content', p.severity || 'suspicious', p.label || p.id || 'Подозрительный шаблон', 'Обнаружен известный тестовый маркер или подозрительный шаблон в первых 1 МиБ содержимого. Это эвристика, её нужно оценивать вместе с контекстом.');
            } catch (_) {}
          }
          if (/#include\s*<windows\.h>|WinExec\s*\(|CreateRemoteThread\s*\(/i.test(textSample)) addFinding(findings, 'native-code', 'medium', 'Признаки вызовов системных функций', 'Найдено упоминание функций, которые встречаются в нативных программах. Это не самостоятельный индикатор вредоносности.');
        }
      } catch (e) {
        addFinding(findings, 'read-error', 'low', 'Часть содержимого не удалось проверить', cleanMeta(e.message || 'Ошибка чтения фрагмента файла', 200));
      }
    } else if (size > MAX_FILE_SCAN_BYTES) {
      addFinding(findings, 'content-limit', 'low', 'Глубокий анализ ограничен размером', `Проверены расширение и SHA-256 (если размер не превышает ${Math.round(MAX_HASH_FILE_BYTES / 1048576)} МиБ). Глубокая эвристика и разбор архивов ограничены файлами до ${Math.round(MAX_FILE_SCAN_BYTES / 1048576)} МиБ.`);
    }

    const knownThreat = findings.some(f => f.type === 'hash' && !['test'].includes(f.severity));
    const matchedTest = findings.some(f => f.type === 'hash' && f.severity === 'test') || findings.some(f => f.severity === 'test');
    const suspicious = findings.some(f => ['extension','content','signature','archive-path','archive-executable','archive-macro','archive-ratio','apk-structure','apk-permissions','apk-package','native-code'].includes(f.type) || ['suspicious','high','malicious','miner'].includes(f.severity));
    const verdict = knownThreat ? 'known-threat' : suspicious ? 'suspicious' : (matchedTest ? 'test-signature' : 'unknown');
    const verdictLabel = ({'known-threat':'Совпадение с базой угроз','suspicious':'Обнаружены подозрительные признаки','test-signature':'Учебная тестовая сигнатура','unknown':'Неизвестный файл'})[verdict];
    const level = knownThreat ? 'high' : matchedTest ? 'test' : riskLevelFromFindings(findings);
    const result = {
      id: Date.now(), kind: 'file', name, size,
      sizeLabel: size > 1048576 ? (size / 1048576).toFixed(2) + ' МиБ' : (size / 1024).toFixed(1) + ' КиБ',
      ext, sha256: hash, level, levelLabel: levelLabel(level), verdict, verdictLabel,
      findings, scannedAt: new Date().toISOString(),
      database: { name: db.name || 'Локальная база', source: db.source || 'bundled', updatedAt: db.updatedAt || null, validUntil: db.validUntil || null },
      scope: verdict === 'unknown' ? 'Неизвестный файл: совпадений и достаточных подозрительных признаков не найдено. Это НЕ подтверждает безопасность файла. Анализ локальный, без исполнения файла.' : 'Браузерный анализатор: SHA-256, ограниченный анализ содержимого, сигнатуры форматов и структура ZIP. Не запускает файл, не распаковывает вложения на диск и не заменяет системный антивирус.'
    };
    lastScanResult = result;
    if (getSettings().autoAddToHistory) pushHistory(result);
    return result;
  }

  function scanUrl(rawUrl) {
    const db = loadDB();
    const findings = [];
    let url;
    try {
      const s = String(rawUrl || '').trim();
      url = new URL(s.includes('://') ? s : 'https://' + s);
    } catch {
      return {
        id: Date.now(),
        kind: 'url',
        name: String(rawUrl || ''),
        level: 'medium',
        levelLabel: levelLabel('medium'),
        findings: [{ type: 'parse', severity: 'medium', title: 'Некорректный URL', detail: 'Не удалось разобрать адрес.' }],
        scannedAt: new Date().toISOString(),
        scope: 'Проверка URL по локальным правилам.'
      };
    }

    const host = url.hostname.toLowerCase();
    const parts = host.split('.');
    const tld = parts[parts.length - 1];

    if (db.domains[host] && !(validDate(db.domains[host].expiresAt) && Date.parse(db.domains[host].expiresAt) < Date.now())) {
      const d = db.domains[host];
      findings.push({
        type: 'domain',
        severity: d.severity === 'shortener' ? 'medium' : d.severity || 'high',
        title: d.severity === 'shortener' ? 'Сокращатель ссылок' : 'Домен из базы риска',
        detail: d.note || 'Домен отмечен в локальной базе.'
      });
    }

    if ((db.suspiciousTlds || []).includes(tld)) {
      findings.push({
        type: 'tld',
        severity: 'medium',
        title: `Подозрительная зона .${tld}`,
        detail: 'Эта TLD часто используется в фишинговых кампаниях.'
      });
    }

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      findings.push({
        type: 'ip',
        severity: 'high',
        title: 'IP-адрес вместо домена',
        detail: 'Легитимные сервисы редко ведут на «голый» IP.'
      });
    }

    if (host.includes('xn--')) {
      findings.push({
        type: 'punycode',
        severity: 'high',
        title: 'Punycode (возможный IDN-спуфинг)',
        detail: 'Домен использует кодировку xn-- — проверьте визуально, нет ли подмены символов.'
      });
    }

    if ((host.match(/-/g) || []).length >= 3) {
      findings.push({
        type: 'hyphens',
        severity: 'low',
        title: 'Много дефисов в домене',
        detail: 'Частый признак фишинговых доменов-имитаций.'
      });
    }

    if (url.protocol === 'http:') {
      findings.push({
        type: 'http',
        severity: 'low',
        title: 'Незащищённый HTTP',
        detail: 'Нет шифрования TLS. Не вводите пароли и данные карт.'
      });
    }

    // Use global analyzer if available for deeper URL checks
    if (typeof global.analyze === 'function') {
      try {
        const a = global.analyze(url.href);
        if (a && a.score >= 40) {
          findings.push({
            type: 'heuristic',
            severity: a.score >= 70 ? 'high' : 'medium',
            title: 'Эвристика FiribStop: повышенный риск',
            detail: `Оценка анализатора сообщений/ссылок: ${a.score}. Уровень: ${a.level}.`
          });
        }
      } catch (_) {}
    }

    const level = riskLevelFromFindings(findings);
    const result = {
      id: Date.now(),
      kind: 'url',
      name: url.href,
      host,
      level,
      levelLabel: levelLabel(level),
      findings,
      scannedAt: new Date().toISOString(),
      scope: 'Локальные правила + база доменов. Нет облачного репутационного сервиса в реальном времени.'
    };
    lastScanResult = result;
    if (getSettings().autoAddToHistory) pushHistory(result);
    return result;
  }

  function pushHistory(result) {
    const hist = ld(HIST_KEY, []);
    hist.unshift({
      id: result.id,
      kind: result.kind,
      name: result.name,
      level: result.level,
      sha256: result.sha256 || null,
      findingsCount: (result.findings || []).length,
      scannedAt: result.scannedAt
    });
    sv(HIST_KEY, hist.slice(0, MAX_HISTORY));
  }

  function getHistory() {
    return ld(HIST_KEY, []);
  }

  function clearHistory() {
    sv(HIST_KEY, []);
  }

  function addToQuarantine(result) {
    if (!result) return false;
    const q = ld(QUAR_KEY, []);
    q.unshift({
      id: result.id || Date.now(),
      name: result.name,
      sha256: result.sha256 || null,
      level: result.level,
      findings: result.findings || [],
      quarantinedAt: new Date().toISOString(),
      note: 'Локальная запись. Файл на диске не перемещался — браузер не имеет такого доступа.'
    });
    sv(QUAR_KEY, q.slice(0, MAX_QUARANTINE));
    return true;
  }

  function getQuarantine() {
    return ld(QUAR_KEY, []);
  }

  function removeFromQuarantine(id) {
    const q = ld(QUAR_KEY, []).filter((x) => x.id !== id);
    sv(QUAR_KEY, q);
  }

  function clearQuarantine() {
    sv(QUAR_KEY, []);
  }

  function protectionStatus() {
    const stats = dbStats();
    const hist = getHistory();
    const recentThreats = hist.filter((h) => h.level === 'high' || h.level === 'malicious').length;
    return {
      active: true,
      mode: 'offline-first',
      database: stats,
      recentScans: hist.length,
      recentThreats,
      lastScan: hist[0] || null,
      tips: loadDB().tips || DEFAULT_DB.tips
    };
  }

  // ---------- UI helpers (used by V.antivirus) ----------

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function renderFindings(findings) {
    if (!findings || !findings.length) {
      return '<p class="good">Подозрительных признаков не найдено.</p>';
    }
    return findings
      .map(
        (f) =>
          `<div class="f"><b>${esc(f.title)}</b><span class="mu">${esc(f.severity || '')}</span><p>${esc(f.detail || '')}</p></div>`
      )
      .join('');
  }

  function renderScanResult(result) {
    if (!result) return '<p class="mu">Результат появится после проверки.</p>';
    const color = levelColor(result.level);
    return `
      <div class="card" style="border-color:${color}">
        <div class="card-head">
          <h2 style="margin:0">${esc(result.verdictLabel || ('Результат: ' + result.levelLabel))}</h2>
          <span class="pill" style="background:${color}">${esc(result.level)}</span>
        </div>
        <p><b>${esc(result.name)}</b></p>
        ${result.verdict === 'unknown' ? '<p class="scan-verdict unknown">Файл неизвестен: не найден в базе. Не считайте это доказательством безопасности.</p>' : result.verdict === 'known-threat' ? '<p class="scan-verdict danger">Точное совпадение с базой. Не открывайте файл.</p>' : result.verdict === 'suspicious' ? '<p class="scan-verdict warning">Проверьте найденные признаки и источник файла.</p>' : ''}
        ${result.sizeLabel ? `<p class="mu">Размер: ${esc(result.sizeLabel)}</p>` : ''}
        ${result.sha256 ? `<p class="mu" style="word-break:break-all">SHA-256: <code>${esc(result.sha256)}</code></p>` : ''}
        ${renderFindings(result.findings)}
        <p class="mu" style="margin-top:12px">${esc(result.scope)}</p>
        <div class="row" style="margin-top:12px">
          <button type="button" class="btn" onclick="FiribStopAV.uiQuarantineLast()">🔒 В карантин (запись)</button>
          <button type="button" class="btn" onclick="FiribStopAV.uiCopyReport()">📋 Копировать отчёт</button>
        </div>
      </div>`;
  }

  function renderHistoryList() {
    const hist = getHistory();
    if (!hist.length) return '<p class="mu">Журнал пуст.</p>';
    return hist
      .slice(0, 20)
      .map(
        (h) =>
          `<div class="region-row" style="display:flex;justify-content:space-between;gap:8px;padding:8px 0;border-bottom:1px solid var(--bd)">
            <span><b>${esc(h.kind)}</b> · ${esc((h.name || '').slice(0, 48))}${h.name && h.name.length > 48 ? '…' : ''}</span>
            <span style="color:${levelColor(h.level)};font-weight:700">${esc(levelLabel(h.level))}</span>
          </div>`
      )
      .join('');
  }

  function renderQuarantineList() {
    const q = getQuarantine();
    if (!q.length) return '<p class="mu">Карантин пуст. Это локальный список меток — файлы на диске не перемещаются.</p>';
    return q
      .map(
        (item) =>
          `<div class="card" style="padding:12px">
            <b>${esc(item.name)}</b>
            <p class="mu">${esc(item.quarantinedAt)} · ${esc(levelLabel(item.level))}</p>
            ${item.sha256 ? `<p class="mu" style="word-break:break-all"><code>${esc(item.sha256)}</code></p>` : ''}
            <button type="button" class="btn" onclick="FiribStopAV.uiRemoveQuarantine(${item.id})">Удалить запись</button>
          </div>`
      )
      .join('');
  }

  function renderDashboard() {
    const st = protectionStatus();
    const db = st.database;
    const tip = (st.tips && st.tips[Math.floor(Math.random() * st.tips.length)]) || '';
    return `
      <div class="card" style="background:linear-gradient(135deg,#0b2545,#0f766e);color:#fff;border:0;padding:24px">
        <div style="display:flex;gap:18px;align-items:center;flex-wrap:wrap">
          <div style="font-size:52px" aria-hidden="true">🛡️</div>
          <div style="flex:1;min-width:200px">
            <div class="eyebrow" style="color:#5de4d2">FIRIBSTOP SECURITY</div>
            <h1 style="color:#fff;margin:6px 0 8px;font-size:28px">Антивирусный центр</h1>
            <p style="margin:0;color:#cfeee9">Защита активна в режиме offline-first. Проверка файлов, ссылок и локальной базы угроз.</p>
          </div>
          <div style="text-align:center;padding:12px 16px;border-radius:16px;background:#ffffff18;border:1px solid #ffffff33">
            <div style="font-size:13px;color:#a7f3d0">СТАТУС</div>
            <b style="font-size:20px">Активна</b>
          </div>
        </div>
        <div class="grid" style="margin-top:20px">
          <div style="padding:14px;border-radius:14px;background:#ffffff14">
            <div style="font-size:12px;opacity:.85">БАЗА ХЕШЕЙ</div>
            <b style="font-size:26px">${db.hashCount}</b>
          </div>
          <div style="padding:14px;border-radius:14px;background:#ffffff14">
            <div style="font-size:12px;opacity:.85">ДОМЕНЫ / TLD</div>
            <b style="font-size:26px">${db.domainCount + db.tldCount}</b>
          </div>
          <div style="padding:14px;border-radius:14px;background:#ffffff14">
            <div style="font-size:12px;opacity:.85">ПРОВЕРОК</div>
            <b style="font-size:26px">${st.recentScans}</b>
          </div>
        </div>
      </div>

      <div class="map-disclaimer">
        <b>⚠ Честные ограничения</b>
        Это браузерный/PWA-сканер. Он не имеет доступа к ядру ОС, не блокирует процессы в реальном времени и не заменяет Kaspersky, Windows Defender или антивирус на телефоне. Используйте как дополнительный слой цифровой гигиены.
      </div>

      <div class="pro-grid" style="margin-top:16px">
        <div class="card">
          <h2>⚡ Быстрая проверка</h2>
          <p class="mu">Файл (APK, документы, архивы) или ссылка. Всё считается локально на вашем устройстве.</p>
          <input id="avFilePicker" type="file" hidden onchange="FiribStopAV.uiScanFile(this)">
          <button type="button" class="btn p" onclick="document.getElementById('avFilePicker').click()">📂 Проверить файл</button>
          <div class="row">
            <input id="avUrlInput" type="url" placeholder="https://example.com/..." style="flex:1;padding:12px;border:1px solid var(--bd);border-radius:12px;background:var(--sf);color:var(--tx);font:inherit">
          </div>
          <button type="button" class="btn" onclick="FiribStopAV.uiScanUrl()">🔗 Проверить ссылку локально</button>
          <button type="button" class="btn" onclick="FiribStopAV.uiLookupUrlhaus()">🌐 Сверить URL с URLhaus онлайн</button>
          <p class="mu">Онлайн-сверка отправляет выбранный URL стороннему источнику. Требует настройки URLHAUS_AUTH_KEY на сервере.</p>
          <button type="button" class="btn" onclick="FiribStopAV.uiScanTextAsUrl()">📝 Проверить текст/сообщение (через анализатор)</button>
          <div id="avScanResult">${lastScanResult ? renderScanResult(lastScanResult) : '<p class="mu">Загрузите файл или вставьте ссылку.</p>'}</div>
        </div>
        <div class="card">
          <h2>📊 Состояние</h2>
          <p class="mu">База: <b>${esc(db.name || 'Built-in')}</b></p>
          <p class="mu">Источник: ${esc(db.source || 'локальные эвристики')}</p>
          <p class="mu">Обновлена: ${esc(db.updatedAt || '—')}<br>Действует до: ${esc(db.validUntil || 'не задано')}${db.stale ? ' · СРОК ИСТЁК' : ''}${db.importedAt ? '<br>Импорт: ' + esc(new Date(db.importedAt).toLocaleString('ru-RU')) : ''}</p>
          <p class="mu">Угроз в журнале: <b>${st.recentThreats}</b></p>
          <div class="tip-row"><span>💡</span><div><b>Совет дня</b><p>${esc(tip)}</p></div></div>
          <button type="button" class="btn" onclick="FiribStopAV.uiLoadBundled()">🔄 Загрузить встроенную базу</button>
          <button type="button" class="btn" onclick="document.getElementById('avDbPicker').click()">📥 Импорт JSON базы</button>
          <input id="avDbPicker" type="file" accept="application/json,.json" hidden onchange="FiribStopAV.uiImportDb(this)">
          <p id="avDbStatus" class="status-note">Хешей: ${db.hashCount}. Доменов: ${db.domainCount}.</p>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><h2>🧾 Журнал проверок</h2>
          <button type="button" class="btn" style="width:auto;min-height:40px;padding:8px 14px" onclick="FiribStopAV.uiClearHistory()">Очистить</button>
        </div>
        <div id="avHistory">${renderHistoryList()}</div>
      </div>

      <div class="card">
        <div class="card-head"><h2>🔒 Карантин (локальные метки)</h2>
          <button type="button" class="btn" style="width:auto;min-height:40px;padding:8px 14px" onclick="FiribStopAV.uiClearQuarantine()">Очистить</button>
        </div>
        <p class="mu">Браузер не может перемещать файлы в системный карантин. Здесь хранятся только записи о подозрительных объектах.</p>
        <div id="avQuarantine">${renderQuarantineList()}</div>
      </div>
    `;
  }

  // UI action bridges
  const ui = {
    async uiScanFile(input) {
      const file = input?.files?.[0];
      if (!file) return;
      const box = document.getElementById('avScanResult');
      if (box) box.innerHTML = '<div class="av-scanning">Сканирование файла…</div>';
      try {
        const result = await scanFile(file);
        if (box) box.innerHTML = renderScanResult(result);
        const hist = document.getElementById('avHistory');
        if (hist) hist.innerHTML = renderHistoryList();
        if (typeof global.toast === 'function') {
          global.toast(result.level === 'clean' ? 'Файл: чисто' : 'Найдены признаки риска');
        }
      } catch (e) {
        if (box) box.innerHTML = `<p class="err">${esc(e.message || e)}</p>`;
      }
      input.value = '';
    },
    uiScanUrl() {
      const input = document.getElementById('avUrlInput');
      const raw = input?.value?.trim();
      if (!raw) {
        if (typeof global.toast === 'function') global.toast('Вставьте ссылку');
        return;
      }
      const result = scanUrl(raw);
      const box = document.getElementById('avScanResult');
      if (box) box.innerHTML = renderScanResult(result);
      const hist = document.getElementById('avHistory');
      if (hist) hist.innerHTML = renderHistoryList();
    },
    async uiLookupUrlhaus() {
      const input = document.getElementById('avUrlInput');
      const raw = input?.value?.trim();
      const box = document.getElementById('avScanResult');
      if (!raw) { if (typeof global.toast === 'function') global.toast('Сначала вставьте URL'); return; }
      let target;
      try { target = new URL(raw.includes('://') ? raw : 'https://' + raw); }
      catch { if (typeof global.toast === 'function') global.toast('Некорректный URL'); return; }
      if (!['http:', 'https:'].includes(target.protocol)) { if (typeof global.toast === 'function') global.toast('Разрешены только HTTP/HTTPS ссылки'); return; }
      if (!global.confirm('Онлайн-проверка отправит этот адрес в URLhaus (abuse.ch). Продолжить?')) return;
      if (box) box.innerHTML = '<div class="av-scanning">Проверяем URL через внешний источник…</div>';
      try {
        const response = await fetch('/api/intel/urlhaus', { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify({ url: target.href }), cache: 'no-store' });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
        const matched = data.queryStatus === 'ok';
        const title = matched ? 'Найден URL в базе URLhaus' : data.queryStatus === 'no_results' ? 'URLhaus не нашёл совпадение' : 'Ответ URLhaus требует проверки';
        const label = matched ? 'Совпадение источника угроз' : data.queryStatus === 'no_results' ? 'Совпадений нет' : data.queryStatus;
        if (box) box.innerHTML = `<div class="card"><div class="card-head"><h2>${esc(title)}</h2><span class="pill" style="background:${matched ? 'var(--hi)' : 'var(--tl)'}">${esc(label)}</span></div><p><b>${esc(data.url || target.href)}</b></p><p class="mu">Источник: ${esc(data.source)} · Проверено: ${esc(data.checkedAt)}${data.cached ? ' · из кеша' : ''}</p>${data.urlStatus ? `<p>Статус URL: ${esc(data.urlStatus)}</p>` : ''}${data.threat ? `<p>Тип угрозы: ${esc(data.threat)}</p>` : ''}${data.tags?.length ? `<p>Метки: ${esc(data.tags.join(', '))}</p>` : ''}${data.reference ? `<p><a href="${esc(data.reference)}" target="_blank" rel="noopener noreferrer">Открыть источник ↗</a></p>` : ''}<p class="mu">Отрицательный результат не гарантирует безопасность: данные могут быть неполными или устаревшими. Локальная эвристическая проверка остаётся отдельным результатом.</p></div>`;
        if (typeof global.toast === 'function') global.toast(matched ? 'URL найден в базе URLhaus' : 'Ответ URLhaus получен');
      } catch (e) {
        if (box) box.innerHTML = `<div class="card"><h2>Онлайн-проверка недоступна</h2><p class="err">${esc(e.message || e)}</p><p class="mu">Для включения задайте URLHAUS_AUTH_KEY в переменных окружения серверного хостинга. URL не был проверен через внешний источник.</p></div>`;
      }
    },
    uiScanTextAsUrl() {
      if (typeof global.go === 'function') global.go('check');
      else if (typeof global.toast === 'function') global.toast('Откройте раздел проверки сообщений');
    },
    uiQuarantineLast() {
      if (!lastScanResult) return;
      addToQuarantine(lastScanResult);
      const q = document.getElementById('avQuarantine');
      if (q) q.innerHTML = renderQuarantineList();
      if (typeof global.toast === 'function') global.toast('Добавлено в карантин (запись)');
    },
    uiCopyReport() {
      if (!lastScanResult) return;
      const r = lastScanResult;
      const text = [
        'FiribStop AV Report',
        '==================',
        `Object: ${r.name}`,
        `Level: ${r.levelLabel} (${r.level})`,
        r.sha256 ? `SHA-256: ${r.sha256}` : '',
        r.sizeLabel ? `Size: ${r.sizeLabel}` : '',
        `Scanned: ${r.scannedAt}`,
        '',
        'Findings:',
        ...(r.findings || []).map((f) => `- [${f.severity}] ${f.title}: ${f.detail || ''}`),
        '',
        r.scope
      ]
        .filter(Boolean)
        .join('\n');
      navigator.clipboard?.writeText(text).then(
        () => typeof global.toast === 'function' && global.toast('Отчёт скопирован'),
        () => typeof global.toast === 'function' && global.toast('Не удалось скопировать')
      );
    },
    async uiImportDb(input) {
      const file = input?.files?.[0];
      if (!file) return;
      try {
        if (file.size > MAX_IMPORT_BYTES) throw new Error('Файл базы больше 2 МиБ — импорт отклонён');
        const text = await file.text();
        const res = await importThreatJSON(text);
        const st = document.getElementById('avDbStatus');
        if (st) st.textContent = `Импортировано записей: ${res.entries}. Источник: ${res.source}. Обновлено: ${res.updatedAt}. Действует до: ${res.validUntil || 'не указано'}.`;
        if (typeof global.toast === 'function') global.toast('База импортирована');
        if (typeof global.render === 'function') global.render(true);
      } catch (e) {
        if (typeof global.toast === 'function') global.toast('Ошибка импорта: ' + (e.message || e));
      }
      input.value = '';
    },
    async uiLoadBundled() {
      const ok = await tryLoadBundledDB();
      const st = document.getElementById('avDbStatus');
      const stats = dbStats();
      if (st) st.textContent = ok
        ? `Встроенная база загружена. Хешей: ${stats.hashCount}.`
        : `Используется встроенный минимум. Хешей: ${stats.hashCount}.`;
      if (typeof global.toast === 'function') global.toast(ok ? 'База обновлена' : 'Локальный минимум активен');
    },
    uiClearHistory() {
      if (confirm('Очистить журнал проверок?')) {
        clearHistory();
        const hist = document.getElementById('avHistory');
        if (hist) hist.innerHTML = renderHistoryList();
      }
    },
    uiClearQuarantine() {
      if (confirm('Очистить карантин?')) {
        clearQuarantine();
        const q = document.getElementById('avQuarantine');
        if (q) q.innerHTML = renderQuarantineList();
      }
    },
    uiRemoveQuarantine(id) {
      removeFromQuarantine(id);
      const q = document.getElementById('avQuarantine');
      if (q) q.innerHTML = renderQuarantineList();
    }
  };

  // Public API
  global.FiribStopAV = {
    scanFile,
    scanUrl,
    parseBinaryManifest,
    importThreatJSON,
    tryLoadBundledDB,
    dbStats,
    protectionStatus,
    getHistory,
    clearHistory,
    addToQuarantine,
    getQuarantine,
    removeFromQuarantine,
    clearQuarantine,
    renderDashboard,
    renderScanResult,
    get lastScanResult() {
      return lastScanResult;
    },
    ...ui
  };

  // Preload DB
  loadDB();
  tryLoadBundledDB().catch(() => {});
})(typeof window !== 'undefined' ? window : globalThis);
