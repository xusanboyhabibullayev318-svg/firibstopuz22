# FiribStop UZ — Offline Shield 2.7.9 · No-API CyberAttackMap Embed

**Офлайн-first PWA** для цифровой безопасности граждан Узбекистана.

Проверка подозрительных сообщений и ссылок, экстренные контакты, карта упоминаний киберугроз по регионам, живая лента новостей из проверенных RSS-источников и обучение.

---

## Возможности

| Модуль | Описание | Офлайн |
|--------|----------|--------|
| **Проверка текста** | Анализ сообщений на признаки фишинга, срочности, угроз, просьб кодов/денег | ✅ Полностью |
| **Проверка URL** | Эвристики: короткие ссылки, подозрительные TLD, имитация брендов, IP-хосты | ✅ Полностью |
| **Карта угроз** | Административные границы Узбекистана + текстовые упоминания регионов в новостях | ⚠️ Границы + новости требуют интернет |
| **Новости** | Агрегация RSS (UZCERT, SecurityLab, Securelist, Kaspersky, Anti-Malware.ru) | ⚠️ Кеш + офлайн-копия |
| **Антивирус** | Центр защиты: сканер файлов (SHA-256 + эвристика), проверка URL, локальная база угроз, карантин-метки, журнал | ✅ |
| **Экстренные контакты** | Банки и полиция | ✅ |
| **Обучение** | Примеры типичных схем мошенничества | ✅ |

> **Важно:** Карта отражает только текстовые совпадения в публикациях. Это **не** подтверждённая статистика атак в реальном времени.

---

## Быстрый старт

```bash
# Требуется Node.js 18+
npm install   # (зависимостей нет — команда для совместимости)
npm start
```

Откройте http://localhost:3000

### Тесты

```bash
npm test
```

---

## Развёртывание на Netlify

Для новостной ленты добавлены Netlify Functions: `/api/news` направляется на `netlify/functions/news.js`, а `/api/health` — на `netlify/functions/health.js`. Поэтому для этих двух маршрутов не требуется отдельный Render-сервер или настройка CORS: фронтенд и функции работают на одном домене. После загрузки изменений в GitHub дождитесь нового успешного Deploy на Netlify и проверьте `https://ВАШ-САЙТ.netlify.app/api/health` (должен открыться JSON со значением `"ok": true`) и `https://ВАШ-САЙТ.netlify.app/api/news` (JSON с полями `items`, `sources`, `updatedAt`). RSS-источники по отдельности могут временно не отвечать; тогда их состояние указано в `sources`.

## Развёртывание (Render)

Файл `render.yaml` уже настроен:

- Runtime: Node
- Build: `npm install`
- Start: `npm start`
- Health check: `/api/health`

После деплоя:

1. Откройте сайт и сделайте **Ctrl+Shift+R** (жёсткая перезагрузка).
2. Проверьте светлую/тёмную тему и мобильную навигацию.
3. Откройте «Карта киберугроз» — при блокировке картографических сервисов подложка может не загрузиться, но список регионов останется доступным.

Service Worker: **v39**.

---


## Антивирусный модуль (2.7.1)

Полноценный **offline-first** центр защиты внутри PWA:

- Проверка **любых файлов** (SHA-256, расширение, эвристика содержимого)
- Проверка **ссылок** (сокращатели, IP-хосты, подозрительные TLD, punycode)
- Локальная база угроз (`data/threats.json`) + импорт JSON
- Журнал проверок и **карантин-метки** (браузер не может перемещать файлы в системный карантин)
- Честные дисклеймеры: не заменяет Kaspersky / Defender

API движка: `window.FiribStopAV` (`scanFile`, `scanUrl`, `importThreatJSON`, …).

## Архитектура

```
firibstop-uz/
├── index.html          # Чистая оболочка + a11y
├── styles.css          # Вся визуальная система + motion system
├── app.js              # Логика приложения + анализатор
├── server.js           # Node-сервер (статика + RSS-прокси + GeoJSON)
├── runtime.js          # Внешний bootstrap для строгой CSP
├── sw.js               # Service Worker v28
├── manifest.webmanifest
├── scams.json          # Примеры мошенничества
├── known_apk_hashes.template.json
└── tests/
```

- **Zero external runtime dependencies** (только Node.js built-ins).
- Клиент — vanilla JS + SVG renderer.
- API: `/api/health`, `/api/news`, `/api/analytics`, `/api/attacks`, `/api/regions`.
- Безопасность: CSP, `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`.

---

## Что нового в 2.7.1 (Professional)

- Модульная структура (HTML / CSS / JS разделены).
- Улучшенные security headers + Content-Security-Policy.
- Skip-link и улучшения accessibility.
- Индикатор Онлайн / Офлайн.
- Service Worker v28 с кешированием CSS/JS.
- Более заметный дисклеймер на карте.
- Профессиональная документация и package.json.
- Версия в health-check.

---

## Ограничения и честность

- Анализатор — эвристический. Не заменяет профессиональный антифишинг.
- Карта не показывает реальные инциденты, только упоминания в открытых источниках.
- Локальная база хешей APK демонстрационная, а не исчерпывающая; импортируйте свежие индикаторы с указанием источника и срока действия.
- Для свежих новостей и подложки карты нужен интернет.

---

## Лицензия

MIT (community project). Используйте ответственно.

**FiribStop UZ** — делаем цифровую гигиену доступной.


## Security hardening in 2.7.1

- CSP no longer permits inline `<script>` blocks (`script-src` has no `unsafe-inline`). Legacy generated inline event attributes remain temporarily permitted via the narrower `script-src-attr` directive; converting all existing handlers to delegated listeners is the next hardening step.
- The server does not expose wildcard CORS. Same-origin works by default; cross-origin access must be explicitly configured using `CORS_ORIGINS=https://example.org,https://another.example`.
- API requests have a per-IP limit (120/min; RSS refresh limited to 8/min), and upstream RSS/GeoJSON response sizes and timeouts are bounded.
- Public static serving blocks server source, tests, package metadata and dotfiles.
- File scan separates exact known-threat matches, suspicious indicators and unknown files. It inspects common signatures and ZIP directory entries (paths, executable/script entries, Office macros and suspicious compression ratios), without executing or extracting files.
- Unknown does not mean clean. Large files over 50 MiB are not loaded into memory for hashing; deep file/archive inspection is limited to 25 MiB.
- Threat imports are limited to 2 MiB, 20,000 hashes and 5,000 domains, validate SHA-256, domain syntax, severity and dates, and preserve source/expiry metadata.
- Keep `CORS_ORIGINS` unset for a same-origin-only deployment. To enable online URL reputation lookup, set `URLHAUS_AUTH_KEY` in the hosting environment; never commit this key. URLhaus requires an API key for automated bulk lookups. Every online lookup sends the chosen URL to URLhaus, while the local scanner stays offline-capable. Do not put raw malware samples in the public repository.

### Before presenting publicly

Run `npm test`, test all key pages in a desktop and mobile browser, inspect the production `/api/health`, confirm no console errors, and refresh with Ctrl+Shift+R. This project uses heuristics and is not a certified antivirus; test the demo with benign files and the standard EICAR test signature only.

## Что нового в 2.7.1 — Demo Intelligence

- Пошаговый локальный сканер: структура текста, ссылки и домены, эвристические правила, объяснение сигналов и подготовка отчёта.
- Объяснимый результат с найденными фрагментами, причинами предупреждений и практическими следующими действиями.
- Фильтры карты публикаций по тематике и периоду; категории классифицируются по ключевым словам и не являются подтверждением инцидента.
- Дополнительные учебные сценарии: доставка, вакансия с предоплатой, ложный выигрыш и поддельная техподдержка.
- Отчёт для печати/сохранения в PDF и TXT. Распознанные в сообщении коды, длинные номера карт и распространённые телефонные форматы маскируются в экспортируемом фрагменте.
- Обновлён Service Worker cache до v28.

Экспорт PDF использует системный диалог печати браузера: выберите «Сохранить как PDF». Риск-индекс — эвристическая оценка по локальным правилам, а не вероятность мошенничества; возможны ложные срабатывания и пропуски.


## Fix 2.7.1 — карта

- Отключены внешние тайловые слои OpenStreetMap/CARTO, которые в некоторых сетях могли отвечать `Access blocked`.
- Границы регионов и маркеры отрисовываются локально из GeoJSON; внешний картографический фон больше не требуется.
- Service Worker cache обновлён до v28.

- В версии 2.7.1 external map library CDN полностью удалён: карта регионов использует нативный SVG, а не внешние тайлы.


## Fix 2.7.3 — RSS feed fallback

- Не показываем сырой `Failed to fetch`: интерфейс объясняет, когда проект открыт через `file://`, когда API недоступен и как проверить `/api/health`.
- При сбое загружаются сохранённые публикации из localStorage; если копии нет, отображаются инструкции и ссылки на реальные источники, а не выдуманные новости.
- Добавлены тайм-аут запроса и проверка JSON-ответа API. Карта использует тот же graceful fallback.
- Service Worker cache обновлён до v30, чтобы браузер не продолжал показывать старый интерфейс.


## Fix 2.7.3 — карта не зависит от внешней геометрии

- `/api/regions` использует проверенный внешний GeoJSON, если источник отвечает. При ошибке сервер возвращает локальную встроенную схему регионов.
- Клиент имеет встроенный fallback, поэтому карта не остаётся пустой при недоступности API/CORS.
- Локальный fallback — **схематичная картограмма**, а не точная административная геометрия; это явно обозначено в интерфейсе. Для точных границ используйте проверенный источник GeoJSON и храните его в проекте локально.
- Кэш карты обновлён до `fs_uzbekistan_regions_geojson_v2`; Service Worker cache v30.


## Release 2.7.4 — UZCERT live monitor

- Added a dedicated **UZCERT LIVE** section with the official Cyber Trends attack map (`https://trends.uzcert.uz/map`), trends dashboard (`https://trends.uzcert.uz/trends`) and main UZCERT website.
- The official map is offered as a direct external panel. If UZCERT disables third-party framing, the top-level links remain available and open the authoritative source directly.
- The integration does not fabricate attack counts or treat FiribStop RSS headlines as confirmed live incidents.
- Added a restrictive `frame-src` CSP allowlist for the UZCERT dashboard and incremented the Service Worker cache to v31.
- This is an external-data integration. Availability and refresh cadence remain controlled by UZCERT.

## Усиление антивируса (v38)
- Разбор AndroidManifest.xml в APK: опасные права (SMS, специальные возможности, наложение окон, установка пакетов, администратор устройства).
- Автообновление базы хешей из MalwareBazaar: `ABUSECH_AUTH_KEY=... node scripts/update-threat-db.js` или GitHub Actions `.github/workflows/update-threat-db.yml` (секрет `ABUSECH_AUTH_KEY`).
