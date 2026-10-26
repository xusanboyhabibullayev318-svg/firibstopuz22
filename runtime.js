/* FiribStop runtime bootstrap. Kept external so CSP does not need inline scripts. */
'use strict';
try {
  const theme = localStorage.getItem('fs_theme');
  if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
} catch (_) {}
function updateOnlineBadge() {
  const el = document.getElementById('onlineBadge');
  if (!el) return;
  const online = navigator.onLine;
  el.textContent = online ? 'Онлайн' : 'Офлайн';
  el.classList.toggle('is-online', online);
  el.classList.toggle('is-offline', !online);
  el.setAttribute('aria-label', online ? 'Подключение к интернету есть' : 'Работа без подключения к интернету');
}
window.addEventListener('online', updateOnlineBadge);
window.addEventListener('offline', updateOnlineBadge);
window.addEventListener('DOMContentLoaded', updateOnlineBadge);
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => navigator.serviceWorker.register('./sw.js').catch(() => {}));
}
