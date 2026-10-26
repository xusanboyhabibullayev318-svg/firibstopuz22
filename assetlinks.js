'use strict';
// Строит /.well-known/assetlinks.json из переменных окружения.
// Нужен, чтобы Android-приложение (TWA) открывало сайт без адресной строки браузера.
//   ANDROID_PACKAGE        — имя пакета, как в PWABuilder (например uz.firibstop.app)
//   ANDROID_SHA256_CERTS   — SHA-256 отпечаток(и) ключа подписи, через запятую
function buildAssetLinks(env = process.env) {
  const pkg = String(env.ANDROID_PACKAGE || '').trim();
  const certs = String(env.ANDROID_SHA256_CERTS || '').split(',').map((s) => s.trim().toUpperCase()).filter(Boolean);
  if (!/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/i.test(pkg)) return null;
  if (!certs.length || !certs.every((c) => /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(c))) return null;
  return [{
    relation: ['delegate_permission/common.handle_all_urls'],
    target: { namespace: 'android_app', package_name: pkg, sha256_cert_fingerprints: certs }
  }];
}
module.exports = { buildAssetLinks };
