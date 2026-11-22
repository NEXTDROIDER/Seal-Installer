'use strict';
// Загрузка ваших сертификатов из вашего API (список /api/certificates/list/signed/N).
// Формат ответа определяется по именам полей: *p12*, *provision*, *pass*; значения — URL, путь или base64.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { loadIdentity, loadProfile, checkIdentity } = require('./ipasigner');

const pick = (o, re) => {
  for (const [k, v] of Object.entries(o)) if (re.test(k) && typeof v === 'string' && v) return v;
  return null;
};
// поднимаем вложенные объекты на один уровень: { files: { p12: ... } } -> { 'files.p12': ... }
const flatten = (o) => {
  const out = {};
  for (const [k, v] of Object.entries(o || {})) {
    if (v && typeof v === 'object' && !Array.isArray(v)) for (const [k2, v2] of Object.entries(v)) out[`${k}.${k2}`] = v2;
    else out[k] = v;
  }
  return out;
};

function headersFor(cfg, url) {
  if (!cfg.certApiAuth) return {};
  const host = new URL(url).hostname;
  const apiHost = new URL(cfg.certApiUrl).hostname;
  const ok = host === apiHost || /(^|\.)github(usercontent)?\.com$/.test(host);
  return ok ? { Authorization: cfg.certApiAuth, 'User-Agent': 'seal-installer' } : {};
}

async function getBytes(cfg, value, baseUrl) {
  const v = value.trim();
  if (/^[A-Za-z0-9+/=\s]{200,}$/.test(v)) return Buffer.from(v.replace(/\s+/g, ''), 'base64');
  const url = new URL(v, baseUrl).toString();
  const res = await fetch(url, { headers: headersFor(cfg, url), signal: AbortSignal.timeout(30000) });
  if (!res.ok) throw new Error(`HTTP ${res.status} при загрузке ${url}`);
  return Buffer.from(await res.arrayBuffer());
}

async function syncOnce(cfg, log = console.log) {
  const listUrl = new URL(cfg.certApiPath, cfg.certApiUrl.replace(/\/?$/, '/')).toString();
  const res = await fetch(listUrl, { headers: { Accept: 'application/json', ...headersFor(cfg, listUrl) }, signal: AbortSignal.timeout(30000) });
  if (!res.ok) throw new Error(`API списка вернул HTTP ${res.status}`);
  const json = await res.json();
  const items = Array.isArray(json) ? json
    : json.certificates || json.data || json.items || json.results || (json.p12 ? [json] : []);
  if (!items.length) throw new Error('API вернул пустой список сертификатов');

  const errors = [];
  for (const item of items) {
    const flat = flatten(item);
    const state = String(flat.status ?? flat.state ?? '').toLowerCase();
    if (/revok|missing/.test(state) || flat.revoked === true) continue;
    const until = Date.parse(flat.valid_to || flat.validTo || '');
    if (until && until < Date.now()) continue; // срок по метаданным уже истёк
    const name = flat.name || flat.id || 'cert';
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'seal-cert-'));
    try {
      let p12v = pick(flat, /p12|pkcs12/i);
      let mpv = pick(flat, /provision/i);
      let password = pick(flat, /pass/i);
      // API отдаёт только метаданные: файлы качаются из /api/certificates/download/:id/ (или по CERT_FILES_URL)
      if (!p12v || !mpv) {
        const tpl = cfg.certFilesUrl || (flat.id != null ? cfg.certApiUrl.replace(/\/+$/, '') + '/api/certificates/download/{id}/' : '');
        if (tpl) {
          const dir = tpl.replace('{id}', encodeURIComponent(flat.id ?? '')).replace('{folder_name}', encodeURIComponent(flat.folder_name ?? '')).replace(/\/?$/, '/');
          p12v = p12v || dir + cfg.certP12File;
          mpv = mpv || dir + cfg.certProfileFile;
          if (password == null && cfg.certPassword == null && cfg.certPassFile) {
            password = (await getBytes(cfg, dir + cfg.certPassFile, listUrl)).toString('utf8').trim();
          }
        }
      }
      if (!p12v || !mpv) { errors.push(`${name}: нет p12 или mobileprovision (нет id/folder_name или CERT_FILES_URL)`); continue; }
      password = password ?? cfg.certPassword ?? '';
      fs.writeFileSync(path.join(tmp, 'cert.p12'), await getBytes(cfg, p12v, listUrl));
      fs.writeFileSync(path.join(tmp, 'cert.mobileprovision'), await getBytes(cfg, mpv, listUrl));
      const identity = loadIdentity(tmp, password);
      const profile = loadProfile(path.join(tmp, 'cert.mobileprovision'));
      checkIdentity(identity, profile); // бросает при истёкшем сертификате/профиле
      fs.mkdirSync(cfg.certDir, { recursive: true });
      for (const f of ['cert.p12', 'cert.mobileprovision']) fs.copyFileSync(path.join(tmp, f), path.join(cfg.certDir, f));
      fs.writeFileSync(path.join(cfg.certDir, 'password.txt'), password);
      for (const stale of ['identity.pem', 'key.pem', 'cert.pem', 'chain.pem']) fs.rmSync(path.join(cfg.certDir, stale), { force: true });
      log(`Сертификат обновлён: ${name} (команда ${profile.team})`);
      return { name, team: profile.team };
    } catch (e) {
      errors.push(`${name}: ${e.message}`);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }
  throw new Error('Подходящий сертификат не найден. ' + errors.join('; '));
}

module.exports = { syncOnce };
