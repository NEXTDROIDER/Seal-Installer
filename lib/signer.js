'use strict';
// Подпись IPA. Три бэкенда:
//   js    — встроенная подпись на чистом JS (по умолчанию)
//   zsign — локально, через бинарник zsign (рекомендуется)
//   api   — внешний сервис подписи (как в исходном проекте), POST multipart на SIGN_API_URL
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { signIpa, loadIdentity, loadProfile } = require('./ipasigner');

// Кэш удостоверения для встроенного JS-подписанта (ключ читается один раз)
let jsCache = null;
function jsIdentity(cfg) {
  const key = cfg.certDir + '|' + cfg.certPassword;
  if (jsCache && jsCache.key === key) return jsCache;
  const identity = loadIdentity(cfg.certDir, cfg.certPassword ?? readPassFile(cfg));
  const profile = loadProfile(path.join(cfg.certDir, 'cert.mobileprovision'));
  jsCache = { key, identity, profile };
  return jsCache;
}
function readPassFile(cfg) {
  const f = path.join(cfg.certDir, 'password.txt');
  return fs.existsSync(f) ? fs.readFileSync(f, 'utf8').trim() : '';
}

function loadCerts(cfg) {
  const p12 = path.join(cfg.certDir, 'cert.p12');
  const prov = path.join(cfg.certDir, 'cert.mobileprovision');
  const passFile = path.join(cfg.certDir, 'password.txt');
  const password =
    cfg.certPassword ?? (fs.existsSync(passFile) ? fs.readFileSync(passFile, 'utf8').trim() : '');
  return { p12, prov, password, ok: fs.existsSync(p12) && fs.existsSync(prov) };
}

function which(bin) {
  for (const dir of (process.env.PATH || '').split(path.delimiter)) {
    const full = path.join(dir, bin);
    try { fs.accessSync(full, fs.constants.X_OK); return full; } catch {}
  }
  return null;
}

function status(cfg) {
  const certs = loadCerts(cfg);
  if (cfg.signer === 'js') {
    try {
      const { identity, profile } = jsIdentity(cfg);
      const exp = profile.data.ExpirationDate;
      return { ready: true, team: profile.team, cert: identity.leaf.subject.split('\n').find((l) => l.startsWith('CN=')),
               profileExpires: exp ? new Date(exp).toISOString() : null };
    } catch (e) { jsCache = null; return { ready: false, reason: e.message }; }
  }
  if (cfg.signer === 'zsign') {
    const bin = cfg.zsignBin.includes(path.sep) ? cfg.zsignBin : which(cfg.zsignBin);
    if (!bin) return { ready: false, reason: `zsign не найден (${cfg.zsignBin})` };
    if (!certs.ok) return { ready: false, reason: `нет cert.p12 / cert.mobileprovision в ${cfg.certDir}` };
    return { ready: true, bin };
  }
  if (cfg.signer === 'api') {
    if (!certs.ok) return { ready: false, reason: `нет cert.p12 / cert.mobileprovision в ${cfg.certDir}` };
    return { ready: true };
  }
  return { ready: false, reason: 'SIGNER должен быть js, zsign или api' };
}

function runZsign(cfg, input, output) {
  const certs = loadCerts(cfg);
  const args = ['-k', certs.p12, '-m', certs.prov, '-o', output, '-z', '1'];
  if (certs.password) args.push('-p', certs.password);
  args.push(input);
  return new Promise((resolve, reject) => {
    const bin = cfg.zsignBin;
    const child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let log = '';
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('zsign: таймаут')); }, cfg.signTimeoutMs);
    child.stdout.on('data', (d) => (log += d));
    child.stderr.on('data', (d) => (log += d));
    child.on('error', (e) => { clearTimeout(timer); reject(new Error('zsign не запустился: ' + e.message)); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0 && fs.existsSync(output)) resolve({ file: output, log });
      else reject(new Error(`zsign завершился с кодом ${code}\n${log.slice(-1500)}`));
    });
  });
}

async function runApi(cfg, input) {
  const certs = loadCerts(cfg);
  const form = new FormData();
  form.append('ipa', await fs.openAsBlob(input), 'app.ipa');
  form.append('p12', await fs.openAsBlob(certs.p12), 'cert.p12');
  form.append('mobileprovision', await fs.openAsBlob(certs.prov), 'cert.mobileprovision');
  form.append('password', certs.password);
  const res = await fetch(cfg.signApiUrl, {
    method: 'POST',
    body: form,
    signal: AbortSignal.timeout(cfg.signTimeoutMs),
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { throw new Error(`API вернул не JSON (HTTP ${res.status}): ${text.slice(0, 200)}`); }
  if (!res.ok) throw new Error(`API HTTP ${res.status}: ${JSON.stringify(data).slice(0, 300)}`);
  return data; // { installUrl } или { url }
}

/**
 * Возвращает { file } (локальный подписанный IPA) или { remoteUrl } (IPA лежит на стороне API).
 */
async function sign(cfg, input, output) {
  const st = status(cfg);
  if (!st.ready) throw new Error('Подпись недоступна: ' + st.reason);
  if (cfg.signer === 'js') {
    const { identity, profile } = jsIdentity(cfg);
    const r = await signIpa(input, output, { identity, profile, bundleId: cfg.bundleId, log: (m) => console.log('[sign]', m) });
    r.warnings.forEach((w) => console.warn('[sign] ⚠', w));
    return { file: output, warnings: r.warnings, bundleId: r.bundleId };
  }
  if (cfg.signer === 'zsign') return runZsign(cfg, input, output);
  const data = await runApi(cfg, input);
  const remoteUrl = data.installUrl || data.url;
  if (!remoteUrl) throw new Error('Неизвестный ответ API: ' + JSON.stringify(data).slice(0, 300));
  return { remoteUrl, install: Boolean(data.installUrl) };
}

const resetCache = () => { jsCache = null; };

module.exports = { sign, status, resetCache };
