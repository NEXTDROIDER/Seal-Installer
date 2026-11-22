#!/usr/bin/env node
'use strict';
// Seal Installer — сервер подписи и установки IPA. Без внешних зависимостей, Node >= 18.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { pipeline } = require('stream/promises');

const { openZip } = require('./lib/zip');
const { parsePlist, buildManifest } = require('./lib/plist');
const signer = require('./lib/signer');
const { syncOnce } = require('./lib/certsync');

const env = process.env;
const cfg = {
  port: Number(env.PORT || 8080),
  host: env.HOST || '0.0.0.0',
  publicUrl: (env.PUBLIC_URL || '').replace(/\/+$/, ''),
  signer: env.SIGNER || 'js',
  bundleId: env.BUNDLE_ID || '',
  zsignBin: env.ZSIGN_BIN || 'zsign',
  signApiUrl: env.SIGN_API_URL || 'https://api.daisign.lol/sign',
  certDir: path.resolve(env.CERT_DIR || path.join(__dirname, 'certs')),
  certPassword: env.CERT_PASSWORD,
  dataDir: path.resolve(env.DATA_DIR || path.join(__dirname, 'data')),
  maxSize: Number(env.MAX_SIZE_MB || 500) * 1024 * 1024,
  ttlMs: Number(env.TTL_MIN || 60) * 60 * 1000,
  signTimeoutMs: Number(env.SIGN_TIMEOUT_SEC || 600) * 1000,
  token: env.ACCESS_TOKEN || '',
  concurrency: Number(env.CONCURRENCY || 1),
  certApiUrl: env.CERT_API_URL || '',
  certApiPath: env.CERT_API_PATH || '/api/certificates/list/signed/5',
  certApiAuth: env.CERT_API_AUTH || '',
  certFilesUrl: env.CERT_FILES_URL || '',
  certP12File: env.CERT_P12_FILE || 'cert.p12',
  certProfileFile: env.CERT_PROFILE_FILE || 'cert.mobileprovision',
  certPassFile: env.CERT_PASS_FILE === undefined ? 'password.txt' : env.CERT_PASS_FILE,
  certSyncMs: Number(env.CERT_SYNC_MIN || 30) * 60 * 1000,
};

const publicDir = path.join(__dirname, 'public');
fs.mkdirSync(cfg.dataDir, { recursive: true });

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.ico': 'image/x-icon', '.png': 'image/png',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml',
};
const ID_RE = /^[a-f0-9]{32}$/;
const jobs = new Map(); // id -> { dir, meta, created }

function send(res, code, body, headers = {}) {
  const isObj = typeof body === 'object' && !Buffer.isBuffer(body);
  res.writeHead(code, {
    'Content-Type': isObj ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...headers,
  });
  res.end(isObj ? JSON.stringify(body) : body);
}

function baseUrl(req) {
  if (cfg.publicUrl) return cfg.publicUrl;
  const proto = (req.headers['x-forwarded-proto'] || 'http').split(',')[0].trim();
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return `${proto}://${host}`;
}

function authorized(req) {
  if (!cfg.token) return true;
  const got = Buffer.from(String(req.headers['x-token'] || ''));
  const want = Buffer.from(cfg.token);
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

// Простая очередь, чтобы не запускать много подписей сразу
let running = 0;
const waiting = [];
async function limited(fn) {
  if (running >= cfg.concurrency) await new Promise((r) => waiting.push(r));
  running++;
  try { return await fn(); } finally { running--; waiting.shift()?.(); }
}

async function readAppInfo(ipaPath) {
  const zip = await openZip(ipaPath);
  try {
    const entry = zip.entries.find((e) => /^Payload\/[^/]+\.app\/Info\.plist$/.test(e.name));
    if (!entry) throw new Error('В IPA нет Payload/<App>.app/Info.plist');
    const info = parsePlist(await zip.read(entry.name));
    if (!info || !info.CFBundleIdentifier) throw new Error('В Info.plist нет CFBundleIdentifier');
    return {
      bundleId: String(info.CFBundleIdentifier),
      version: String(info.CFBundleShortVersionString || info.CFBundleVersion || '1.0'),
      name: String(info.CFBundleDisplayName || info.CFBundleName || info.CFBundleIdentifier),
    };
  } finally {
    await zip.close();
  }
}

async function handleSign(req, res) {
  if (!authorized(req)) return send(res, 401, { error: 'Неверный токен доступа' });
  const st = signer.status(cfg);
  if (!st.ready) return send(res, 503, { error: st.reason });

  const declared = Number(req.headers['content-length'] || 0);
  if (declared > cfg.maxSize) return send(res, 413, { error: 'Файл слишком большой' });

  const id = crypto.randomBytes(16).toString('hex');
  const dir = path.join(cfg.dataDir, id);
  fs.mkdirSync(dir, { recursive: true });
  const input = path.join(dir, 'input.ipa');
  const output = path.join(dir, 'signed.ipa');
  const fail = (code, msg) => {
    fs.rmSync(dir, { recursive: true, force: true });
    return send(res, code, { error: msg });
  };

  try {
    // 1. Принимаем IPA потоком на диск, с лимитом размера
    let received = 0;
    const limiter = async function* (src) {
      for await (const chunk of src) {
        received += chunk.length;
        if (received > cfg.maxSize) throw Object.assign(new Error('Файл слишком большой'), { code: 413 });
        yield chunk;
      }
    };
    await pipeline(req, limiter, fs.createWriteStream(input));
    if (received < 100) return fail(400, 'Пустой файл');

    // 2. Достаём метаданные
    let info;
    try { info = await readAppInfo(input); } catch (e) { return fail(400, 'Некорректный IPA: ' + e.message); }

    // 3. Подписываем
    const result = await limited(() => signer.sign(cfg, input, output));
    fs.rmSync(input, { force: true });

    const base = baseUrl(req);
    const meta = { ...info, bundleId: result.bundleId || info.bundleId, created: Date.now() };
    let ipaUrl;
    if (result.file) ipaUrl = `${base}/files/${id}.ipa`;
    else ipaUrl = result.remoteUrl;
    meta.ipaUrl = ipaUrl;
    jobs.set(id, { dir, meta });
    fs.writeFileSync(path.join(dir, 'meta.json'), JSON.stringify(meta));

    const out = { id, warnings: result.warnings || [], bundleId: result.bundleId || info.bundleId, version: info.version, name: info.name, downloadUrl: ipaUrl };
    if (result.file || result.install) {
      const manifestUrl = `${base}/manifest/${id}.plist`;
      out.installUrl = `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}`;
      out.manifestUrl = manifestUrl;
      out.https = base.startsWith('https://');
    }
    send(res, 200, out);
  } catch (e) {
    console.error('[sign]', e);
    fail(e.code === 413 ? 413 : 500, e.message);
  }
}

function loadJob(id) {
  if (!ID_RE.test(id)) return null;
  if (jobs.has(id)) return jobs.get(id);
  try { // после перезапуска сервера
    const dir = path.join(cfg.dataDir, id);
    const meta = JSON.parse(fs.readFileSync(path.join(dir, 'meta.json'), 'utf8'));
    const job = { dir, meta };
    jobs.set(id, job);
    return job;
  } catch { return null; }
}

function serveFile(req, res, file, type, name) {
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) return send(res, 404, 'Not found');
    const headers = { 'Content-Type': type, 'Content-Length': st.size, 'Cache-Control': 'no-store' };
    if (name) headers['Content-Disposition'] = `attachment; filename="${name}"`;
    res.writeHead(200, headers);
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  });
}

function serveStatic(req, res, pathname) {
  let rel = decodeURIComponent(pathname);
  if (rel === '/') rel = '/index.html';
  const file = path.normalize(path.join(publicDir, rel));
  if (!file.startsWith(publicDir + path.sep)) return send(res, 403, 'Forbidden');
  serveFile(req, res, file, MIME[path.extname(file)] || 'application/octet-stream');
}

const server = http.createServer(async (req, res) => {
  try {
    const { pathname } = new URL(req.url, 'http://x');
    let m;
    if (req.method === 'POST' && pathname === '/api/sign') return await handleSign(req, res);
    if (req.method === 'GET' && pathname === '/api/config') {
      const st = signer.status(cfg);
      return send(res, 200, {
        certSync: cfg.certApiUrl ? lastSync : null, signer: cfg.signer, ready: st.ready, reason: st.reason || null, profileExpires: st.profileExpires || null,
        tokenRequired: Boolean(cfg.token), maxSizeMB: Math.round(cfg.maxSize / 1048576),
        https: baseUrl(req).startsWith('https://'),
      });
    }
    if ((req.method === 'GET' || req.method === 'HEAD') && (m = pathname.match(/^\/manifest\/([a-f0-9]{32})\.plist$/))) {
      const job = loadJob(m[1]);
      if (!job) return send(res, 404, 'Not found');
      const xml = buildManifest({
        ipaUrl: job.meta.ipaUrl, bundleId: job.meta.bundleId,
        version: job.meta.version, title: job.meta.name,
      });
      return send(res, 200, xml, { 'Content-Type': 'text/xml; charset=utf-8' });
    }
    if ((req.method === 'GET' || req.method === 'HEAD') && (m = pathname.match(/^\/files\/([a-f0-9]{32})\.ipa$/))) {
      const job = loadJob(m[1]);
      if (!job) return send(res, 404, 'Not found');
      return serveFile(req, res, path.join(job.dir, 'signed.ipa'), 'application/octet-stream',
        job.meta.name.replace(/[^\w.-]+/g, '_') + '.ipa');
    }
    if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(req, res, pathname);
    send(res, 405, 'Method not allowed');
  } catch (e) {
    console.error(e);
    if (!res.headersSent) send(res, 500, { error: 'Внутренняя ошибка' });
  }
});

// Очистка старых заданий
const await_sync = () => runCertSync().then(() => console.log('   certs:', JSON.stringify(signer.status(cfg))));

function cleanup() {
  const now = Date.now();
  for (const name of fs.readdirSync(cfg.dataDir)) {
    if (!ID_RE.test(name)) continue;
    const dir = path.join(cfg.dataDir, name);
    try {
      if (now - fs.statSync(dir).mtimeMs > cfg.ttlMs) {
        fs.rmSync(dir, { recursive: true, force: true });
        jobs.delete(name);
      }
    } catch {}
  }
}
setInterval(cleanup, 60 * 1000).unref();
cleanup();

let lastSync = { at: null, error: null };
async function runCertSync() {
  try {
    const r = await syncOnce(cfg, (m) => console.log('[certs]', m));
    signer.resetCache();
    lastSync = { at: new Date().toISOString(), error: null, ...r };
  } catch (e) {
    lastSync = { ...lastSync, error: e.message };
    console.error('[certs] ⚠', e.message);
  }
}
if (cfg.certApiUrl) setInterval(runCertSync, cfg.certSyncMs).unref();

if (require.main === module) {
  server.requestTimeout = 0; // большие загрузки
  if (cfg.certApiUrl) await_sync();
  server.listen(cfg.port, cfg.host, () => {
    const st = signer.status(cfg);
    console.log(`🦭 Seal Installer: http://${cfg.host}:${cfg.port}`);
    console.log(`   signer: ${cfg.signer} — ${st.ready ? 'готов' : 'НЕ готов: ' + st.reason}`);
    if (!cfg.publicUrl) console.log('   ⚠ PUBLIC_URL не задан: для установки на iOS нужен HTTPS-адрес');
  });
}

module.exports = { server, cfg };
