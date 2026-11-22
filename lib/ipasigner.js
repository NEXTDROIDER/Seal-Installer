'use strict';
// Подпись IPA целиком на JS: Mach-O, CodeResources, embedded.mobileprovision, entitlements.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { readAll, writeZip } = require('./zip');
const { parsePlist, buildXmlPlist } = require('./plist');
const { signMachO, isMachO } = require('./macho');

const sha = (alg, b) => crypto.createHash(alg).update(b).digest();

// ---------- сертификат и профиль ----------

const KEY_RE = /-----BEGIN (?:[A-Z ]*)PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z ]*)PRIVATE KEY-----/;
const CERT_RE = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

function p12ToPem(p12, password) {
  const base = ['pkcs12', '-in', p12, '-nodes', '-passin', 'env:SEAL_P12_PASS'];
  const env = { ...process.env, SEAL_P12_PASS: password || '' };
  let last = '';
  for (const extra of [['-legacy'], []]) { // p12 от Apple часто в старом шифровании
    const r = spawnSync('openssl', [...base, ...extra], { env, encoding: 'utf8' });
    if (r.error) throw new Error('Нужен openssl (pkg install openssl-tool) для чтения .p12: ' + r.error.message);
    if (r.status === 0 && KEY_RE.test(r.stdout)) return r.stdout;
    last = r.stderr;
  }
  throw new Error('Не удалось прочитать cert.p12 (неверный пароль?): ' + last.trim().split('\n').pop());
}

/** Ищет в certDir: identity.pem | key.pem+cert.pem | cert.p12. Возвращает { key, certs, leaf }. */
function loadIdentity(certDir, password) {
  const f = (n) => path.join(certDir, n);
  let pem = '';
  if (fs.existsSync(f('identity.pem'))) pem = fs.readFileSync(f('identity.pem'), 'utf8');
  else if (fs.existsSync(f('key.pem')) && fs.existsSync(f('cert.pem'))) {
    pem = fs.readFileSync(f('key.pem'), 'utf8') + '\n' + fs.readFileSync(f('cert.pem'), 'utf8');
    if (fs.existsSync(f('chain.pem'))) pem += '\n' + fs.readFileSync(f('chain.pem'), 'utf8');
  } else if (fs.existsSync(f('cert.p12'))) pem = p12ToPem(f('cert.p12'), password);
  else throw new Error(`В ${certDir} нет cert.p12 (или key.pem + cert.pem)`);

  const keyPem = (pem.match(KEY_RE) || [])[0];
  if (!keyPem) throw new Error('Приватный ключ не найден');
  const key = crypto.createPrivateKey({ key: keyPem, passphrase: password || undefined });
  const certs = (pem.match(CERT_RE) || []).map((c) => new crypto.X509Certificate(c));
  const leafIdx = certs.findIndex((c) => c.checkPrivateKey(key));
  if (leafIdx < 0) throw new Error('Ни один сертификат не соответствует приватному ключу');
  const [leaf] = certs.splice(leafIdx, 1);
  return { key, certs: [leaf, ...certs], leaf };
}

function loadProfile(file) {
  const buf = fs.readFileSync(file);
  const a = buf.indexOf('<?xml');
  const b = buf.lastIndexOf('</plist>');
  if (a < 0 || b < 0) throw new Error('Не удалось разобрать .mobileprovision');
  const prof = parsePlist(buf.subarray(a, b + 8));
  return { raw: buf, data: prof, ents: prof.Entitlements || {}, team: (prof.TeamIdentifier || [])[0] || '' };
}

/** Проверки, о которых лучше узнать до подписи, а не после неудачной установки. */
function checkIdentity(identity, profile) {
  const warnings = [];
  const now = Date.now();
  const leafEnd = Date.parse(identity.leaf.validTo);
  if (leafEnd < now) throw new Error(`Сертификат истёк ${identity.leaf.validTo}`);
  const exp = profile.data.ExpirationDate;
  if (exp && new Date(exp).getTime() < now) throw new Error(`Профиль (.mobileprovision) истёк ${new Date(exp).toISOString()}`);
  const devCerts = profile.data.DeveloperCertificates || [];
  if (devCerts.length && !devCerts.some((d) => Buffer.isBuffer(d) && d.equals(identity.leaf.raw))) {
    warnings.push('Сертификат не входит в DeveloperCertificates профиля — iOS отклонит установку');
  }
  if (identity.certs.length < 2) warnings.push('В цепочке нет промежуточного сертификата Apple WWDR');
  return warnings;
}

// ---------- CodeResources ----------

const RULES = {
  '^.*': true,
  '^.*\\.lproj/': { optional: true, weight: 1000 },
  '^.*\\.lproj/locversion.plist$': { omit: true, weight: 1100 },
  '^Base\\.lproj/': { weight: 1010 },
  '^version.plist$': true,
};
const RULES2 = {
  '.*\\.dSYM($|/)': { weight: 11 },
  '^(.*/)?\\.DS_Store$': { omit: true, weight: 2000 },
  '^.*': true,
  '^.*\\.lproj/': { optional: true, weight: 1000 },
  '^.*\\.lproj/locversion.plist$': { omit: true, weight: 1100 },
  '^Base\\.lproj/': { weight: 1010 },
  '^Info\\.plist$': { omit: true, weight: 20 },
  '^PkgInfo$': { omit: true, weight: 20 },
  '^embedded\\.provisioning\\.profile$': { weight: 20 },
  '^version\\.plist$': { weight: 20 },
};

function buildCodeResources(entries) {
  const files = {};
  const files2 = {};
  for (const { rel, data } of entries) {
    if (/(^|\/)\.DS_Store$/.test(rel)) continue;
    const h1 = sha('sha1', data);
    const h2 = sha('sha256', data);
    const lproj = /\.lproj\//.test(rel);
    if (/\.lproj\/locversion\.plist$/.test(rel)) continue;
    files[rel] = lproj ? { hash: h1, optional: true } : h1;
    if (rel !== 'Info.plist' && rel !== 'PkgInfo') {
      files2[rel] = lproj ? { hash: h1, hash2: h2, optional: true } : { hash: h1, hash2: h2 };
    }
  }
  return Buffer.from(buildXmlPlist({ files, files2, rules: RULES, rules2: RULES2 }), 'utf8');
}

// ---------- основная функция ----------

const BUNDLE_RE = /\.(app|appex|framework|xpc)$/;

/**
 * @param opts { identity, profile, bundleId? (принудительный id), log? }
 */
async function signIpa(inputPath, outputPath, opts) {
  const { identity, profile } = opts;
  const log = opts.log || (() => {});
  const warnings = checkIdentity(identity, profile);

  const entries = await readAll(inputPath);
  const files = new Map(); // name -> entry (только файлы)
  const order = [];
  for (const e of entries) {
    if (e.name.startsWith('__MACOSX/')) continue;
    if (e.isDir) { order.push(e); continue; }
    files.set(e.name, e);
    order.push(e);
  }

  const appDirs = [...new Set([...files.keys()].map((n) => n.match(/^Payload\/[^/]+\.app\//)?.[0]).filter(Boolean))];
  if (appDirs.length !== 1) throw new Error('В IPA должен быть ровно один Payload/*.app');
  const appDir = appDirs[0];

  // Бандлы = каталоги с Info.plist и подходящим расширением
  const bundles = [];
  for (const name of files.keys()) {
    const m = name.match(/^(.*\.(?:app|appex|framework|xpc))\/Info\.plist$/);
    if (m) bundles.push(m[1] + '/');
  }
  bundles.sort((a, b) => b.split('/').length - a.split('/').length); // самые глубокие первыми
  if (!bundles.includes(appDir)) throw new Error('Нет Info.plist у основного приложения');

  const owner = (name) => bundles.find((b) => name.startsWith(b)); // ближайший бандл (самый глубокий)

  // --- смена bundle id под профиль (если профиль не wildcard)
  const appInfoPath = appDir + 'Info.plist';
  const appInfo = parsePlist(files.get(appInfoPath).data);
  const origId = appInfo.CFBundleIdentifier;
  const profId = String(profile.ents['application-identifier'] || '').replace(/^[A-Z0-9]+\./, '');
  let newId = opts.bundleId || (profId && !profId.includes('*') ? profId : origId);
  if (profId.includes('*') && !opts.bundleId) newId = origId;
  if (newId !== origId) {
    log(`Bundle id: ${origId} → ${newId}`);
    for (const b of bundles) {
      if (!/\.(app|appex)\/$/.test(b)) continue;
      const ip = b + 'Info.plist';
      const info = parsePlist(files.get(ip).data);
      const id = info.CFBundleIdentifier;
      if (id === origId) info.CFBundleIdentifier = newId;
      else if (typeof id === 'string' && id.startsWith(origId + '.')) info.CFBundleIdentifier = newId + id.slice(origId.length);
      else continue;
      if (info.WKCompanionAppBundleIdentifier === origId) info.WKCompanionAppBundleIdentifier = newId;
      files.get(ip).data = Buffer.from(buildXmlPlist(info), 'utf8');
    }
  }

  // --- удаляем старые подписи, ставим профиль
  for (const name of [...files.keys()]) {
    if (/(^|\/)_CodeSignature\//.test(name) || /(^|\/)embedded\.mobileprovision$/.test(name)) {
      files.delete(name);
    }
  }
  const prof = { name: '', extAttr: 0x81a40000, isDir: false, data: profile.raw };
  for (const b of bundles) {
    if (/\.(app|appex)\/$/.test(b)) files.set(b + 'embedded.mobileprovision', { ...prof, name: b + 'embedded.mobileprovision' });
  }

  const entsXml = buildXmlPlist(profile.ents);
  const getTaskAllow = profile.ents['get-task-allow'] === true;
  const newFiles = new Map(); // бинарники и ресурсы, добавленные при подписи

  let signed = 0;
  for (const b of bundles) {
    const info = parsePlist(files.get(b + 'Info.plist').data);
    const exeName = info.CFBundleExecutable;
    const exePath = exeName ? b + exeName : null;
    const isApp = /\.(app|appex)\/$/.test(b);
    const bundleId = info.CFBundleIdentifier || path.basename(b);
    const own = [...files.keys()].filter((n) => n.startsWith(b) && owner(n) === b);

    // 1) все Mach-O этого бандла, кроме главного исполняемого (dylib и т. п.)
    for (const n of own) {
      if (n === exePath || n.endsWith('/')) continue;
      const e = files.get(n);
      if (e.data.length < 8 || !isMachO(e.data)) continue;
      e.data = signMachO(e.data, { ident: path.basename(n), team: profile.team, identity, getTaskAllow });
      signed++;
    }

    // 2) CodeResources по всем файлам бандла (включая вложенные), кроме главного exe
    const sealed = [];
    for (const [n, e] of files) {
      if (!n.startsWith(b) || n === exePath) continue;
      sealed.push({ rel: n.slice(b.length), data: e.data });
    }
    sealed.sort((x, y) => (x.rel < y.rel ? -1 : 1));
    const codeRes = buildCodeResources(sealed);
    const crName = b + '_CodeSignature/CodeResources';
    files.set(crName, { name: crName, extAttr: 0x81a40000, isDir: false, data: codeRes });

    // 3) главный исполняемый файл
    if (exePath && files.has(exePath) && isMachO(files.get(exePath).data)) {
      const e = files.get(exePath);
      e.data = signMachO(e.data, {
        ident: bundleId, team: profile.team, identity,
        entitlements: isApp ? entsXml : null,
        infoPlist: files.get(b + 'Info.plist').data,
        codeResources: codeRes,
        isMain: b === appDir || /\.appex\/$/.test(b),
        getTaskAllow,
      });
      signed++;
      log(`Подписан ${exePath}`);
    } else if (exePath) {
      warnings.push(`Нет исполняемого файла ${exePath}`);
    }
  }

  // --- сборка нового ZIP: порядок как в оригинале, затем новые файлы
  const out = [];
  const written = new Set();
  for (const e of order) {
    if (e.isDir) { out.push(e); continue; }
    const cur = files.get(e.name);
    if (cur) { out.push({ ...cur, name: e.name }); written.add(e.name); }
  }
  for (const [n, e] of files) if (!written.has(n)) out.push({ ...e, name: n });
  await writeZip(outputPath, out);
  return { bundleId: newId, signed, warnings };
}

module.exports = { signIpa, loadIdentity, loadProfile, checkIdentity };
