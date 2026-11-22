'use strict';
// Проверка встроенной JS-подписи: структура Mach-O signature, хеши, CMS (через openssl) и CodeResources.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync, spawnSync } = require('child_process');
const { signIpa, loadIdentity, loadProfile } = require('../lib/ipasigner');
const { readAll } = require('../lib/zip');
const { parsePlist, buildXmlPlist } = require('../lib/plist');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'seal-sign-'));
const sh = (...a) => execFileSync(a[0], a.slice(1), { cwd: tmp, stdio: 'pipe' });
const sha = (alg, b) => crypto.createHash(alg).update(b).digest();

// тестовая цепочка: CA («WWDR») -> leaf (RSA-2048)
sh('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-subj', '/CN=Test WWDR CA', '-days', '30');
sh('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'key.pem', '-out', 'leaf.csr', '-subj', '/CN=iPhone Distribution: Test/OU=TEAM123456');
sh('openssl', 'x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'cert.pem', '-days', '30');
fs.writeFileSync(path.join(tmp, 'chain.pem'), fs.readFileSync(path.join(tmp, 'ca.pem')));
const leafDer = new crypto.X509Certificate(fs.readFileSync(path.join(tmp, 'cert.pem'))).raw;

const profPlist = buildXmlPlist({
  Name: 'test', TeamIdentifier: ['TEAM123456'], ExpirationDate: new Date(Date.now() + 86400e3),
  DeveloperCertificates: [leafDer],
  Entitlements: { 'application-identifier': 'TEAM123456.*', 'get-task-allow': false, 'com.apple.developer.team-identifier': 'TEAM123456' },
});
fs.writeFileSync(path.join(tmp, 'cert.mobileprovision'), profPlist);
sh('python3', path.join(__dirname, 'make_macho_ipa.py'), path.join(tmp, 'in.ipa'));

function parseSuper(buf) {
  const lim = buf.length;
  const n = buf.readUInt32BE(8);
  const blobs = {};
  for (let i = 0; i < n; i++) {
    const slot = buf.readUInt32BE(12 + i * 8), off = buf.readUInt32BE(16 + i * 8);
    blobs[slot] = buf.subarray(off, off + buf.readUInt32BE(off + 4));
  }
  assert.strictEqual(buf.readUInt32BE(0), 0xfade0cc0);
  return blobs;
}

function checkBinary(data, { special, label }) {
  assert.strictEqual(data.readUInt32LE(0), 0xfeedfacf);
  const ncmds = data.readUInt32LE(16);
  let off = 32, sig, link;
  for (let i = 0; i < ncmds; i++) {
    const cmd = data.readUInt32LE(off), size = data.readUInt32LE(off + 4);
    if (cmd === 0x1d) sig = { dataoff: data.readUInt32LE(off + 8), datasize: data.readUInt32LE(off + 12) };
    if (cmd === 0x19 && data.toString('latin1', off + 8, off + 18) === '__LINKEDIT') {
      link = { fileoff: Number(data.readBigUInt64LE(off + 40)), filesize: Number(data.readBigUInt64LE(off + 48)), vmsize: Number(data.readBigUInt64LE(off + 32)) };
    }
    off += size;
  }
  assert.ok(sig, label + ': нет LC_CODE_SIGNATURE');
  assert.strictEqual(sig.dataoff + sig.datasize, data.length, label + ': подпись не в конце файла');
  assert.strictEqual(link.fileoff + link.filesize, data.length, label + ': __LINKEDIT не покрывает подпись');
  assert.strictEqual(link.vmsize % 0x4000, 0);
  assert.strictEqual(sig.dataoff % 16, 0);

  const blobs = parseSuper(data.subarray(sig.dataoff));
  for (const [slot, alg, hs] of [[0, 'sha1', 20], [0x1000, 'sha256', 32]]) {
    const cd = blobs[slot];
    assert.strictEqual(cd.readUInt32BE(0), 0xfade0c02);
    assert.strictEqual(cd[36], hs);
    const codeLimit = cd.readUInt32BE(32), nCode = cd.readUInt32BE(28), nSpecial = cd.readUInt32BE(24);
    assert.strictEqual(codeLimit, sig.dataoff);
    const hashOff = cd.readUInt32BE(16);
    for (let i = 0; i < nCode; i++) {
      const page = data.subarray(i * 4096, Math.min((i + 1) * 4096, codeLimit));
      assert.ok(sha(alg, page).equals(cd.subarray(hashOff + i * hs, hashOff + (i + 1) * hs)), `${label}: хеш страницы ${i} (${alg})`);
    }
    const want = special(alg, blobs);
    for (const [s, buf] of Object.entries(want)) {
      assert.ok(sha(alg, buf).equals(cd.subarray(hashOff - s * hs, hashOff - (s - 1) * hs)), `${label}: special slot ${s} (${alg})`);
    }
    assert.ok(nSpecial >= Math.max(0, ...Object.keys(want).map(Number)));
  }
  // CMS: проверяем подпись openssl-ом; контент — основной CodeDirectory
  fs.writeFileSync(path.join(tmp, 'cd.bin'), blobs[0]);
  fs.writeFileSync(path.join(tmp, 'sig.der'), blobs[0x10000].subarray(8));
  const v = spawnSync('openssl', ['cms', '-verify', '-inform', 'DER', '-in', 'sig.der', '-content', 'cd.bin', '-binary', '-CAfile', 'ca.pem', '-purpose', 'any'], { cwd: tmp, encoding: 'utf8' });
  assert.strictEqual(v.status, 0, label + ': openssl cms -verify: ' + v.stderr);
  return blobs;
}

(async () => {
  const identity = loadIdentity(tmp, '');
  const profile = loadProfile(path.join(tmp, 'cert.mobileprovision'));
  assert.strictEqual(identity.certs.length, 2);
  const res = await signIpa(path.join(tmp, 'in.ipa'), path.join(tmp, 'out.ipa'), { identity, profile });
  assert.strictEqual(res.signed, 3);
  console.log('signIpa:', JSON.stringify(res));

  const files = new Map((await readAll(path.join(tmp, 'out.ipa'))).map((e) => [e.name, e]));
  const app = 'Payload/Demo.app/';
  assert.ok(files.has(app + 'embedded.mobileprovision'));
  assert.ok(files.has(app + '_CodeSignature/CodeResources'));
  assert.ok(files.has(app + 'Frameworks/Fw.framework/_CodeSignature/CodeResources'));
  assert.strictEqual((files.get(app + 'Demo').extAttr >>> 16) & 0o777, 0o755, 'права исполняемого файла сохранены');

  const infoBuf = files.get(app + 'Info.plist').data;
  const cr = files.get(app + '_CodeSignature/CodeResources').data;
  const crObj = parsePlist(cr);
  assert.ok(!(app + 'Demo' in crObj.files) && !('Demo' in crObj.files2), 'главный exe не в CodeResources');
  assert.ok(crObj.files2['Frameworks/libx.dylib'].hash2.equals(sha('sha256', files.get(app + 'Frameworks/libx.dylib').data)), 'хеш подписанного dylib в CodeResources');
  assert.ok(crObj.files['PkgInfo'] && !crObj.files2['PkgInfo'], 'PkgInfo только в files (omit в rules2)');
  assert.ok(crObj.files2['en.lproj/Localizable.strings'].optional);
  assert.ok(!('Info.plist' in crObj.files2) && 'Info.plist' in crObj.files);
  assert.ok(crObj.files2['Frameworks/Fw.framework/_CodeSignature/CodeResources']);

  const entsBlobWant = (b) => b[5];
  const main = checkBinary(files.get(app + 'Demo').data, {
    label: 'main',
    special: (alg, b) => ({ 1: infoBuf, 2: b[2], 3: cr, 5: b[5] }),
  });
  const ent = parsePlist(main[5].subarray(8));
  assert.strictEqual(ent['application-identifier'], 'TEAM123456.*');
  const cd = main[0];
  assert.strictEqual(cd.readUInt32BE(8), 0x20400);
  assert.strictEqual(cd.readBigUInt64BE(80) & 1n, 1n, 'execSegFlags: main binary');
  assert.strictEqual(cd.toString('utf8', cd.readUInt32BE(20), cd.readUInt32BE(20) + 16), 'com.example.demo');
  assert.strictEqual(cd.toString('utf8', cd.readUInt32BE(48), cd.readUInt32BE(48) + 10), 'TEAM123456');

  const fwInfo = files.get(app + 'Frameworks/Fw.framework/Info.plist').data;
  const fwCr = files.get(app + 'Frameworks/Fw.framework/_CodeSignature/CodeResources').data;
  checkBinary(files.get(app + 'Frameworks/Fw.framework/Fw').data, { label: 'framework', special: (a, b) => ({ 1: fwInfo, 2: b[2], 3: fwCr }) });
  checkBinary(files.get(app + 'Frameworks/libx.dylib').data, { label: 'dylib', special: (a, b) => ({ 2: b[2] }) });

  // Повторная подпись уже подписанного IPA должна работать (старая подпись снимается)
  await signIpa(path.join(tmp, 'out.ipa'), path.join(tmp, 'out2.ipa'), { identity, profile });
  const again = new Map((await readAll(path.join(tmp, 'out2.ipa'))).map((e) => [e.name, e]));
  const d2 = again.get(app + 'Demo').data;
  assert.ok(d2.length < files.get(app + 'Demo').data.length + 64, 'подпись не наслаивается');

  // Истёкший профиль должен давать понятную ошибку
  const exp = { ...profile, data: { ...profile.data, ExpirationDate: new Date(Date.now() - 1000) } };
  await assert.rejects(() => signIpa(path.join(tmp, 'in.ipa'), path.join(tmp, 'x.ipa'), { identity, profile: exp }), /Профиль .* истёк/);

  console.log('SIGN OK');
  fs.rmSync(tmp, { recursive: true, force: true });
})().catch((e) => { console.error(e); console.error('tmp:', tmp); process.exit(1); });
