'use strict';
// Сквозной тест: cert.p12 -> сервер (SIGNER=js) -> подписанный IPA и manifest.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'seal-srv-'));
const sh = (...a) => execFileSync(a[0], a.slice(1), { cwd: tmp, stdio: 'pipe' });
fs.mkdirSync(path.join(tmp, 'certs'));
sh('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'k.pem', '-out', 'c.pem', '-subj', '/CN=Test/OU=TEAM123456', '-days', '2');
sh('openssl', 'pkcs12', '-export', '-inkey', 'k.pem', '-in', 'c.pem', '-out', 'certs/cert.p12', '-passout', 'pass:pw');
const { buildXmlPlist } = require('../lib/plist');
fs.writeFileSync(path.join(tmp, 'certs/cert.mobileprovision'), buildXmlPlist({
  TeamIdentifier: ['TEAM123456'], ExpirationDate: new Date(Date.now() + 86400e3),
  Entitlements: { 'application-identifier': 'TEAM123456.com.example.custom', 'get-task-allow': true },
}));
fs.writeFileSync(path.join(tmp, 'certs/password.txt'), 'pw');
sh('python3', path.join(__dirname, 'make_macho_ipa.py'), path.join(tmp, 'in.ipa'));
Object.assign(process.env, { CERT_DIR: path.join(tmp, 'certs'), DATA_DIR: path.join(tmp, 'data'), PUBLIC_URL: 'https://example.test' });
delete process.env.SIGNER;
const { server } = require('../server');
const { readAll } = require('../lib/zip');
const { parsePlist } = require('../lib/plist');

(async () => {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const cfg = await (await fetch(base + '/api/config')).json();
  assert.strictEqual(cfg.signer, 'js');
  assert.strictEqual(cfg.ready, true, cfg.reason);
  const r = await fetch(base + '/api/sign', { method: 'POST', body: fs.readFileSync(path.join(tmp, 'in.ipa')) });
  const d = await r.json();
  assert.strictEqual(r.status, 200, JSON.stringify(d));
  assert.strictEqual(d.bundleId, 'com.example.custom', 'bundle id приведён к профилю');
  assert.ok(d.warnings.length >= 1, 'предупреждение про цепочку WWDR');
  const mf = await (await fetch(base + `/manifest/${d.id}.plist`)).text();
  assert.ok(mf.includes('<string>com.example.custom</string>'));
  fs.writeFileSync(path.join(tmp, 'dl.ipa'), Buffer.from(await (await fetch(base + `/files/${d.id}.ipa`)).arrayBuffer()));
  const files = new Map((await readAll(path.join(tmp, 'dl.ipa'))).map((e) => [e.name, e]));
  assert.strictEqual(parsePlist(files.get('Payload/Demo.app/Info.plist').data).CFBundleIdentifier, 'com.example.custom');
  console.log('SERVER JS OK');
  server.close(); fs.rmSync(tmp, { recursive: true, force: true }); process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
