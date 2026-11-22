'use strict';
// Интеграционный тест: python3 делает IPA, fake-zsign.sh имитирует подпись.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'seal-'));
fs.mkdirSync(path.join(tmp, 'certs'));
fs.writeFileSync(path.join(tmp, 'certs/cert.p12'), 'x');
fs.writeFileSync(path.join(tmp, 'certs/cert.mobileprovision'), 'x');
Object.assign(process.env, {
  CERT_DIR: path.join(tmp, 'certs'), DATA_DIR: path.join(tmp, 'data'), CERT_PASSWORD: 'pw',
  ZSIGN_BIN: path.join(__dirname, 'fake-zsign.sh'), SIGNER: 'zsign',
  PUBLIC_URL: 'https://example.test', ACCESS_TOKEN: 'secret',
});
const { server } = require('../server');

(async () => {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;

  const cfg = await (await fetch(base + '/api/config')).json();
  assert.strictEqual(cfg.ready, true);
  assert.strictEqual(cfg.tokenRequired, true);

  for (const fmt of ['bin', 'xml']) {
    const ipa = path.join(tmp, fmt + '.ipa');
    execFileSync('python3', [path.join(__dirname, 'make_ipa.py'), ipa, fmt]);
    const body = fs.readFileSync(ipa);

    let r = await fetch(base + '/api/sign', { method: 'POST', body });
    assert.strictEqual(r.status, 401, 'без токена должен быть 401');

    r = await fetch(base + '/api/sign', { method: 'POST', body, headers: { 'x-token': 'secret' } });
    const d = await r.json();
    assert.strictEqual(r.status, 200, JSON.stringify(d));
    assert.strictEqual(d.bundleId, 'com.example.Тест&App');
    assert.strictEqual(d.version, '1.2.3');
    assert.ok(d.installUrl.startsWith('itms-services://?action=download-manifest&url=https%3A%2F%2Fexample.test%2Fmanifest%2F'));

    const mf = await (await fetch(base + `/manifest/${d.id}.plist`)).text();
    assert.ok(mf.includes('com.example.Тест&amp;App') && mf.includes(`https://example.test/files/${d.id}.ipa`));
    assert.ok(mf.includes('Demo &lt;App&gt;'));

    const f = await fetch(base + `/files/${d.id}.ipa`);
    assert.strictEqual(f.status, 200);
    assert.ok(Buffer.from(await f.arrayBuffer()).equals(body));
    console.log('ok', fmt);
  }

  let r = await fetch(base + '/api/sign', { method: 'POST', body: 'not a zip at all, just some text '.repeat(10), headers: { 'x-token': 'secret' } });
  assert.strictEqual(r.status, 400);
  assert.strictEqual((await fetch(base + '/files/../../etc/passwd')).status, 404);
  for (const u of ['/%2e%2e/server.js', '/..%2fserver.js', '/%2e%2e%2f%2e%2e%2fetc/passwd']) {
    const t = await fetch(base + u);
    assert.ok([403, 404].includes(t.status), u + ' -> ' + t.status);
    assert.ok(!(await t.text()).includes('require('), 'утечка исходников через ' + u);
  }
  assert.strictEqual((await fetch(base + '/')).status, 200);
  console.log('ALL OK');
  server.close(); fs.rmSync(tmp, { recursive: true, force: true });
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
