'use strict';
// Мок вашего API: отозванный, с истёкшим профилем и рабочий сертификат; доступ по токену.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { execFileSync } = require('child_process');
const { buildXmlPlist } = require('../lib/plist');
const { syncOnce } = require('../lib/certsync');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'seal-cs-'));
const sh = (...a) => execFileSync(a[0], a.slice(1), { cwd: tmp, stdio: 'pipe' });
sh('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'k.pem', '-out', 'c.pem', '-subj', '/CN=T/OU=TEAMABCDEF', '-days', '2');
sh('openssl', 'pkcs12', '-export', '-inkey', 'k.pem', '-in', 'c.pem', '-out', 'good.p12', '-passout', 'pass:s3cret');
const p12 = fs.readFileSync(path.join(tmp, 'good.p12'));
const prof = (d) => Buffer.from(buildXmlPlist({ TeamIdentifier: ['TEAMABCDEF'], ExpirationDate: new Date(Date.now() + d), Entitlements: {} }));

const srv = http.createServer((req, res) => {
  if (req.headers.authorization !== 'Bearer tok') { res.statusCode = 401; return res.end('no'); }
  const u = req.url;
  if (u.startsWith('/api/certificates/list/signed/')) {
    res.setHeader('content-type', 'application/json');
    return res.end(JSON.stringify({ certificates: [
      { name: 'revoked-one', status: 'revoked', p12: '/f/good.p12', mobileprovision: '/f/ok.mobileprovision', password: 's3cret' },
      { name: 'expired-profile', status: 'signed', p12Url: '/f/good.p12', provisionUrl: '/f/old.mobileprovision', password: 's3cret' },
      { id: 4, name: 'meta-only', status: 'Signed', valid_to: 'Jun 23 08:49:28 2037 GMT', folder_name: 'Mycert1', nickname: 'X' },
      { name: 'good', status: 'signed', files: { p12: '/f/good.p12', mobileprovision: prof(86400e3).toString('base64').padEnd(300, ' ') }, password: 's3cret' },
    ] }));
  }
  if (u === '/api/certificates/download/4/cert.p12') return res.end(p12);
  if (u === '/api/certificates/download/4/cert.mobileprovision') return res.end(prof(86400e3));
  if (u === '/api/certificates/download/4/password.txt') return res.end('s3cret\n');
  if (u === '/f/good.p12') return res.end(p12);
  if (u === '/f/ok.mobileprovision') return res.end(prof(86400e3));
  if (u === '/f/old.mobileprovision') return res.end(prof(-1000));
  res.statusCode = 404; res.end();
});

(async () => {
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const cfg = { certApiUrl: `http://127.0.0.1:${srv.address().port}`, certApiPath: '/api/certificates/list/signed/5', certApiAuth: 'Bearer tok', certP12File: 'cert.p12', certProfileFile: 'cert.mobileprovision', certPassFile: 'password.txt', certDir: path.join(tmp, 'certs') };
  const r = await syncOnce(cfg, () => {});
  assert.strictEqual(r.name, 'meta-only', 'файлы из /api/certificates/download/<id>');
  assert.strictEqual(r.team, 'TEAMABCDEF');
  assert.strictEqual(fs.readFileSync(path.join(tmp, 'certs/password.txt'), 'utf8'), 's3cret');
  await assert.rejects(() => syncOnce({ ...cfg, certApiAuth: 'Bearer bad' }, () => {}), /401/);
  console.log('CERTSYNC OK');
  srv.close(); fs.rmSync(tmp, { recursive: true, force: true }); process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
