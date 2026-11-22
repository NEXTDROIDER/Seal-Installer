'use strict';
// Минимальный DER-энкодер/ридер для сборки CMS-подписи.

const lenBytes = (n) =>
  n < 0x80 ? Buffer.from([n])
  : n < 0x100 ? Buffer.from([0x81, n])
  : n < 0x10000 ? Buffer.from([0x82, n >> 8, n & 255])
  : Buffer.from([0x83, n >> 16, (n >> 8) & 255, n & 255]);

const tlv = (tag, ...parts) => {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), lenBytes(body.length), body]);
};

const seq = (...p) => tlv(0x30, ...p);
const set = (...p) => tlv(0x31, ...p);
const octet = (b) => tlv(0x04, b);
const nul = Buffer.from([0x05, 0x00]);

function oid(str) {
  const parts = str.split('.').map(Number);
  const out = [40 * parts[0] + parts[1]];
  for (const n of parts.slice(2)) {
    const stack = [n & 0x7f];
    for (let v = Math.floor(n / 128); v > 0; v = Math.floor(v / 128)) stack.unshift((v & 0x7f) | 0x80);
    out.push(...stack);
  }
  return tlv(0x06, Buffer.from(out));
}

function integer(n) {
  const bytes = [];
  do { bytes.unshift(n & 255); n = Math.floor(n / 256); } while (n > 0);
  if (bytes[0] & 0x80) bytes.unshift(0);
  return tlv(0x02, Buffer.from(bytes));
}

function utcTime(d) {
  const p = (x) => String(x).padStart(2, '0');
  const s = `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}` +
    `${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0x17, Buffer.from(s, 'ascii'));
}

/** SET OF: элементы сортируются по байтам (требование DER). */
const sortedSetBody = (items) => items.slice().sort(Buffer.compare);

/** Читает один TLV с позиции pos. */
function read(buf, pos) {
  const tag = buf[pos];
  let len = buf[pos + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[pos + 2 + i];
    hdr = 2 + n;
  }
  return { tag, hdr, len, start: pos, end: pos + hdr + len, raw: buf.subarray(pos, pos + hdr + len) };
}

/** Из DER сертификата достаёт serialNumber и issuer (как готовые TLV). */
function certIssuerSerial(der) {
  const cert = read(der, 0);
  const tbs = read(der, cert.start + cert.hdr);
  let p = tbs.start + tbs.hdr;
  let item = read(der, p);
  if (item.tag === 0xa0) { p = item.end; item = read(der, p); } // version
  const serial = item;
  p = serial.end;
  const sigAlg = read(der, p);
  p = sigAlg.end;
  const issuer = read(der, p);
  return { serial: serial.raw, issuer: issuer.raw };
}

module.exports = { tlv, seq, set, octet, nul, oid, integer, utcTime, sortedSetBody, read, certIssuerSerial };
