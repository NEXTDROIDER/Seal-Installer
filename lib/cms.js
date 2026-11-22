'use strict';
// CMS SignedData (detached) в формате, который ожидает Apple для code signature.
const crypto = require('crypto');
const der = require('./der');

const OID = {
  signedData: '1.2.840.113549.1.7.2',
  data: '1.2.840.113549.1.7.1',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingTime: '1.2.840.113549.1.9.5',
  sha256: '2.16.840.1.101.3.4.2.1',
  rsa: '1.2.840.113549.1.1.1',
  appleCdHashes: '1.2.840.113635.100.9.1',
  appleCdHashes2: '1.2.840.113635.100.9.2',
};

function cdhashesPlist(hashes) {
  const data = hashes.map((h) => `\t\t<data>\n\t\t${h.toString('base64')}\n\t\t</data>`).join('\n');
  return Buffer.from(
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n' +
    '<plist version="1.0">\n<dict>\n\t<key>cdhashes</key>\n\t<array>\n' + data + '\n\t</array>\n</dict>\n</plist>\n');
}

/**
 * @param cd1        Buffer — основной CodeDirectory (SHA-1), он же «подписываемый контент»
 * @param cdhashes   { sha1: Buffer(20), sha256: Buffer(32) } — cdhash обоих CodeDirectory
 * @param identity   { key: KeyObject, certs: X509Certificate[] (leaf первым) }
 */
function buildCms(cd1, cdhashes, identity, now = new Date()) {
  const leaf = identity.certs[0];
  if (identity.key.asymmetricKeyType !== 'rsa') throw new Error('Поддерживаются только RSA-ключи');

  const attrs = [
    der.seq(der.oid(OID.contentType), der.set(der.oid(OID.data))),
    der.seq(der.oid(OID.signingTime), der.set(der.utcTime(now))),
    der.seq(der.oid(OID.messageDigest), der.set(der.octet(crypto.createHash('sha256').update(cd1).digest()))),
    der.seq(der.oid(OID.appleCdHashes),
      der.set(der.octet(cdhashesPlist([cdhashes.sha1, cdhashes.sha256.subarray(0, 20)])))),
    der.seq(der.oid(OID.appleCdHashes2),
      der.set(der.seq(der.seq(der.oid(OID.sha256), der.octet(cdhashes.sha256))))),
  ];
  const sorted = der.sortedSetBody(attrs);
  const toSign = der.tlv(0x31, ...sorted);
  const signature = crypto.sign('sha256', toSign, identity.key);

  const { issuer, serial } = der.certIssuerSerial(leaf.raw);
  const sha256Alg = der.seq(der.oid(OID.sha256), der.nul);
  const signerInfo = der.seq(
    der.integer(1),
    der.seq(issuer, serial),
    sha256Alg,
    der.tlv(0xa0, ...sorted),
    der.seq(der.oid(OID.rsa), der.nul),
    der.octet(signature),
  );

  const signedData = der.seq(
    der.integer(1),
    der.set(sha256Alg),
    der.seq(der.oid(OID.data)),
    der.tlv(0xa0, ...identity.certs.map((c) => c.raw)),
    der.set(signerInfo),
  );
  return der.seq(der.oid(OID.signedData), der.tlv(0xa0, signedData));
}

module.exports = { buildCms };
