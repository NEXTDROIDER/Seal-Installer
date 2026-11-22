'use strict';
// Минимальный парсер plist (бинарный bplist00 и XML) без зависимостей.

function parseBinary(buf) {
  if (buf.length < 40) throw new Error('bplist слишком короткий');
  const t = buf.length - 32;
  const offSize = buf[t + 6];
  const refSize = buf[t + 7];
  const numObjects = Number(buf.readBigUInt64BE(t + 8));
  const top = Number(buf.readBigUInt64BE(t + 16));
  const tableOff = Number(buf.readBigUInt64BE(t + 24));

  const readUInt = (pos, size) => {
    let v = 0n;
    for (let i = 0; i < size; i++) v = (v << 8n) | BigInt(buf[pos + i]);
    return v;
  };
  const offsetOf = (i) => {
    if (i >= numObjects) throw new Error('bplist: неверный индекс объекта');
    return Number(readUInt(tableOff + i * offSize, offSize));
  };

  const seen = new Set();
  function parse(idx) {
    if (seen.has(idx) && seen.size > numObjects) throw new Error('bplist: цикл');
    let pos = offsetOf(idx);
    const marker = buf[pos++];
    const type = marker >> 4;
    let n = marker & 0x0f;

    const readLen = () => {
      if (n !== 0x0f) return n;
      const m = buf[pos++];
      const size = 1 << (m & 0x0f);
      const v = Number(readUInt(pos, size));
      pos += size;
      return v;
    };

    switch (type) {
      case 0x0:
        if (marker === 0x08) return false;
        if (marker === 0x09) return true;
        return null;
      case 0x1: {
        const size = 1 << n;
        const v = readUInt(pos, size);
        return size === 8 && v >= 1n << 63n ? Number(v - (1n << 64n)) : Number(v);
      }
      case 0x2:
        return n === 2 ? buf.readFloatBE(pos) : buf.readDoubleBE(pos);
      case 0x3:
        return new Date(Date.UTC(2001, 0, 1) + buf.readDoubleBE(pos) * 1000);
      case 0x4: {
        const len = readLen();
        return Buffer.from(buf.subarray(pos, pos + len));
      }
      case 0x5: {
        const len = readLen();
        return buf.toString('latin1', pos, pos + len);
      }
      case 0x6: {
        const len = readLen();
        const raw = Buffer.from(buf.subarray(pos, pos + len * 2));
        raw.swap16();
        return raw.toString('utf16le');
      }
      case 0x8:
        return { UID: Number(readUInt(pos, n + 1)) };
      case 0xa: {
        const len = readLen();
        const arr = [];
        for (let i = 0; i < len; i++) arr.push(parse(Number(readUInt(pos + i * refSize, refSize))));
        return arr;
      }
      case 0xd: {
        const len = readLen();
        const obj = {};
        for (let i = 0; i < len; i++) {
          const k = parse(Number(readUInt(pos + i * refSize, refSize)));
          const v = parse(Number(readUInt(pos + (len + i) * refSize, refSize)));
          obj[k] = v;
        }
        return obj;
      }
      default:
        throw new Error('bplist: неизвестный тип 0x' + marker.toString(16));
    }
  }
  return parse(top);
}

const unescapeXml = (s) =>
  s
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(+d))
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');

function parseXml(text) {
  text = text
    .replace(/<\?[\s\S]*?\?>/g, '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<!DOCTYPE[\s\S]*?>/gi, '');
  const re = /<(\/?)([a-zA-Z]+)(?:\s[^>]*?)?(\/?)>|([^<]+)/g;
  const tokens = [];
  let m;
  while ((m = re.exec(text))) {
    if (m[4] !== undefined) {
      if (m[4].trim() !== '') tokens.push({ kind: 'text', text: m[4] });
    } else tokens.push({ kind: m[1] ? 'close' : m[3] ? 'self' : 'open', name: m[2] });
  }
  let i = 0;

  function value() {
    const t = tokens[i++];
    if (!t) throw new Error('plist: неожиданный конец');
    if (t.kind === 'self') {
      if (t.name === 'true') return true;
      if (t.name === 'false') return false;
      if (t.name === 'dict') return {};
      if (t.name === 'array') return [];
      return t.name === 'string' ? '' : null;
    }
    if (t.kind !== 'open') throw new Error('plist: ожидался тег');
    switch (t.name) {
      case 'plist': {
        const v = value();
        return v;
      }
      case 'dict': {
        const o = {};
        while (tokens[i] && tokens[i].kind !== 'close') {
          const k = value(); // <key>
          o[k] = value();
        }
        i++;
        return o;
      }
      case 'array': {
        const a = [];
        while (tokens[i] && tokens[i].kind !== 'close') a.push(value());
        i++;
        return a;
      }
      default: {
        let txt = '';
        if (tokens[i] && tokens[i].kind === 'text') txt = tokens[i++].text;
        if (tokens[i] && tokens[i].kind === 'close') i++;
        txt = unescapeXml(txt);
        if (t.name === 'integer') return Number(txt);
        if (t.name === 'real') return parseFloat(txt);
        if (t.name === 'date') return new Date(txt);
        if (t.name === 'data') return Buffer.from(txt.replace(/\s+/g, ''), 'base64');
        return txt; // key, string
      }
    }
  }
  return value();
}

function parsePlist(buf) {
  if (buf.subarray(0, 8).toString('latin1') === 'bplist00') return parseBinary(buf);
  return parseXml(buf.toString('utf8'));
}

const escapeXml = (s) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function buildManifest({ ipaUrl, bundleId, version, title }) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>items</key>
  <array>
    <dict>
      <key>assets</key>
      <array>
        <dict>
          <key>kind</key>
          <string>software-package</string>
          <key>url</key>
          <string>${escapeXml(ipaUrl)}</string>
        </dict>
      </array>
      <key>metadata</key>
      <dict>
        <key>bundle-identifier</key>
        <string>${escapeXml(bundleId)}</string>
        <key>bundle-version</key>
        <string>${escapeXml(version)}</string>
        <key>kind</key>
        <string>software</string>
        <key>title</key>
        <string>${escapeXml(title)}</string>
      </dict>
    </dict>
  </array>
</dict>
</plist>
`;
}

/** Сериализация значения в XML plist (строки, числа, bool, даты, Buffer, массивы, объекты). */
function buildXmlPlist(value) {
  const body = (v, ind) => {
    const t = '\t'.repeat(ind);
    if (typeof v === 'boolean') return `${t}<${v}/>\n`;
    if (typeof v === 'number') return Number.isInteger(v) ? `${t}<integer>${v}</integer>\n` : `${t}<real>${v}</real>\n`;
    if (typeof v === 'string') return `${t}<string>${escapeXml(v).replace(/"/g, '"')}</string>\n`;
    if (v instanceof Date) return `${t}<date>${v.toISOString().replace(/\.\d+Z$/, 'Z')}</date>\n`;
    if (Buffer.isBuffer(v)) return `${t}<data>${v.toString('base64')}</data>\n`;
    if (Array.isArray(v)) return v.length ? `${t}<array>\n${v.map((x) => body(x, ind + 1)).join('')}${t}</array>\n` : `${t}<array/>\n`;
    if (v && typeof v === 'object') {
      const keys = Object.keys(v);
      if (!keys.length) return `${t}<dict/>\n`;
      return `${t}<dict>\n${keys.map((k) => `${t}\t<key>${escapeXml(k).replace(/"/g, '"')}</key>\n${body(v[k], ind + 1)}`).join('')}${t}</dict>\n`;
    }
    return `${t}<string></string>\n`;
  };
  return '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n' +
    '<plist version="1.0">\n' + body(value, 0) + '</plist>\n';
}

module.exports = { parsePlist, buildManifest, escapeXml, buildXmlPlist };
