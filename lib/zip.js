'use strict';
// Читалка ZIP/IPA на чистом Node: читает центральный каталог и достаёт нужный файл,
// не загружая весь архив в память.
const fs = require('fs');
const zlib = require('zlib');

async function readAt(fh, pos, len) {
  const buf = Buffer.alloc(len);
  const { bytesRead } = await fh.read(buf, 0, len, pos);
  return buf.subarray(0, bytesRead);
}

async function listEntries(fh, size) {
  const tailLen = Math.min(size, 0xffff + 22);
  const tail = await readAt(fh, size - tailLen, tailLen);
  let eocd = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tail.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('Это не ZIP/IPA (нет EOCD)');
  const count = tail.readUInt16LE(eocd + 10);
  const cdSize = tail.readUInt32LE(eocd + 12);
  const cdOff = tail.readUInt32LE(eocd + 16);
  if (count === 0xffff || cdSize === 0xffffffff || cdOff === 0xffffffff) {
    throw new Error('ZIP64 не поддерживается');
  }
  const cd = await readAt(fh, cdOff, cdSize);
  const entries = [];
  let p = 0;
  while (p + 46 <= cd.length && cd.readUInt32LE(p) === 0x02014b50) {
    const nameLen = cd.readUInt16LE(p + 28);
    const extraLen = cd.readUInt16LE(p + 30);
    const commentLen = cd.readUInt16LE(p + 32);
    entries.push({
      madeBy: cd.readUInt16LE(p + 4),
      extAttr: cd.readUInt32LE(p + 38),
      method: cd.readUInt16LE(p + 10),
      compSize: cd.readUInt32LE(p + 20),
      size: cd.readUInt32LE(p + 24),
      offset: cd.readUInt32LE(p + 42),
      name: cd.toString('utf8', p + 46, p + 46 + nameLen),
    });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

async function extract(fh, e, maxSize = 16 * 1024 * 1024) {
  if (e.size > maxSize) throw new Error('Файл в архиве слишком большой: ' + e.name);
  const lh = await readAt(fh, e.offset, 30);
  if (lh.readUInt32LE(0) !== 0x04034b50) throw new Error('Повреждён локальный заголовок ZIP');
  const start = e.offset + 30 + lh.readUInt16LE(26) + lh.readUInt16LE(28);
  const data = await readAt(fh, start, e.compSize);
  if (e.method === 0) return data;
  if (e.method === 8) return zlib.inflateRawSync(data);
  throw new Error('Неподдерживаемый метод сжатия ZIP: ' + e.method);
}

/** Возвращает { entries, read(name) } для файла на диске. Закройте через close(). */
async function openZip(path) {
  const fh = await fs.promises.open(path, 'r');
  try {
    const { size } = await fh.stat();
    const entries = await listEntries(fh, size);
    return {
      entries,
      read: (name) => {
        const e = entries.find((x) => x.name === name);
        if (!e) throw new Error('Нет файла в архиве: ' + name);
        return extract(fh, e);
      },
      close: () => fh.close(),
    };
  } catch (err) {
    await fh.close();
    throw err;
  }
}


// ---------- Полное чтение и запись (для подписи IPA) ----------
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(buf) {
  if (zlib.crc32) return zlib.crc32(buf) >>> 0;
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** Читает весь ZIP в память: [{ name, data, extAttr, madeBy, isDir }]. */
async function readAll(path, maxTotal = 1024 * 1024 * 1024) {
  const fh = await fs.promises.open(path, 'r');
  try {
    const { size } = await fh.stat();
    const list = await listEntries(fh, size);
    let total = 0;
    const out = [];
    for (const e of list) {
      total += e.size;
      if (total > maxTotal) throw new Error('IPA после распаковки слишком большой');
      const isDir = e.name.endsWith('/');
      out.push({
        name: e.name, extAttr: e.extAttr, madeBy: e.madeBy, isDir,
        data: isDir ? Buffer.alloc(0) : await extract(fh, e, maxTotal),
      });
    }
    return out;
  } finally {
    await fh.close();
  }
}

/** Пишет ZIP (deflate). Без ZIP64. */
async function writeZip(path, files) {
  if (files.length > 0xfffe) throw new Error('Слишком много файлов в IPA (ZIP64 не поддерживается)');
  const fh = await fs.promises.open(path, 'w');
  try {
    let pos = 0;
    const central = [];
    for (const f of files) {
      const name = Buffer.from(f.name, 'utf8');
      const raw = f.data;
      const crc = crc32(raw);
      let method = 8;
      let body = raw.length ? zlib.deflateRawSync(raw, { level: 6 }) : Buffer.alloc(0);
      if (!raw.length || body.length >= raw.length) { method = 0; body = raw; }
      if (pos + body.length > 0xfff00000) throw new Error('IPA больше 4 ГБ (ZIP64 не поддерживается)');
      const h = Buffer.alloc(30);
      h.writeUInt32LE(0x04034b50, 0);
      h.writeUInt16LE(20, 4);
      h.writeUInt16LE(0x0800, 6); // UTF-8 имена
      h.writeUInt16LE(method, 8);
      h.writeUInt16LE(0, 10);
      h.writeUInt16LE(0x21, 12); // 1980-01-01
      h.writeUInt32LE(crc, 14);
      h.writeUInt32LE(body.length, 18);
      h.writeUInt32LE(raw.length, 22);
      h.writeUInt16LE(name.length, 26);
      await fh.write(Buffer.concat([h, name, body]), 0, 30 + name.length + body.length, pos);
      central.push({ f, name, crc, method, csize: body.length, size: raw.length, offset: pos });
      pos += 30 + name.length + body.length;
    }
    const cdStart = pos;
    const parts = central.map((c) => {
      const h = Buffer.alloc(46);
      h.writeUInt32LE(0x02014b50, 0);
      h.writeUInt16LE(c.f.madeBy || 0x031e, 4);
      h.writeUInt16LE(20, 6);
      h.writeUInt16LE(0x0800, 8);
      h.writeUInt16LE(c.method, 10);
      h.writeUInt16LE(0, 12);
      h.writeUInt16LE(0x21, 14);
      h.writeUInt32LE(c.crc, 16);
      h.writeUInt32LE(c.csize, 20);
      h.writeUInt32LE(c.size, 24);
      h.writeUInt16LE(c.name.length, 28);
      h.writeUInt32LE(c.f.extAttr || (c.f.isDir ? 0x41ed0010 : 0x81a40000) >>> 0, 38);
      h.writeUInt32LE(c.offset, 42);
      return Buffer.concat([h, c.name]);
    });
    const cd = Buffer.concat(parts);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0);
    end.writeUInt16LE(central.length, 8);
    end.writeUInt16LE(central.length, 10);
    end.writeUInt32LE(cd.length, 12);
    end.writeUInt32LE(cdStart, 16);
    await fh.write(Buffer.concat([cd, end]), 0, cd.length + 22, cdStart);
  } finally {
    await fh.close();
  }
}

module.exports = { openZip, readAll, writeZip };
