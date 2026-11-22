'use strict';
// Подпись Mach-O (thin arm64 и fat) на чистом JS: CodeDirectory (SHA-1 + SHA-256), requirements,
// entitlements и CMS-подпись.
const crypto = require('crypto');
const { buildCms } = require('./cms');

const MH_MAGIC_64 = 0xfeedfacf;
const FAT_MAGIC = 0xcafebabe;
const LC_SEGMENT_64 = 0x19;
const LC_CODE_SIGNATURE = 0x1d;
const MH_EXECUTE = 2;
const PAGE = 4096;

const CSMAGIC = { superblob: 0xfade0cc0, cd: 0xfade0c02, req: 0xfade0c01, ent: 0xfade7171, cms: 0xfade0b01 };
const SLOT = { cd: 0, req: 2, ent: 5, altCd: 0x1000, cms: 0x10000 };

const sha = (alg, b) => crypto.createHash(alg).update(b).digest();
const alignUp = (n, a) => Math.ceil(n / a) * a;

/** Быстрая проверка: похоже ли содержимое на Mach-O (thin 64 или fat). */
function isMachO(buf) {
  if (buf.length < 8) return false;
  if (buf.readUInt32LE(0) === MH_MAGIC_64) return true;
  if (buf.readUInt32BE(0) === FAT_MAGIC) {
    const n = buf.readUInt32BE(4);
    if (n === 0 || n > 8 || buf.length < 8 + n * 20) return false;
    for (let i = 0; i < n; i++) {
      const off = buf.readUInt32BE(8 + i * 20 + 8);
      if (off + 4 > buf.length) return false;
      const m = buf.readUInt32LE(off);
      if (m !== MH_MAGIC_64 && m !== 0xfeedface) return false;
    }
    return true;
  }
  return false;
}

function blob(magic, body) {
  const h = Buffer.alloc(8);
  h.writeUInt32BE(magic, 0);
  h.writeUInt32BE(8 + body.length, 4);
  return Buffer.concat([h, body]);
}

const emptyRequirements = () => {
  const b = Buffer.alloc(12);
  b.writeUInt32BE(CSMAGIC.req, 0);
  b.writeUInt32BE(12, 4);
  return b; // count = 0
};

function buildCodeDirectory({ alg, ident, team, specials, data, codeLimit, execBase, execLimit, execFlags }) {
  const hashSize = alg === 'sha1' ? 20 : 32;
  const nSpecial = Math.max(0, ...Object.keys(specials).map(Number));
  const nCode = Math.ceil(codeLimit / PAGE);
  const identBuf = Buffer.from(ident + '\0');
  const teamBuf = team ? Buffer.from(team + '\0') : Buffer.alloc(0);
  const HEADER = 88;
  const identOff = HEADER;
  const teamOff = team ? identOff + identBuf.length : 0;
  const hashOff = HEADER + identBuf.length + teamBuf.length + nSpecial * hashSize;
  const total = hashOff + nCode * hashSize;

  const cd = Buffer.alloc(total);
  cd.writeUInt32BE(CSMAGIC.cd, 0);
  cd.writeUInt32BE(total, 4);
  cd.writeUInt32BE(0x20400, 8);
  cd.writeUInt32BE(0, 12); // flags
  cd.writeUInt32BE(hashOff, 16);
  cd.writeUInt32BE(identOff, 20);
  cd.writeUInt32BE(nSpecial, 24);
  cd.writeUInt32BE(nCode, 28);
  cd.writeUInt32BE(codeLimit, 32);
  cd[36] = hashSize;
  cd[37] = alg === 'sha1' ? 1 : 2;
  cd[38] = 0; // platform
  cd[39] = 12; // log2(4096)
  cd.writeUInt32BE(0, 40); // spare2
  cd.writeUInt32BE(0, 44); // scatterOffset
  cd.writeUInt32BE(teamOff, 48);
  cd.writeUInt32BE(0, 52); // spare3
  cd.writeBigUInt64BE(0n, 56); // codeLimit64
  cd.writeBigUInt64BE(BigInt(execBase), 64);
  cd.writeBigUInt64BE(BigInt(execLimit), 72);
  cd.writeBigUInt64BE(BigInt(execFlags), 80);
  identBuf.copy(cd, identOff);
  if (team) teamBuf.copy(cd, teamOff);

  for (const [slot, raw] of Object.entries(specials)) {
    sha(alg, raw).copy(cd, hashOff - Number(slot) * hashSize);
  }
  for (let i = 0; i < nCode; i++) {
    const start = i * PAGE;
    sha(alg, data.subarray(start, Math.min(start + PAGE, codeLimit))).copy(cd, hashOff + i * hashSize);
  }
  return cd;
}

function superBlob(items) {
  const head = Buffer.alloc(12 + items.length * 8);
  let off = head.length;
  items.forEach((it, i) => {
    head.writeUInt32BE(it.slot, 12 + i * 8);
    head.writeUInt32BE(off, 16 + i * 8);
    off += it.data.length;
  });
  head.writeUInt32BE(CSMAGIC.superblob, 0);
  head.writeUInt32BE(off, 4);
  head.writeUInt32BE(items.length, 8);
  return Buffer.concat([head, ...items.map((i) => i.data)]);
}

/** Строит SuperBlob подписи для уже подготовленного буфера (data[0..codeLimit) покрывается хешами). */
function buildSignature(o, data, codeLimit) {
  const common = { ident: o.ident, team: o.team, data, codeLimit, execBase: o.execBase, execLimit: o.execLimit, execFlags: o.execFlags };
  const req = emptyRequirements();
  const baseSpecials = { 2: req };
  if (o.infoPlist) baseSpecials[1] = o.infoPlist;
  if (o.codeResources) baseSpecials[3] = o.codeResources;
  let entBlob = null;
  if (o.entitlements) {
    entBlob = blob(CSMAGIC.ent, Buffer.from(o.entitlements, 'utf8'));
    baseSpecials[5] = entBlob;
  }
  const cd1 = buildCodeDirectory({ ...common, alg: 'sha1', specials: baseSpecials });
  const cd2 = buildCodeDirectory({ ...common, alg: 'sha256', specials: baseSpecials });
  const cms = buildCms(cd1, { sha1: sha('sha1', cd1), sha256: sha('sha256', cd2) }, o.identity);

  const items = [{ slot: SLOT.cd, data: cd1 }, { slot: SLOT.req, data: req }];
  if (entBlob) items.push({ slot: SLOT.ent, data: entBlob });
  items.push({ slot: SLOT.altCd, data: cd2 }, { slot: SLOT.cms, data: blob(CSMAGIC.cms, cms) });
  return superBlob(items);
}

function signThin(slice, o) {
  if (slice.readUInt32LE(0) !== MH_MAGIC_64) throw new Error('Поддерживается только 64-битный Mach-O (arm64)');
  const filetype = slice.readUInt32LE(12);
  const ncmds = slice.readUInt32LE(16);
  const sizeofcmds = slice.readUInt32LE(20);

  let off = 32;
  let sig = null, linkedit = null, text = null, firstData = Infinity;
  for (let i = 0; i < ncmds; i++) {
    const cmd = slice.readUInt32LE(off);
    const size = slice.readUInt32LE(off + 4);
    if (cmd === LC_SEGMENT_64) {
      const name = slice.toString('latin1', off + 8, off + 24).replace(/\0.*$/s, '');
      const seg = {
        off, name,
        fileoff: Number(slice.readBigUInt64LE(off + 40)),
        filesize: Number(slice.readBigUInt64LE(off + 48)),
      };
      if (name === '__LINKEDIT') linkedit = seg;
      if (name === '__TEXT') text = seg;
      const nsects = slice.readUInt32LE(off + 64);
      for (let s = 0; s < nsects; s++) {
        const so = off + 72 + s * 80;
        const secOff = slice.readUInt32LE(so + 48);
        const secSize = Number(slice.readBigUInt64LE(so + 40));
        if (secOff > 0 && secSize > 0) firstData = Math.min(firstData, secOff);
      }
      if (name !== '__TEXT' && seg.fileoff > 0 && seg.filesize > 0) firstData = Math.min(firstData, seg.fileoff);
    } else if (cmd === LC_CODE_SIGNATURE) {
      sig = { off, dataoff: slice.readUInt32LE(off + 8), datasize: slice.readUInt32LE(off + 12) };
    }
    off += size;
  }
  if (!linkedit || !text) throw new Error('Нет сегмента __TEXT или __LINKEDIT');

  const linkEnd = linkedit.fileoff + linkedit.filesize;
  let contentEnd;
  if (sig) {
    if (sig.dataoff < linkedit.fileoff || sig.dataoff + sig.datasize + 16 < linkEnd) {
      throw new Error('Подпись не в конце __LINKEDIT — такой бинарь не поддерживается');
    }
    contentEnd = sig.dataoff;
  } else {
    contentEnd = linkEnd;
  }
  if (contentEnd > slice.length) throw new Error('Повреждённый Mach-O (выход за границы файла)');

  const content = Buffer.from(slice.subarray(0, contentEnd));
  let ncmdsNew = ncmds, sizeNew = sizeofcmds, sigCmdOff;
  if (sig) {
    sigCmdOff = sig.off;
  } else {
    sigCmdOff = 32 + sizeofcmds;
    if (sigCmdOff + 16 > firstData) throw new Error('Нет места в заголовке Mach-O под LC_CODE_SIGNATURE');
    for (let i = sigCmdOff; i < sigCmdOff + 16; i++) {
      if (content[i] !== 0) throw new Error('Нет свободного места в заголовке Mach-O');
    }
    ncmdsNew++;
    sizeNew += 16;
  }

  const dataoff = alignUp(contentEnd, 16);
  const execFlags = (o.isMain && filetype === MH_EXECUTE ? 1 : 0) | (o.getTaskAllow ? 0x20 : 0);
  const base = { ...o, execBase: text.fileoff, execLimit: text.filesize, execFlags };

  // 1-й проход: узнаём размер подписи (+ запас), 2-й — подписываем с финальным заголовком.
  const prepare = (reserve) => {
    const out = Buffer.alloc(dataoff + reserve);
    content.copy(out);
    out.writeUInt32LE(ncmdsNew, 16);
    out.writeUInt32LE(sizeNew, 20);
    out.writeUInt32LE(0x1d, sigCmdOff);
    out.writeUInt32LE(16, sigCmdOff + 4);
    out.writeUInt32LE(dataoff, sigCmdOff + 8);
    out.writeUInt32LE(reserve, sigCmdOff + 12);
    const newLinkSize = dataoff + reserve - linkedit.fileoff;
    out.writeBigUInt64LE(BigInt(newLinkSize), linkedit.off + 48);
    out.writeBigUInt64LE(BigInt(alignUp(newLinkSize, 0x4000)), linkedit.off + 32);
    return out;
  };

  const probe = buildSignature(base, prepare(0), dataoff);
  const reserve = alignUp(probe.length + 512, 16);
  const out = prepare(reserve);
  const finalSig = buildSignature(base, out, dataoff);
  if (finalSig.length > reserve) throw new Error('Подпись больше зарезервированного места');
  finalSig.copy(out, dataoff);
  return out;
}

/**
 * @param buf Mach-O (thin или fat)
 * @param o { ident, team, identity, entitlements?, infoPlist?, codeResources?, isMain?, getTaskAllow? }
 */
function signMachO(buf, o) {
  if (buf.readUInt32BE(0) !== FAT_MAGIC) return signThin(buf, o);
  const n = buf.readUInt32BE(4);
  const slices = [];
  for (let i = 0; i < n; i++) {
    const p = 8 + i * 20;
    const offset = buf.readUInt32BE(p + 8);
    const size = buf.readUInt32BE(p + 12);
    slices.push({
      cputype: buf.readUInt32BE(p), cpusub: buf.readUInt32BE(p + 4),
      align: buf.readUInt32BE(p + 16),
      data: signThin(buf.subarray(offset, offset + size), o),
    });
  }
  const head = Buffer.alloc(8 + n * 20);
  head.writeUInt32BE(FAT_MAGIC, 0);
  head.writeUInt32BE(n, 4);
  const parts = [head];
  let pos = head.length;
  slices.forEach((s, i) => {
    const start = alignUp(pos, 2 ** Math.max(s.align, 14));
    parts.push(Buffer.alloc(start - pos), s.data);
    const p = 8 + i * 20;
    head.writeUInt32BE(s.cputype, p);
    head.writeUInt32BE(s.cpusub, p + 4);
    head.writeUInt32BE(start, p + 8);
    head.writeUInt32BE(s.data.length, p + 12);
    head.writeUInt32BE(Math.max(s.align, 14), p + 16);
    pos = start + s.data.length;
  });
  return Buffer.concat(parts);
}

module.exports = { signMachO, isMachO };
