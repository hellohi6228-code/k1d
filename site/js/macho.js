// Mach-O parser for iOS executables: load commands, linked libraries, encryption info,
// string sections, and the embedded code signature (CodeDirectory, entitlements, CMS).
import { parsePlist } from './plist.js';

const FAT_MAGIC = 0xcafebabe;
const FAT_MAGIC_64 = 0xcafebabf;
const MH_MAGIC_64 = 0xfeedfacf;
const MH_MAGIC = 0xfeedface;
const CPU_TYPE_ARM64 = 0x0100000c;

const LC_SEGMENT_64 = 0x19;
const LC_SEGMENT = 0x1;
const LC_CODE_SIGNATURE = 0x1d;
const LC_ENCRYPTION_INFO = 0x21;
const LC_ENCRYPTION_INFO_64 = 0x2c;
const LC_VERSION_MIN_IPHONEOS = 0x25;
const LC_BUILD_VERSION = 0x32;
const DYLIB_CMDS = new Set([0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023]);

const td = new TextDecoder('utf-8');

function cstr(bytes, off, max = 1024) {
  let e = off;
  const lim = Math.min(bytes.length, off + max);
  while (e < lim && bytes[e] !== 0) e++;
  return td.decode(bytes.subarray(off, e));
}

function fixedName(bytes, off) {
  return cstr(bytes, off, 16);
}

function version(v) {
  return `${v >>> 16}.${(v >> 8) & 0xff}.${v & 0xff}`.replace(/\.0$/, '');
}

export function isMachO(bytes) {
  if (!bytes || bytes.length < 4) return false;
  const be = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, false);
  const le = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);
  return be === FAT_MAGIC || be === FAT_MAGIC_64 || le === MH_MAGIC_64 || le === MH_MAGIC;
}

// Choose the arm64 slice of a universal binary; returns [sliceBytes, archList].
function pickSlice(bytes) {
  const d = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magic = d.getUint32(0, false);
  if (magic !== FAT_MAGIC && magic !== FAT_MAGIC_64) return [bytes, null];
  const n = d.getUint32(4, false);
  const archs = [];
  for (let i = 0; i < n; i++) {
    if (magic === FAT_MAGIC) {
      const p = 8 + i * 20;
      archs.push({ cputype: d.getUint32(p, false), offset: d.getUint32(p + 8, false), size: d.getUint32(p + 12, false) });
    } else {
      const p = 8 + i * 32;
      archs.push({ cputype: d.getUint32(p, false), offset: Number(d.getBigUint64(p + 8, false)), size: Number(d.getBigUint64(p + 16, false)) });
    }
  }
  const pick = archs.find((a) => a.cputype === CPU_TYPE_ARM64) ?? archs[0];
  return [bytes.subarray(pick.offset, pick.offset + pick.size), archs.map((a) => a.cputype)];
}

export function parseMachO(input) {
  const [bytes, fatArchs] = pickSlice(input);
  const d = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magic = d.getUint32(0, true);
  if (magic !== MH_MAGIC_64 && magic !== MH_MAGIC) throw new Error('NOT_MACHO');
  const is64 = magic === MH_MAGIC_64;
  const cputype = d.getUint32(4, true);
  const filetype = d.getUint32(12, true);
  const ncmds = d.getUint32(16, true);
  let p = is64 ? 32 : 28;

  const out = {
    is64,
    arch: cputype === CPU_TYPE_ARM64 ? 'arm64' : `cpu:0x${cputype.toString(16)}`,
    fatArchs,
    filetype,
    dylibs: [],
    encryption: null,
    minOS: null,
    sdk: null,
    sections: [],
    codeSignature: null,
    bytes,
  };

  for (let i = 0; i < ncmds && p + 8 <= bytes.length; i++) {
    const cmd = d.getUint32(p, true);
    const size = d.getUint32(p + 4, true);
    if (size < 8) break;
    if (cmd === LC_SEGMENT_64 || cmd === LC_SEGMENT) {
      const segname = fixedName(bytes, p + 8);
      const nsects = d.getUint32(p + (is64 ? 64 : 48), true);
      let s = p + (is64 ? 72 : 56);
      for (let k = 0; k < nsects; k++) {
        const sectname = fixedName(bytes, s);
        const size64 = is64 ? Number(d.getBigUint64(s + 40, true)) : d.getUint32(s + 36, true);
        const offset = d.getUint32(s + (is64 ? 48 : 40), true);
        out.sections.push({ segname, sectname, offset, size: size64 });
        s += is64 ? 80 : 68;
      }
    } else if (DYLIB_CMDS.has(cmd)) {
      out.dylibs.push(cstr(bytes, p + d.getUint32(p + 8, true)));
    } else if (cmd === LC_ENCRYPTION_INFO_64 || cmd === LC_ENCRYPTION_INFO) {
      out.encryption = { cryptoff: d.getUint32(p + 8, true), cryptsize: d.getUint32(p + 12, true), cryptid: d.getUint32(p + 16, true) };
    } else if (cmd === LC_CODE_SIGNATURE) {
      out.codeSignature = { dataoff: d.getUint32(p + 8, true), datasize: d.getUint32(p + 12, true) };
    } else if (cmd === LC_BUILD_VERSION) {
      out.minOS = version(d.getUint32(p + 12, true));
      out.sdk = version(d.getUint32(p + 16, true));
    } else if (cmd === LC_VERSION_MIN_IPHONEOS) {
      out.minOS = version(d.getUint32(p + 8, true));
      out.sdk = version(d.getUint32(p + 12, true));
    }
    p += size;
  }
  out.encrypted = Boolean(out.encryption && out.encryption.cryptid !== 0);
  return out;
}

function encryptedRange(m) {
  if (!m.encrypted) return null;
  return [m.encryption.cryptoff, m.encryption.cryptoff + m.encryption.cryptsize];
}

function readable(m, offset, size) {
  const r = encryptedRange(m);
  if (!r) return true;
  return offset + size <= r[0] || offset >= r[1];
}

// Strings from __cstring / __objc_classname when they are not encrypted.
export function machoStrings(m) {
  const cstrings = [];
  const classNames = [];
  for (const s of m.sections) {
    const isC = s.sectname === '__cstring' || s.sectname === '__oslogstring';
    const isCls = s.sectname === '__objc_classname';
    if (!isC && !isCls) continue;
    if (!s.size || s.offset + s.size > m.bytes.length || !readable(m, s.offset, s.size)) continue;
    const chunk = m.bytes.subarray(s.offset, s.offset + s.size);
    let start = 0;
    for (let i = 0; i <= chunk.length; i++) {
      if (i === chunk.length || chunk[i] === 0) {
        if (i - start >= 3) {
          const str = td.decode(chunk.subarray(start, i));
          (isCls ? classNames : cstrings).push(str);
        }
        start = i + 1;
      }
    }
  }
  return { cstrings, classNames };
}

// Code signature SuperBlob (big-endian).
export function parseCodeSignature(m) {
  if (!m.codeSignature) return null;
  const { dataoff, datasize } = m.codeSignature;
  if (dataoff + 12 > m.bytes.length) return null;
  const b = m.bytes.subarray(dataoff, Math.min(m.bytes.length, dataoff + datasize));
  const d = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (d.getUint32(0, false) !== 0xfade0cc0) return null;
  const count = d.getUint32(8, false);
  const out = { identifier: null, teamId: null, entitlements: null, cms: null };
  for (let i = 0; i < count; i++) {
    const off = d.getUint32(12 + i * 8 + 4, false);
    if (off + 8 > b.length) continue;
    const magic = d.getUint32(off, false);
    const len = d.getUint32(off + 4, false);
    const blob = b.subarray(off, Math.min(b.length, off + len));
    const bd = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
    if (magic === 0xfade0c02 && !out.identifier) { // CodeDirectory
      const ver = bd.getUint32(8, false);
      out.identifier = cstr(blob, bd.getUint32(20, false));
      if (ver >= 0x20200) {
        const teamOff = bd.getUint32(48, false);
        if (teamOff) out.teamId = cstr(blob, teamOff);
      }
    } else if (magic === 0xfade7171) { // XML entitlements
      try { out.entitlements = parsePlist(blob.subarray(8)); } catch { /* ignore */ }
    } else if (magic === 0xfade0b01) { // CMS signature
      if (len > 8) out.cms = blob.slice(8);
    }
  }
  return out;
}
