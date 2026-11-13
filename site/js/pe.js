// Windows PE (.exe/.dll/.sys) parser: headers, sections, imports, version info, application
// manifest, Authenticode signature, .NET marker, overlay (embedded installer payload).
import { signerCertFromPkcs7 } from './cert.js';

const td16 = new TextDecoder('utf-16le');
const td8 = new TextDecoder('utf-8');

export function isPE(head) {
  if (head.length < 64 || head[0] !== 0x4d || head[1] !== 0x5a) return false;
  return true;
}

const MACHINES = { 0x14c: 'x86', 0x8664: 'x64', 0xaa64: 'arm64', 0x1c4: 'arm' };

// Parse the headers from the first bytes of the file (needs the full header region).
export function parsePEHeaders(bytes) {
  const d = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const peOff = d.getUint32(0x3c, true);
  if (peOff + 24 > bytes.length || d.getUint32(peOff, true) !== 0x00004550) throw new Error('NOT_PE');
  const coff = peOff + 4;
  const machine = d.getUint16(coff, true);
  const nSections = d.getUint16(coff + 2, true);
  const timestamp = d.getUint32(coff + 4, true);
  const optSize = d.getUint16(coff + 16, true);
  const characteristics = d.getUint16(coff + 18, true);
  const opt = coff + 20;
  const magic = d.getUint16(opt, true);
  const pe32plus = magic === 0x20b;
  const subsystem = d.getUint16(opt + 68, true);
  const numDirs = d.getUint32(opt + (pe32plus ? 108 : 92), true);
  const dirBase = opt + (pe32plus ? 112 : 96);
  const dirs = [];
  for (let i = 0; i < Math.min(numDirs, 16); i++) dirs.push({ rva: d.getUint32(dirBase + i * 8, true), size: d.getUint32(dirBase + i * 8 + 4, true) });
  const sections = [];
  let s = opt + optSize;
  for (let i = 0; i < nSections; i++, s += 40) {
    sections.push({
      name: td8.decode(bytes.subarray(s, s + 8)).replace(/\0.*$/, ''),
      vsize: d.getUint32(s + 8, true), rva: d.getUint32(s + 12, true),
      rawSize: d.getUint32(s + 16, true), rawPtr: d.getUint32(s + 20, true),
    });
  }
  const rawEnd = sections.reduce((m, x) => Math.max(m, x.rawPtr + x.rawSize), 0);
  return {
    machine: MACHINES[machine] ?? `0x${machine.toString(16)}`,
    pe32plus, timestamp: timestamp ? new Date(timestamp * 1000).toISOString() : null,
    isDll: (characteristics & 0x2000) !== 0,
    subsystem: { 2: 'GUI', 3: 'console', 1: 'native (driver)' }[subsystem] ?? String(subsystem),
    dirs, sections, rawEnd,
    isDotNet: Boolean(dirs[14]?.rva),
    headerEnd: s,
  };
}

function rvaToOff(h, rva) {
  for (const s of h.sections) if (rva >= s.rva && rva < s.rva + Math.max(s.vsize, s.rawSize)) return rva - s.rva + s.rawPtr;
  return -1;
}

function cstr(bytes, off, max = 512) {
  let e = off;
  while (e < bytes.length && e - off < max && bytes[e] !== 0) e++;
  return td8.decode(bytes.subarray(off, e));
}

// Imports: DLL names and (capped) function names.
export function parseImports(bytes, h, limit = 8000) {
  const dir = h.dirs[1];
  const out = [];
  if (!dir?.rva) return out;
  const d = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let p = rvaToOff(h, dir.rva);
  let count = 0;
  while (p > 0 && p + 20 <= bytes.length) {
    const oft = d.getUint32(p, true);
    const nameRva = d.getUint32(p + 12, true);
    const ft = d.getUint32(p + 16, true);
    if (!nameRva && !ft) break;
    const nameOff = rvaToOff(h, nameRva);
    const dll = nameOff > 0 ? cstr(bytes, nameOff) : '?';
    const fns = [];
    let t = rvaToOff(h, oft || ft);
    const step = h.pe32plus ? 8 : 4;
    while (t > 0 && t + step <= bytes.length && count < limit) {
      const lo = d.getUint32(t, true);
      const hi = h.pe32plus ? d.getUint32(t + 4, true) : 0;
      if (!lo && !hi) break;
      const ordinal = h.pe32plus ? (hi & 0x80000000) !== 0 : (lo & 0x80000000) !== 0;
      if (!ordinal) {
        const hn = rvaToOff(h, lo);
        if (hn > 0) fns.push(cstr(bytes, hn + 2, 256));
      }
      t += step;
      count++;
    }
    out.push({ dll, functions: fns });
    p += 20;
  }
  return out;
}

// Resources: version info (RT_VERSION=16) and manifest (RT_MANIFEST=24).
function resourceLeaves(bytes, h, typeId) {
  const dir = h.dirs[2];
  if (!dir?.rva) return [];
  const base = rvaToOff(h, dir.rva);
  if (base < 0) return [];
  const d = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const leaves = [];
  const walk = (off, depth, matchType) => {
    if (depth > 3 || off < 0 || off + 16 > bytes.length) return;
    const named = d.getUint16(off + 12, true);
    const ids = d.getUint16(off + 14, true);
    for (let i = 0; i < named + ids && i < 512; i++) {
      const e = off + 16 + i * 8;
      const id = d.getUint32(e, true);
      const target = d.getUint32(e + 4, true);
      if (depth === 0 && (id & 0x80000000 || id !== matchType)) continue;
      if (target & 0x80000000) walk(base + (target & 0x7fffffff), depth + 1, matchType);
      else {
        const de = base + target;
        const rva = d.getUint32(de, true);
        const size = d.getUint32(de + 4, true);
        const fo = rvaToOff(h, rva);
        if (fo > 0 && fo + size <= bytes.length) leaves.push(bytes.subarray(fo, fo + size));
      }
    }
  };
  walk(base, 0, typeId);
  return leaves;
}

export function parseVersionInfo(bytes, h) {
  const leaf = resourceLeaves(bytes, h, 16)[0];
  if (!leaf) return null;
  const d = new DataView(leaf.buffer, leaf.byteOffset, leaf.byteLength);
  const strings = {};
  const align4 = (n) => (n + 3) & ~3;
  const readKey = (off) => {
    let e = off;
    while (e + 1 < leaf.length && (leaf[e] | leaf[e + 1])) e += 2;
    return [td16.decode(leaf.subarray(off, e)), e + 2];
  };
  const walk = (off, end, depth) => {
    while (off + 6 <= end && depth < 6) {
      const len = d.getUint16(off, true);
      const valLen = d.getUint16(off + 2, true);
      const type = d.getUint16(off + 4, true);
      if (len < 6) break;
      const [key, afterKey] = readKey(off + 6);
      const valOff = align4(afterKey);
      const blockEnd = Math.min(off + len, end);
      if (depth === 3 && type === 1 && valLen) {
        strings[key] = td16.decode(leaf.subarray(valOff, Math.min(valOff + valLen * 2, blockEnd))).replace(/\0+$/, '');
      } else {
        const childStart = align4(valOff + (type === 1 ? valLen * 2 : valLen));
        if (key === 'VS_VERSION_INFO' || key === 'StringFileInfo' || depth === 2) walk(childStart, blockEnd, depth + 1);
      }
      off = align4(off + len);
    }
  };
  walk(0, leaf.length, 0);
  return Object.keys(strings).length ? strings : null;
}

export function parseManifest(bytes, h) {
  const leaf = resourceLeaves(bytes, h, 24)[0];
  if (!leaf) return null;
  const xml = td8.decode(leaf);
  const level = /requestedExecutionLevel[^>]*level=["']([^"']+)/i.exec(xml)?.[1] ?? null;
  return { executionLevel: level, uiAccess: /uiAccess=["']true/i.test(xml), xml: xml.slice(0, 4000) };
}

// Authenticode: data directory 4 is a *file offset* to WIN_CERTIFICATE structures.
export function parseAuthenticode(bytes, h) {
  const dir = h.dirs[4];
  if (!dir?.rva || !dir.size || dir.rva + 8 > bytes.length) return null;
  const d = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const len = d.getUint32(dir.rva, true);
  const type = d.getUint16(dir.rva + 6, true);
  if (type !== 2 || len < 8) return null;
  const pkcs7 = bytes.subarray(dir.rva + 8, Math.min(bytes.length, dir.rva + len));
  return { offset: dir.rva, size: dir.size, signerDer: signerCertFromPkcs7(pkcs7) };
}

// What sits after the last section (installers append their payload there).
export function sniffOverlay(head) {
  const s = new TextDecoder('latin1').decode(head.subarray(0, 64));
  if (head[0] === 0x50 && head[1] === 0x4b && head[2] === 0x03 && head[3] === 0x04) return 'zip';
  if (s.startsWith('7z\xBC\xAF\x27\x1C')) return '7z';
  if (s.includes('NullsoftInst')) return 'nsis';
  if (s.startsWith('MSCF')) return 'cab';
  if (s.startsWith('Inno Setup') || s.startsWith('zlb\x1a') || s.startsWith('rDlPtS')) return 'inno';
  if (head[0] === 0xd0 && head[1] === 0xcf && head[2] === 0x11 && head[3] === 0xe0) return 'msi';
  return 'unknown';
}

// Capability signals from imported functions (Windows has no permission system).
export const PE_CAPABILITIES = [
  { id: 'keyboard_hook', fns: ['SetWindowsHookExA', 'SetWindowsHookExW', 'GetAsyncKeyState', 'RegisterRawInputDevices'], category: 'user_content', level: 'high', note: 'Keyboard/mouse hooks or raw input capture' },
  { id: 'clipboard', fns: ['GetClipboardData'], category: 'user_content', level: 'medium', note: 'Reads the clipboard' },
  { id: 'screen_capture', fns: ['BitBlt', 'PrintWindow', 'CreateDXGIFactory1'], category: 'media', level: 'low', note: 'Screen or window capture APIs (also used for normal drawing)' },
  { id: 'process_list', fns: ['CreateToolhelp32Snapshot', 'EnumProcesses', 'Process32FirstW', 'Process32First'], category: 'installed_apps', level: 'medium', note: 'Lists running processes' },
  { id: 'hardware_ids', fns: ['GetAdaptersInfo', 'GetAdaptersAddresses', 'GetVolumeInformationW', 'GetVolumeInformationA'], category: 'device_ids', level: 'medium', note: 'Reads MAC addresses or volume serial numbers (device fingerprinting)' },
  { id: 'credentials', fns: ['CryptUnprotectData', 'CredReadW', 'CredEnumerateW'], category: 'sensitive', level: 'high', note: 'Decrypts stored user secrets (DPAPI) or reads Windows Credential Manager' },
  { id: 'microphone', fns: ['waveInOpen'], category: 'microphone', level: 'high', note: 'Audio capture API' },
  { id: 'camera', fns: ['capCreateCaptureWindowA', 'capCreateCaptureWindowW', 'MFEnumDeviceSources'], category: 'camera', level: 'high', note: 'Camera capture API' },
  { id: 'location', fns: ['WlanGetNetworkBssList'], category: 'location', level: 'medium', note: 'Wi-Fi BSSID scan (usable for location)' },
  { id: 'driver_service', fns: ['CreateServiceW', 'CreateServiceA'], category: 'other', level: 'medium', note: 'Installs Windows services or drivers' },
  { id: 'remote_thread', fns: ['CreateRemoteThread', 'WriteProcessMemory'], category: 'other', level: 'medium', note: 'Writes into other processes (also used by anti-cheat and overlays)' },
];
