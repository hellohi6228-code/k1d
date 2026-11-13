// Collectors for non-mobile and mini-app formats:
// Windows (.exe/.dll/.sys PE, .msi, .msix/.appx/.appxbundle), Linux (ELF, .deb, .rpm),
// HarmonyOS (.hap, .app pack), browser extensions (.crx, .xpi, extension .zip),
// WeChat mini-programs (.wxapkg), Electron (app.asar), and a generic fallback.
import { openZip, bytesSource } from './zip.js';
import { parsePEHeaders, parseImports, parseVersionInfo, parseManifest, parseAuthenticode, sniffOverlay, PE_CAPABILITIES } from './pe.js';
import { readCFB, parseSummaryInformation } from './cfb.js';
import { signerCertFromPkcs7 } from './cert.js';

const td8 = new TextDecoder('utf-8');
const td16 = new TextDecoder('utf-16le');
const MAX_SCAN = 160 * 1024 * 1024;
const TEXT_RE = /\.(json|js|mjs|cjs|html?|txt|xml|cfg|conf|ini|ya?ml|csv|properties|plist|desktop|service|ts|ets)$/i;

export function latin1(bytes) {
  let out = '';
  const CH = 0x8000;
  for (let i = 0; i < bytes.length; i += CH) out += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
  return out;
}

export function offsetSource(source, offset, size) {
  return { size, read: (o, len) => source.read(offset + o, Math.min(len, size - o)) };
}

// Scan a binary blob for URLs / secrets as both 8-bit and UTF-16LE text.
export function scanBinary(bytes, label, { addUrls, scanText }) {
  const b = bytes.length > MAX_SCAN ? bytes.subarray(0, MAX_SCAN) : bytes;
  const a = latin1(b);
  if (a.includes('://')) addUrls(a, label);
  scanText(a, label);
  const u = td16.decode(b.length % 2 ? b.subarray(0, b.length - 1) : b);
  if (u.includes('://')) addUrls(u, label);
  scanText(u, label);
}

const CAP = (name, def) => ({ name, kind: 'capability', category: def.category, level: def.level, description: def.note });

// ---------------------------------------------------------------- Windows PE
export async function collectPE(source, facts, ctx, label = '') {
  const { progress } = ctx;
  progress({ step: 'binary', detail: label || 'PE' });
  facts.platform = facts.platform ?? 'windows';
  const bytes = await source.read(0, source.size);
  const h = parsePEHeaders(bytes);
  const imports = parseImports(bytes, h);
  const version = parseVersionInfo(bytes, h);
  const manifest = parseManifest(bytes, h);
  const sig = parseAuthenticode(bytes, h);
  const overlayStart = h.rawEnd;
  const overlayEnd = sig ? sig.offset : bytes.length;
  const overlaySize = Math.max(0, overlayEnd - overlayStart);
  const overlayType = overlaySize > 16 ? sniffOverlay(bytes.subarray(overlayStart, overlayStart + 64)) : null;

  const fnSet = new Set(imports.flatMap((i) => i.functions));
  const dlls = imports.map((i) => i.dll);
  for (const d of dlls) facts.fileNames.add(d);
  const caps = PE_CAPABILITIES.filter((c) => c.fns.some((f) => fnSet.has(f)));
  for (const c of caps) facts.permissionList.push({ ...CAP(c.id, c), evidence: c.fns.filter((f) => fnSet.has(f)) });
  if (manifest?.executionLevel === 'requireAdministrator') facts.permissionList.push({ name: 'requireAdministrator', kind: 'capability', category: 'other', level: 'high', description: 'Asks Windows for administrator rights when it starts' });

  if (!facts.cert && sig?.signerDer) { facts.cert = { scheme: 'authenticode', der: sig.signerDer }; facts.signatureSchemes.push('Authenticode'); }
  if (!sig) facts.flags.unsigned = true;

  if (!facts.app) {
    facts.app = {
      id: version?.InternalName || version?.OriginalFilename || label || null,
      name: version?.ProductName || version?.FileDescription || null,
      versionName: version?.ProductVersion || version?.FileVersion || null,
      versionCode: null, minSdk: null, targetSdk: null,
      publisher: version?.CompanyName || null,
    };
  }
  const installer = detectInstaller(bytes, overlayType);
  facts.details.push({
    title: { en: `Windows executable${label ? `: ${label}` : ''}`, zh: `Windows 可执行文件${label ? `：${label}` : ''}` },
    rows: [
      ['Type', `${h.isDll ? 'DLL' : 'EXE'} · ${h.machine} · ${h.subsystem}${h.isDotNet ? ' · .NET' : ''}`],
      ['Company', version?.CompanyName ?? '—'], ['Product', version?.ProductName ?? '—'], ['Description', version?.FileDescription ?? '—'],
      ['File version', version?.FileVersion ?? '—'], ['Original file name', version?.OriginalFilename ?? '—'],
      ['Requested privileges', manifest?.executionLevel ?? 'not specified'],
      ['Authenticode', sig ? 'signed (signature present; not verified by k1d)' : 'unsigned'],
      ['Embedded payload', overlaySize ? `${(overlaySize / 1048576).toFixed(1)} MB (${overlayType})` : 'none'],
      ['Installer technology', installer ?? '—'],
    ],
    lists: [
      { title: 'Imported DLLs', items: dlls },
      ...(caps.length ? [{ title: 'Capability APIs imported', items: caps.map((c) => `${c.note}: ${c.fns.filter((f) => fnSet.has(f)).join(', ')}`) }] : []),
    ],
  });

  scanBinary(bytes.subarray(0, overlayStart || bytes.length), label || 'executable', ctx);
  if (overlaySize) {
    if (overlayType === 'zip') {
      try {
        const z = await openZip(offsetSource(source, overlayStart, overlaySize));
        await collectNestedZip(z, facts, ctx, `${label || 'executable'} (embedded zip)`);
      } catch { scanBinary(bytes.subarray(overlayStart, overlayEnd), `${label || 'executable'} (payload)`, ctx); }
    } else {
      scanBinary(bytes.subarray(overlayStart, overlayEnd), `${label || 'executable'} (payload)`, ctx);
      if (['7z', 'nsis', 'inno', 'cab', 'unknown'].includes(overlayType)) {
        facts.limits.push({ en: `The embedded installer payload (${overlayType}) is compressed in a format k1d does not unpack in the browser; only readable strings were scanned. Install the app in a test machine and analyze the installed files (or the APK/IPA it runs) for full coverage.`, zh: `内嵌安装包载荷（${overlayType}）采用 k1d 无法在浏览器中解压的格式，仅扫描了可读字符串。如需完整覆盖，请在测试设备上安装后分析安装出的文件（或其运行的 APK/IPA）。` });
      }
    }
  }
  return { h, version, manifest, sig, overlayType };
}

function detectInstaller(bytes, overlayType) {
  const s = latin1(bytes.subarray(0, Math.min(bytes.length, 4 * 1024 * 1024)));
  if (/Nullsoft Install System|NullsoftInst/.test(s) || overlayType === 'nsis') return 'NSIS';
  if (/Inno Setup/.test(s) || overlayType === 'inno') return 'Inno Setup';
  if (/InstallShield/.test(s)) return 'InstallShield';
  if (/Squirrel|Update\.exe/.test(s)) return 'Squirrel';
  if (/WiX Toolset|WixBundle/.test(s)) return 'WiX bundle';
  if (/electron-builder|app-64\.7z/.test(s)) return 'electron-builder';
  if (/Advanced Installer/.test(s)) return 'Advanced Installer';
  return null;
}

// Zip found inside an installer, a .deb, etc.: inventory + nested app formats.
export async function collectNestedZip(z, facts, ctx, label) {
  for (const e of z.entries) facts.fileNames.add(e.name.split('/').pop());
  facts.details.push({ title: { en: `Embedded archive: ${label}`, zh: `内嵌压缩包：${label}` }, rows: [['Files', String(z.entries.length)]], lists: [{ title: 'Executables and libraries', items: z.entries.filter((e) => /\.(exe|dll|sys|so|dylib|node|asar|apk|ipa)$/i.test(e.name)).map((e) => e.name).slice(0, 200) }] });
  for (const e of z.entries.filter((x) => /(^|\/)app\.asar$/.test(x.name)).slice(0, 3)) {
    try { await collectAsar(await z.readEntry(e), facts, ctx, `${label}/${e.name}`); } catch (err) { facts.errors.push(`${e.name}: ${err.message}`); }
  }
  for (const e of z.entries.filter((x) => TEXT_RE.test(x.name) && x.size < 4 * 1024 * 1024).slice(0, 300)) {
    try { const t = td8.decode(await z.readEntry(e)); ctx.addUrls(t, `${label}/${e.name}`); ctx.scanText(t, `${label}/${e.name}`); } catch { /* ignore */ }
  }
  for (const e of z.entries.filter((x) => /\.(exe|dll)$/i.test(x.name) && x.size < 96 * 1024 * 1024).slice(0, 12)) {
    try { await collectPE(bytesSource(await z.readEntry(e)), facts, ctx, e.name.split('/').pop()); } catch { /* not a PE */ }
  }
}

// ---------------------------------------------------------------- MSIX / APPX
const MSIX_CAPS = {
  location: ['location', 'high'], webcam: ['camera', 'high'], microphone: ['microphone', 'high'], contacts: ['contacts', 'high'],
  appointments: ['calendar', 'medium'], picturesLibrary: ['media', 'medium'], videosLibrary: ['media', 'medium'], musicLibrary: ['media', 'low'],
  documentsLibrary: ['media', 'medium'], broadFileSystemAccess: ['media', 'high'], bluetooth: ['nearby_devices', 'medium'],
  userAccountInformation: ['accounts', 'medium'], phoneCall: ['phone', 'medium'], chat: ['sms', 'high'], runFullTrust: ['other', 'high'],
  allowElevation: ['other', 'high'], internetClient: ['other', 'low'], userDataTasks: ['calendar', 'medium'], gazeInput: ['biometrics', 'medium'],
};
export async function collectMsix(zip, facts, ctx) {
  facts.platform = 'windows';
  const isBundle = zip.byName.has('AppxMetadata/AppxBundleManifest.xml');
  if (isBundle) {
    const inner = zip.entries.filter((e) => /\.(appx|msix)$/i.test(e.name));
    for (const e of inner.slice(0, 6)) {
      try { await collectMsix(await openZip(bytesSource(await zip.readEntry(e))), facts, ctx); } catch (err) { facts.errors.push(`${e.name}: ${err.message}`); }
    }
    return;
  }
  const xml = td8.decode(await zip.readEntry('AppxManifest.xml'));
  const attr = (tag, a) => new RegExp(`<${tag}\\b[^>]*\\b${a}="([^"]*)"`).exec(xml)?.[1] ?? null;
  const caps = [...xml.matchAll(/<(?:[A-Za-z0-9]+:)?(?:Capability|DeviceCapability)\b[^>]*Name="([^"]+)"/g)].map((m) => m[1]);
  if (!facts.app) {
    facts.app = { id: attr('Identity', 'Name'), name: /<DisplayName>([^<]*)<\/DisplayName>/.exec(xml)?.[1] ?? null, versionName: attr('Identity', 'Version'), versionCode: null, minSdk: attr('TargetDeviceFamily', 'MinVersion'), targetSdk: attr('TargetDeviceFamily', 'MaxVersionTested'), publisher: /<PublisherDisplayName>([^<]*)</.exec(xml)?.[1] ?? attr('Identity', 'Publisher') };
  }
  for (const c of caps) {
    const [category, level] = MSIX_CAPS[c] ?? ['other', 'low'];
    facts.permissionList.push({ name: c, kind: 'permission', category, level, description: 'MSIX capability' });
  }
  for (const e of zip.entries) facts.fileNames.add(e.name.split('/').pop());
  facts.details.push({ title: { en: 'MSIX / APPX package', zh: 'MSIX / APPX 安装包' }, rows: [['Publisher', attr('Identity', 'Publisher') ?? '—'], ['Architecture', attr('Identity', 'ProcessorArchitecture') ?? '—']], lists: [{ title: 'Capabilities', items: caps }] });
  const sig = zip.byName.get('AppxSignature.p7x');
  if (sig && !facts.cert) {
    try { const b = await zip.readEntry(sig); const der = signerCertFromPkcs7(b.subarray(4)); if (der) { facts.cert = { scheme: 'msix', der }; facts.signatureSchemes.push('MSIX (AppxSignature.p7x)'); } } catch (err) { facts.errors.push(`AppxSignature.p7x: ${err.message}`); }
  }
  await collectNestedZip(zip, facts, ctx, 'package');
}

// ---------------------------------------------------------------- MSI
export async function collectMsi(source, facts, ctx) {
  facts.platform = 'windows';
  const bytes = await source.read(0, source.size);
  const cfb = readCFB(bytes);
  const find = (n) => cfb.entries.find((e) => e.name === n);
  const si = find('\u0005SummaryInformation');
  const summary = si ? parseSummaryInformation(cfb.readStream(si)) : null;
  const ds = find('\u0005DigitalSignature');
  if (ds && !facts.cert) {
    try { const der = signerCertFromPkcs7(cfb.readStream(ds)); if (der) { facts.cert = { scheme: 'authenticode', der }; facts.signatureSchemes.push('Authenticode (MSI)'); } } catch (err) { facts.errors.push(`DigitalSignature: ${err.message}`); }
  }
  if (!ds) facts.flags.unsigned = true;
  facts.app = { id: summary?.subject ?? null, name: summary?.subject ?? summary?.title ?? null, versionName: null, versionCode: null, minSdk: null, targetSdk: null, publisher: summary?.author ?? null };
  facts.details.push({ title: { en: 'Windows Installer (MSI)', zh: 'Windows Installer（MSI）' }, rows: [['Title', summary?.title ?? '—'], ['Product', summary?.subject ?? '—'], ['Author', summary?.author ?? '—'], ['Created with', summary?.appName ?? '—'], ['Package code', summary?.revision ?? '—'], ['Streams', String(cfb.entries.length)]] });
  for (const e of cfb.entries) if (e.size < 64 * 1024 * 1024) scanBinary(cfb.readStream(e), 'MSI stream', ctx);
  facts.limits.push({ en: 'MSI tables and embedded cabinets are not unpacked; product files inside compressed cabinets were not analyzed.', zh: 'MSI 数据表和内嵌 CAB 未解包；压缩在 CAB 中的产品文件未被分析。' });
}

// ---------------------------------------------------------------- Linux ELF / .deb / .rpm
export function parseELF(bytes) {
  if (bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) throw new Error('NOT_ELF');
  const is64 = bytes[4] === 2;
  const le = bytes[5] === 1;
  const d = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u16 = (o) => d.getUint16(o, le);
  const u32 = (o) => d.getUint32(o, le);
  const uN = (o) => (is64 ? Number(d.getBigUint64(o, le)) : u32(o));
  const machine = { 0x3e: 'x86_64', 0xb7: 'aarch64', 0x28: 'arm', 0x03: 'x86' }[u16(18)] ?? `0x${u16(18).toString(16)}`;
  const shoff = uN(is64 ? 0x28 : 0x20);
  const shentsize = u16(is64 ? 0x3a : 0x2e);
  const shnum = u16(is64 ? 0x3c : 0x30);
  const sh = [];
  for (let i = 0; i < shnum && shoff + (i + 1) * shentsize <= bytes.length; i++) {
    const o = shoff + i * shentsize;
    sh.push({ type: u32(o + 4), offset: uN(is64 ? o + 0x18 : o + 0x10), size: uN(is64 ? o + 0x20 : o + 0x14), link: u32(is64 ? o + 0x28 : o + 0x18) });
  }
  const needed = [];
  const dyn = sh.find((s) => s.type === 6); // SHT_DYNAMIC
  if (dyn && sh[dyn.link]) {
    const str = sh[dyn.link];
    const ent = is64 ? 16 : 8;
    for (let o = dyn.offset; o + ent <= dyn.offset + dyn.size && o + ent <= bytes.length; o += ent) {
      const tag = is64 ? Number(d.getBigInt64(o, le)) : d.getInt32(o, le);
      const val = is64 ? Number(d.getBigUint64(o + 8, le)) : u32(o + 4);
      if (tag === 0) break;
      if (tag === 1) { // DT_NEEDED
        let e = str.offset + val;
        const s = e;
        while (e < bytes.length && bytes[e]) e++;
        needed.push(td8.decode(bytes.subarray(s, e)));
      }
    }
  }
  return { is64, machine, type: { 2: 'executable', 3: 'shared object / PIE' }[u16(16)] ?? String(u16(16)), needed };
}

export async function collectELF(source, facts, ctx, label = 'ELF') {
  facts.platform = facts.platform ?? 'linux';
  const bytes = await source.read(0, source.size);
  const elf = parseELF(bytes);
  for (const n of elf.needed) facts.fileNames.add(n);
  if (!facts.app) facts.app = { id: label, name: label, versionName: null, versionCode: null, minSdk: null, targetSdk: null };
  facts.details.push({ title: { en: `Linux ELF: ${label}`, zh: `Linux ELF：${label}` }, rows: [['Type', `${elf.type} · ${elf.machine} · ${elf.is64 ? '64-bit' : '32-bit'}`]], lists: [{ title: 'Linked libraries (DT_NEEDED)', items: elf.needed }] });
  scanBinary(bytes, label, ctx);
}

function* tarEntries(buf) {
  let p = 0;
  while (p + 512 <= buf.length) {
    const name = td8.decode(buf.subarray(p, p + 100)).replace(/\0.*$/, '');
    if (!name) break;
    const size = parseInt(td8.decode(buf.subarray(p + 124, p + 136)).replace(/\0.*$/, '').trim() || '0', 8);
    const prefix = td8.decode(buf.subarray(p + 345, p + 500)).replace(/\0.*$/, '');
    const type = String.fromCharCode(buf[p + 156] || 48);
    yield { name: (prefix ? `${prefix}/` : '') + name, size, type, data: buf.subarray(p + 512, p + 512 + size) };
    p += 512 + Math.ceil(size / 512) * 512;
  }
}

async function gunzip(bytes) {
  const ds = new DecompressionStream('gzip');
  return new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(ds)).arrayBuffer());
}

export async function collectDeb(source, facts, ctx) {
  facts.platform = 'linux';
  const bytes = await source.read(0, source.size);
  let p = 8;
  const members = {};
  while (p + 60 <= bytes.length) {
    const name = td8.decode(bytes.subarray(p, p + 16)).trim().replace(/\/$/, '');
    const size = parseInt(td8.decode(bytes.subarray(p + 48, p + 58)).trim(), 10);
    members[name] = bytes.subarray(p + 60, p + 60 + size);
    p += 60 + size + (size % 2);
  }
  const control = {};
  const ctl = Object.keys(members).find((k) => k.startsWith('control.tar'));
  if (ctl?.endsWith('.gz')) {
    for (const e of tarEntries(await gunzip(members[ctl]))) {
      if (/(^|\/)control$/.test(e.name)) for (const line of td8.decode(e.data).split('\n')) { const m = /^([A-Za-z-]+):\s*(.*)$/.exec(line); if (m) control[m[1]] = m[2]; }
    }
  }
  facts.app = { id: control.Package ?? null, name: control.Package ?? null, versionName: control.Version ?? null, versionCode: null, minSdk: null, targetSdk: null, publisher: control.Maintainer ?? null };
  const data = Object.keys(members).find((k) => k.startsWith('data.tar'));
  const files = [];
  if (data?.endsWith('.gz')) {
    for (const e of tarEntries(await gunzip(members[data]))) {
      if (e.type !== '0' && e.type !== '\0') continue;
      files.push(e.name);
      facts.fileNames.add(e.name.split('/').pop());
      if (/(^|\/)app\.asar$/.test(e.name)) await collectAsar(e.data, facts, ctx, e.name);
      else if (e.data[0] === 0x7f && e.data[1] === 0x45 && files.length < 4000) { try { await collectELF(bytesSource(e.data), facts, ctx, e.name.split('/').pop()); } catch { /* not ELF */ } }
      else if (TEXT_RE.test(e.name) && e.size < 4 * 1024 * 1024) { const t = td8.decode(e.data); ctx.addUrls(t, e.name); ctx.scanText(t, e.name); }
    }
  } else if (data) {
    facts.limits.push({ en: `${data} uses a compression k1d cannot unpack in the browser (only .gz is supported). Extract the package and drop the main binary or app.asar instead.`, zh: `${data} 使用了 k1d 无法在浏览器中解压的压缩格式（仅支持 .gz）。请解压后拖入主程序或 app.asar。` });
  }
  facts.details.push({ title: { en: 'Debian package (.deb)', zh: 'Debian 软件包（.deb）' }, rows: Object.entries(control).filter(([k]) => ['Package', 'Version', 'Maintainer', 'Architecture', 'Depends', 'Homepage'].includes(k)), lists: [{ title: 'Files', items: files.slice(0, 300) }] });
}

export async function collectRpm(source, facts) {
  facts.platform = 'linux';
  const bytes = await source.read(0, Math.min(source.size, 8 * 1024 * 1024));
  const d = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const readHeader = (off) => {
    if (d.getUint32(off, false) >>> 8 !== 0x8eade8) return null;
    const n = d.getUint32(off + 8, false);
    const storeLen = d.getUint32(off + 12, false);
    const store = off + 16 + n * 16;
    const tags = {};
    for (let i = 0; i < n; i++) {
      const e = off + 16 + i * 16;
      const tag = d.getUint32(e, false);
      const type = d.getUint32(e + 4, false);
      const o = store + d.getUint32(e + 8, false);
      const count = d.getUint32(e + 12, false);
      if (type === 6 || type === 9) { let x = o; while (bytes[x]) x++; tags[tag] = td8.decode(bytes.subarray(o, x)); }
      else if (type === 8) { const arr = []; let x = o; for (let k = 0; k < count && k < 2000; k++) { const s = x; while (bytes[x]) x++; arr.push(td8.decode(bytes.subarray(s, x))); x++; } tags[tag] = arr; }
    }
    return { tags, end: store + storeLen };
  };
  const sig = readHeader(96);
  const mainOff = sig ? Math.ceil(sig.end / 8) * 8 : 96;
  const main = readHeader(mainOff);
  const t = main?.tags ?? {};
  facts.app = { id: t[1000] ?? null, name: t[1000] ?? null, versionName: [t[1001], t[1002]].filter(Boolean).join('-') || null, versionCode: null, minSdk: null, targetSdk: null, publisher: t[1011] ?? t[1015] ?? null };
  for (const f of t[1117] ?? []) facts.fileNames.add(f);
  facts.details.push({ title: { en: 'RPM package', zh: 'RPM 软件包' }, rows: [['Summary', t[1004] ?? '—'], ['Vendor', t[1011] ?? '—'], ['URL', t[1020] ?? '—'], ['Arch', t[1022] ?? '—']], lists: [{ title: 'Requires', items: t[1049] ?? [] }, { title: 'File names', items: (t[1117] ?? []).slice(0, 300) }] });
  facts.limits.push({ en: 'RPM payloads (cpio, usually xz/zstd-compressed) are not unpacked; only package metadata and file names were read.', zh: 'RPM 载荷（cpio，通常为 xz/zstd 压缩）未解包；仅读取了软件包元数据和文件名。' });
}

// ---------------------------------------------------------------- Electron app.asar
export async function collectAsar(bytes, facts, ctx, label = 'app.asar') {
  const d = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const headerSize = d.getUint32(4, true);
  const jsonLen = d.getUint32(12, true);
  const header = JSON.parse(td8.decode(bytes.subarray(16, 16 + jsonLen)));
  const base = 8 + headerSize;
  facts.electron = true;
  const files = [];
  const walk = (node, path) => {
    for (const [name, v] of Object.entries(node.files ?? {})) {
      const p = path ? `${path}/${name}` : name;
      if (v.files) walk(v, p);
      else files.push({ path: p, offset: Number(v.offset ?? 0), size: v.size ?? 0, unpacked: Boolean(v.unpacked) });
    }
  };
  walk(header, '');
  const read = (f) => bytes.subarray(base + f.offset, base + f.offset + f.size);
  let pkg = null;
  for (const f of files) {
    facts.fileNames.add(f.path.split('/').pop());
    const m = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)\/package\.json$/.exec(f.path);
    if (m) facts.npm.add(m[1]);
    if (f.path === 'package.json' && !f.unpacked) { try { pkg = JSON.parse(td8.decode(read(f))); } catch { /* ignore */ } }
  }
  for (const dep of Object.keys({ ...(pkg?.dependencies ?? {}), ...(pkg?.optionalDependencies ?? {}) })) facts.npm.add(dep);
  let scanned = 0;
  for (const f of files) {
    if (f.unpacked || !/\.(m?js|cjs|json|html)$/.test(f.path) || f.size > 8 * 1024 * 1024 || scanned > 64 * 1024 * 1024) continue;
    if (/node_modules\/.*\.(json)$/.test(f.path)) continue;
    const t = td8.decode(read(f));
    scanned += f.size;
    if (t.includes('://')) ctx.addUrls(t, `${label}/${f.path}`);
    ctx.scanText(t, `${label}/${f.path}`);
  }
  if (!facts.app && pkg) facts.app = { id: pkg.name ?? null, name: pkg.productName ?? pkg.name ?? null, versionName: pkg.version ?? null, versionCode: null, minSdk: null, targetSdk: null, publisher: typeof pkg.author === 'string' ? pkg.author : pkg.author?.name ?? null };
  facts.details.push({ title: { en: `Electron app bundle: ${label}`, zh: `Electron 应用包：${label}` }, rows: [['Name', pkg?.name ?? '—'], ['Version', pkg?.version ?? '—'], ['Main script', pkg?.main ?? '—'], ['Files', String(files.length)]], lists: [{ title: 'npm packages', items: [...facts.npm].sort().slice(0, 400) }] });
}

// ---------------------------------------------------------------- HarmonyOS
const OHOS_PERMS = {
  'ohos.permission.LOCATION': ['precise_location', 'high'], 'ohos.permission.APPROXIMATELY_LOCATION': ['location', 'medium'],
  'ohos.permission.LOCATION_IN_BACKGROUND': ['precise_location', 'high'], 'ohos.permission.CAMERA': ['camera', 'high'],
  'ohos.permission.MICROPHONE': ['microphone', 'high'], 'ohos.permission.READ_CONTACTS': ['contacts', 'high'],
  'ohos.permission.READ_CALENDAR': ['calendar', 'medium'], 'ohos.permission.APP_TRACKING_CONSENT': ['advertising_id', 'medium'],
  'ohos.permission.READ_MEDIA': ['media', 'medium'], 'ohos.permission.READ_IMAGEVIDEO': ['media', 'medium'],
  'ohos.permission.ACCESS_BLUETOOTH': ['nearby_devices', 'medium'], 'ohos.permission.READ_HEALTH_DATA': ['health', 'high'],
  'ohos.permission.ACTIVITY_MOTION': ['health', 'medium'], 'ohos.permission.GET_INSTALLED_BUNDLE_LIST': ['installed_apps', 'high'],
  'ohos.permission.READ_MESSAGES': ['sms', 'high'], 'ohos.permission.READ_CALL_LOG': ['call_log', 'high'],
  'ohos.permission.GET_WIFI_INFO': ['device_ids', 'low'], 'ohos.permission.READ_PASTEBOARD': ['user_content', 'medium'],
};
export async function collectHarmony(zip, facts, ctx) {
  facts.platform = 'harmonyos';
  const haps = zip.entries.filter((e) => /\.hsp$|\.hap$/i.test(e.name));
  if (!zip.byName.has('module.json') && !zip.byName.has('config.json') && haps.length) {
    for (const e of haps.slice(0, 8)) {
      try { await collectHarmony(await openZip(bytesSource(await zip.readEntry(e))), facts, ctx); } catch (err) { facts.errors.push(`${e.name}: ${err.message}`); }
    }
    return;
  }
  const stage = zip.byName.has('module.json');
  const cfg = JSON.parse(td8.decode(await zip.readEntry(stage ? 'module.json' : 'config.json')));
  const app = cfg.app ?? {};
  const mod = cfg.module ?? {};
  if (!facts.app) facts.app = { id: app.bundleName ?? null, name: app.label ?? null, versionName: app.versionName ?? app.version?.name ?? null, versionCode: app.versionCode ?? app.version?.code ?? null, minSdk: app.minAPIVersion ?? null, targetSdk: app.targetAPIVersion ?? null, publisher: app.vendor ?? null };
  for (const p of mod.requestPermissions ?? mod.reqPermissions ?? []) {
    const [category, level] = OHOS_PERMS[p.name] ?? ['other', 'low'];
    facts.permissionList.push({ name: p.name, kind: 'permission', category, level, description: p.reason ?? '' });
  }
  for (const e of zip.entries) {
    const m = /^libs\/([^/]+)\/([^/]+\.so)$/.exec(e.name);
    if (m) { if (!facts.nativeLibs.has(m[2])) facts.nativeLibs.set(m[2], new Set()); facts.nativeLibs.get(m[2]).add(m[1]); facts.fileNames.add(m[2]); }
  }
  for (const e of zip.entries.filter((x) => /\.abc$|resources\.index$/.test(x.name) && x.size < 128 * 1024 * 1024)) {
    const b = await zip.readEntry(e);
    const s = latin1(b);
    ctx.addUrls(s, e.name);
    ctx.scanText(s, e.name);
    for (const m of s.matchAll(/@(?:[a-z0-9][a-z0-9_.-]*)\/[a-z0-9][a-z0-9_.-]*/g)) facts.npm.add(m[0]);
  }
  for (const e of zip.entries.filter((x) => /\.so$/.test(x.name) && x.size < 48 * 1024 * 1024).slice(0, 40)) scanBinary(await zip.readEntry(e), e.name, ctx);
  facts.details.push({ title: { en: `HarmonyOS module: ${mod.name ?? '?'}`, zh: `HarmonyOS 模块：${mod.name ?? '?'}` }, rows: [['Model', stage ? 'Stage (module.json)' : 'FA (config.json)'], ['Module type', mod.type ?? mod.distro?.moduleType ?? '—'], ['Vendor', app.vendor ?? '—'], ['Device types', (mod.deviceTypes ?? []).join(', ') || '—']], lists: [{ title: 'Abilities', items: [...(mod.abilities ?? []), ...(mod.extensionAbilities ?? [])].map((a) => `${a.name}${a.type ? ` (${a.type})` : ''}${a.exported ? ' · exported' : ''}`) }] });
}

// ---------------------------------------------------------------- Browser extensions
const EXT_PERMS = {
  tabs: ['browsing', 'medium'], history: ['browsing', 'high'], cookies: ['browsing', 'high'], webRequest: ['browsing', 'high'],
  webRequestBlocking: ['browsing', 'high'], declarativeNetRequest: ['browsing', 'medium'], '<all_urls>': ['browsing', 'high'],
  geolocation: ['location', 'medium'], clipboardRead: ['user_content', 'medium'], bookmarks: ['browsing', 'medium'], identity: ['accounts', 'medium'],
  'identity.email': ['email', 'medium'], nativeMessaging: ['other', 'medium'], debugger: ['other', 'high'], management: ['installed_apps', 'medium'],
  proxy: ['browsing', 'high'], scripting: ['browsing', 'medium'], downloads: ['other', 'low'], topSites: ['browsing', 'medium'],
  desktopCapture: ['media', 'high'], tabCapture: ['media', 'high'], privacy: ['other', 'medium'], storage: ['other', 'low'],
};
export async function collectExtension(zip, facts, ctx, kind) {
  facts.platform = 'browser-extension';
  const m = JSON.parse(td8.decode(await zip.readEntry('manifest.json')).replace(/^﻿/, ''));
  facts.app = { id: m.browser_specific_settings?.gecko?.id ?? m.applications?.gecko?.id ?? m.key?.slice(0, 16) ?? null, name: m.name ?? null, versionName: m.version ?? null, versionCode: null, minSdk: m.minimum_chrome_version ?? null, targetSdk: null, publisher: m.author ?? null };
  const hostPerms = [...(m.host_permissions ?? []), ...(m.permissions ?? []).filter((p) => p.includes('://') || p === '<all_urls>')];
  const perms = (m.permissions ?? []).filter((p) => !p.includes('://'));
  for (const p of [...perms, ...(m.optional_permissions ?? []).map((x) => x)]) {
    const [category, level] = EXT_PERMS[p] ?? ['other', 'low'];
    facts.permissionList.push({ name: p, kind: 'permission', category, level, description: (m.optional_permissions ?? []).includes(p) ? 'optional' : '' });
  }
  const broad = hostPerms.filter((h) => h === '<all_urls>' || /^\*:\/\/\*\/|^https?:\/\/\*\//.test(h));
  if (broad.length) facts.permissionList.push({ name: broad.join(', '), kind: 'permission', category: 'browsing', level: 'high', description: 'Can read and change data on all websites' });
  const cs = (m.content_scripts ?? []).flatMap((c) => c.matches ?? []);
  for (const e of zip.entries) facts.fileNames.add(e.name.split('/').pop());
  for (const e of zip.entries.filter((x) => /\.(m?js|html|json)$/.test(x.name) && x.size < 8 * 1024 * 1024).slice(0, 400)) {
    const t = td8.decode(await zip.readEntry(e));
    ctx.addUrls(t, e.name);
    ctx.scanText(t, e.name);
  }
  const update = m.update_url ?? null;
  facts.details.push({ title: { en: `Browser extension (${kind})`, zh: `浏览器扩展（${kind}）` }, rows: [['Manifest version', String(m.manifest_version ?? '—')], ['Update URL', update ?? '—'], ['Background', m.background?.service_worker ?? m.background?.scripts?.join(', ') ?? '—'], ['Externally connectable', JSON.stringify(m.externally_connectable?.matches ?? []) ]], lists: [{ title: 'Host permissions', items: hostPerms }, { title: 'Content scripts run on', items: [...new Set(cs)] }] });
  if (update && !/clients2\.google\.com|edge\.microsoft\.com|addons\.mozilla\.org/.test(update)) ctx.addUrls(update, 'manifest.json (update_url)');
}

export function crxZipOffset(head) {
  const d = new DataView(head.buffer, head.byteOffset, head.byteLength);
  const version = d.getUint32(4, true);
  if (version === 3) return 12 + d.getUint32(8, true);
  if (version === 2) return 16 + d.getUint32(8, true) + d.getUint32(12, true);
  throw new Error('UNSUPPORTED_CRX');
}

// ---------------------------------------------------------------- WeChat mini-program (.wxapkg)
const WX_APIS = {
  getLocation: ['precise_location', 'high'], getFuzzyLocation: ['location', 'medium'], chooseLocation: ['location', 'medium'],
  startLocationUpdateBackground: ['precise_location', 'high'], onLocationChange: ['precise_location', 'high'],
  getPhoneNumber: ['phone', 'high'], chooseAddress: ['address', 'medium'], getWeRunData: ['health', 'high'],
  getRecorderManager: ['microphone', 'high'], startRecord: ['microphone', 'high'], chooseMedia: ['camera', 'medium'], chooseImage: ['camera', 'medium'],
  getClipboardData: ['user_content', 'medium'], getUserProfile: ['name', 'medium'], getUserInfo: ['name', 'medium'], requestPayment: ['purchases', 'low'],
  startBluetoothDevicesDiscovery: ['nearby_devices', 'medium'], startWifi: ['device_ids', 'low'], chooseContact: ['contacts', 'high'], addPhoneContact: ['contacts', 'medium'],
};
export function isWxapkg(head) {
  return head.length >= 14 && head[0] === 0xbe && head[13] === 0xed;
}
export async function collectWxapkg(source, facts, ctx) {
  facts.platform = 'miniprogram';
  const b = await source.read(0, source.size);
  const d = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const indexLen = d.getUint32(5, false);
  let p = 14;
  const count = d.getUint32(p, false);
  p += 4;
  const files = [];
  for (let i = 0; i < count && p < 14 + indexLen + 4; i++) {
    const nl = d.getUint32(p, false);
    const name = td8.decode(b.subarray(p + 4, p + 4 + nl));
    const off = d.getUint32(p + 4 + nl, false);
    const size = d.getUint32(p + 8 + nl, false);
    files.push({ name, data: b.subarray(off, off + size) });
    p += 12 + nl;
  }
  const apis = new Map();
  let cfg = null;
  for (const f of files) {
    facts.fileNames.add(f.name.split('/').pop());
    if (!/\.(js|json|html|wxml|wxss)$/.test(f.name)) continue;
    const t = td8.decode(f.data);
    if (/app-config\.json$/.test(f.name)) { try { cfg = JSON.parse(t); } catch { /* ignore */ } }
    ctx.addUrls(t, f.name);
    ctx.scanText(t, f.name);
    for (const m of t.matchAll(/\b(?:wx|uni|Taro)\.([A-Za-z]+)\s*\(/g)) if (WX_APIS[m[1]]) apis.set(m[1], (apis.get(m[1]) ?? 0) + 1);
    if (/open-type=["']getPhoneNumber/.test(t)) apis.set('getPhoneNumber', (apis.get('getPhoneNumber') ?? 0) + 1);
  }
  for (const [api] of apis) { const [category, level] = WX_APIS[api]; facts.permissionList.push({ name: `wx.${api}`, kind: 'capability', category, level, description: 'Mini-program API called in code' }); }
  for (const [scope, v] of Object.entries(cfg?.permission ?? {})) facts.permissionList.push({ name: scope, kind: 'permission', category: /Location/.test(scope) ? 'location' : /record/.test(scope) ? 'microphone' : /camera/.test(scope) ? 'camera' : /werun/.test(scope) ? 'health' : 'other', level: 'medium', description: v?.desc ?? '' });
  const plugins = Object.entries(cfg?.plugins ?? {}).map(([k, v]) => `${k} (${v?.provider ?? '?'})`);
  facts.app = facts.app ?? { id: cfg?.entryPagePath ?? null, name: cfg?.global?.window?.navigationBarTitleText ?? null, versionName: null, versionCode: null, minSdk: null, targetSdk: null };
  facts.details.push({ title: { en: 'WeChat mini-program package (.wxapkg)', zh: '微信小程序包（.wxapkg）' }, rows: [['Files', String(files.length)], ['Pages', String((cfg?.pages ?? []).length)]], lists: [{ title: 'requiredPrivateInfos', items: cfg?.requiredPrivateInfos ?? [] }, { title: 'Plugins (third-party providers)', items: plugins }] });
}

// ---------------------------------------------------------------- generic
export async function collectGeneric(source, facts, ctx, why) {
  facts.platform = facts.platform ?? 'unknown';
  const bytes = await source.read(0, Math.min(source.size, MAX_SCAN));
  scanBinary(bytes, 'file', ctx);
  facts.app = facts.app ?? { id: null, name: null, versionName: null, versionCode: null, minSdk: null, targetSdk: null };
  facts.limits.push(why);
}
