// Builds synthetic fixtures for every non-mobile format k1d reads, into tests/fixtures/formats/.
// Certificates come from openssl; tests/fixtures/formats-expected.json records ground truth.
// Usage: node tools/build-demo-formats.mjs   (needs openssl; run build-demo-ipa.mjs first)
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { writeZip } from './ziplib.mjs';
import { openZip, bytesSource } from '../site/js/zip.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.join(root, 'tests', 'fixtures', 'formats');
fs.mkdirSync(out, { recursive: true });
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'k1d-fmt-'));
const f = (n) => path.join(work, n);
const run = (cmd, args) => execFileSync(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const B = (s) => Buffer.from(s, 'utf8');
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u32be = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const align = (n, a) => Math.ceil(n / a) * a;
const pad = (buf, a) => Buffer.concat([buf, Buffer.alloc(align(buf.length, a) - buf.length)]);

// Synthetic credentials (not real keys) for the hard-coded-secret scanner.
const FAKE_ALIBABA_KEY = 'LTAI' + 'K1DdemoFakeKey00';
const FAKE_AWS_KEY = 'AKIA' + 'K1DDEMO0FAKE0KEY';

// ---------------------------------------------------------------- certificates
run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', f('ca.key'), '-out', f('ca.pem'), '-days', '9125', '-subj', '/C=US/O=k1d Test CA/CN=k1d Test Root CA']);
run('openssl', ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', f('leaf.key'), '-out', f('leaf.csr'), '-subj', '/C=CN/ST=Guangdong/O=k1d Demo Studio/CN=k1d Demo Studio']);
run('openssl', ['x509', '-req', '-in', f('leaf.csr'), '-CA', f('ca.pem'), '-CAkey', f('ca.key'), '-CAcreateserial', '-out', f('leaf.pem'), '-days', '365']);
run('openssl', ['x509', '-in', f('leaf.pem'), '-outform', 'DER', '-out', f('leaf.der')]);
const leafDer = fs.readFileSync(f('leaf.der'));
fs.writeFileSync(f('payload.bin'), 'k1d');
run('openssl', ['cms', '-sign', '-binary', '-outform', 'DER', '-in', f('payload.bin'), '-signer', f('leaf.pem'), '-inkey', f('leaf.key'), '-certfile', f('ca.pem'), '-out', f('sig.p7')]);
const pkcs7 = fs.readFileSync(f('sig.p7'));
const expected = { note: 'Ground truth for tests/formats.test.mjs; signer certificate fingerprint from openssl.', signerSha256: sha256(leafDer) };

// ---------------------------------------------------------------- Electron app.asar
function asar(files) {
  const tree = { files: {} };
  const blobs = [];
  let offset = 0;
  for (const [p, data] of Object.entries(files)) {
    const parts = p.split('/');
    let node = tree;
    for (const dir of parts.slice(0, -1)) node = (node.files[dir] ??= { files: {} });
    node.files[parts.at(-1)] = { size: data.length, offset: String(offset) };
    blobs.push(data);
    offset += data.length;
  }
  const json = B(JSON.stringify(tree));
  const jsonPadded = pad(json, 4);
  const headerPickle = Buffer.concat([u32(4 + jsonPadded.length), u32(json.length), jsonPadded]);
  return Buffer.concat([u32(4), u32(headerPickle.length), headerPickle, ...blobs]);
}
const asarBuf = asar({
  'package.json': B(JSON.stringify({ name: 'idle-quest-desktop', productName: 'Idle Quest', version: '1.4.2', main: 'main.js', author: 'k1d Demo Studio', dependencies: { '@sentry/electron': '^5.0.0', 'electron-updater': '^6.0.0' } })),
  'main.js': B(`const api = "https://api.deepseek.com/chat/completions"; const cfg = "https://cfg.k1d-demo.cn/desktop"; const k = "${FAKE_AWS_KEY}";`),
  'node_modules/mixpanel/package.json': B('{"name":"mixpanel","version":"0.18.0"}'),
});
fs.writeFileSync(path.join(out, 'app.asar'), asarBuf);

// ---------------------------------------------------------------- Windows PE (PE32+) with imports, version info, manifest, Authenticode, zip overlay
function utf16z(s) { return Buffer.from(s + '\0', 'utf16le'); }
function verBlock(key, value, type, children = []) {
  const keyBuf = utf16z(key);
  let head = Buffer.concat([u16(0), u16(0), u16(type), keyBuf]);
  head = pad(head, 4);
  const val = value ?? Buffer.alloc(0);
  let body = pad(Buffer.concat([head, val]), 4);
  body = Buffer.concat([body, ...children.map((c) => pad(c, 4))]);
  body.writeUInt16LE(body.length, 0);
  body.writeUInt16LE(type === 1 ? val.length / 2 : val.length, 2);
  return body;
}
const versionStrings = { CompanyName: 'k1d Demo Studio', ProductName: 'Idle Quest', FileDescription: 'Idle Quest Launcher', FileVersion: '1.4.2.0', OriginalFilename: 'IdleQuest.exe', InternalName: 'IdleQuest' };
const fixed = Buffer.alloc(52); fixed.writeUInt32LE(0xfeef04bd, 0); fixed.writeUInt32LE(0x10000, 4);
const versionInfo = verBlock('VS_VERSION_INFO', fixed, 0, [
  verBlock('StringFileInfo', null, 1, [verBlock('040904b0', null, 1, Object.entries(versionStrings).map(([k, v]) => verBlock(k, utf16z(v), 1)))]),
]);
const manifestXml = B('<?xml version="1.0"?><assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><trustInfo><security><requestedPrivileges><requestedExecutionLevel level="requireAdministrator" uiAccess="false"/></requestedPrivileges></security></trustInfo></assembly>');

function buildPE() {
  const RDATA_RVA = 0x1000;
  const imports = { 'IPHLPAPI.DLL': ['GetAdaptersInfo'], 'USER32.dll': ['SetWindowsHookExW', 'GetClipboardData'], 'steam_api64.dll': ['SteamAPI_Init'] };
  // .rdata: descriptors, then per-DLL ILT + names
  const dlls = Object.keys(imports);
  const descSize = (dlls.length + 1) * 20;
  const chunks = [];
  let off = descSize;
  const desc = Buffer.alloc(descSize);
  dlls.forEach((dll, i) => {
    const fns = imports[dll];
    const iltOff = off; off += (fns.length + 1) * 8;
    const hnOffs = fns.map((fn) => { const o = off; off += align(2 + fn.length + 1, 2); return o; });
    const nameOff = off; off += align(dll.length + 1, 2);
    const ilt = Buffer.alloc((fns.length + 1) * 8);
    hnOffs.forEach((o, k) => ilt.writeBigUInt64LE(BigInt(RDATA_RVA + o), k * 8));
    chunks.push([iltOff, ilt]);
    fns.forEach((fn, k) => chunks.push([hnOffs[k], Buffer.concat([u16(0), B(fn + '\0')])]));
    chunks.push([nameOff, B(dll + '\0')]);
    desc.writeUInt32LE(RDATA_RVA + iltOff, i * 20);
    desc.writeUInt32LE(RDATA_RVA + nameOff, i * 20 + 12);
    desc.writeUInt32LE(RDATA_RVA + iltOff, i * 20 + 16);
  });
  const strOff = off;
  const strings = B(`\0https://telemetry.k1d-demo.cn/pc/v1\0${FAKE_ALIBABA_KEY}\0`);
  off += strings.length;
  const rdata = Buffer.alloc(align(off, 0x200));
  desc.copy(rdata, 0);
  for (const [o, b] of chunks) b.copy(rdata, o);
  strings.copy(rdata, strOff);

  // .rsrc: type(16: VERSION, 24: MANIFEST) -> name(1) -> lang(0x409) -> data entry
  const RSRC_RVA = 0x1000 + align(rdata.length, 0x1000);
  const dir = (entries) => Buffer.concat([Buffer.alloc(12), u16(0), u16(entries.length), ...entries.map(([id, target]) => Buffer.concat([u32(id), u32(target >>> 0)]))]);
  const types = [[16, versionInfo], [24, manifestXml]];
  // layout: root(16+2*8) | per type: nameDir(24) langDir(24) dataEntry(16) | data
  const rootSize = 16 + types.length * 8;
  let p = rootSize;
  const layout = types.map(([id, data]) => { const nameDir = p; p += 24; const langDir = p; p += 24; const entry = p; p += 16; return { id, data, nameDir, langDir, entry }; });
  p = align(p, 8);
  for (const l of layout) { l.dataOff = p; p = align(p + l.data.length, 8); }
  const rsrc = Buffer.alloc(align(p, 0x200));
  dir(layout.map((l) => [l.id, 0x80000000 | l.nameDir])).copy(rsrc, 0);
  for (const l of layout) {
    dir([[1, 0x80000000 | l.langDir]]).copy(rsrc, l.nameDir);
    dir([[0x409, l.entry]]).copy(rsrc, l.langDir);
    Buffer.concat([u32(RSRC_RVA + l.dataOff), u32(l.data.length), u32(0), u32(0)]).copy(rsrc, l.entry);
    l.data.copy(rsrc, l.dataOff);
  }

  const headers = Buffer.alloc(0x400);
  headers.write('MZ', 0, 'latin1');
  headers.writeUInt32LE(0x40, 0x3c);
  headers.write('PE\0\0', 0x40, 'latin1');
  const coff = 0x44;
  headers.writeUInt16LE(0x8664, coff); headers.writeUInt16LE(2, coff + 2); headers.writeUInt32LE(0x60000000, coff + 4);
  headers.writeUInt16LE(240, coff + 16); headers.writeUInt16LE(0x0022, coff + 18);
  const opt = coff + 20;
  headers.writeUInt16LE(0x20b, opt); headers.writeUInt32LE(0x1000, opt + 32); headers.writeUInt32LE(0x200, opt + 36);
  headers.writeUInt32LE(RSRC_RVA + align(rsrc.length, 0x1000), opt + 56); headers.writeUInt32LE(0x400, opt + 60);
  headers.writeUInt16LE(2, opt + 68); headers.writeUInt32LE(16, opt + 108);
  const dirAt = (i, rva, size) => { headers.writeUInt32LE(rva, opt + 112 + i * 8); headers.writeUInt32LE(size, opt + 116 + i * 8); };
  dirAt(1, RDATA_RVA, descSize);
  dirAt(2, RSRC_RVA, rsrc.length);
  const sec = (i, name, rva, raw, ptr) => { const s = opt + 240 + i * 40; headers.write(name, s, 'latin1'); headers.writeUInt32LE(raw, s + 8); headers.writeUInt32LE(rva, s + 12); headers.writeUInt32LE(raw, s + 16); headers.writeUInt32LE(ptr, s + 20); };
  sec(0, '.rdata', RDATA_RVA, rdata.length, 0x400);
  sec(1, '.rsrc', RSRC_RVA, rsrc.length, 0x400 + rdata.length);
  const overlay = writeZip([{ name: 'resources/app.asar', data: asarBuf, method: 0 }, { name: 'steam_api64.dll', data: B('MZ fake') }, { name: 'EasyAntiCheat_EOS_Setup.exe', data: B('MZ fake') }]);
  const body = Buffer.concat([headers, rdata, rsrc, overlay]);
  const certOff = align(body.length, 8);
  const winCert = pad(Buffer.concat([u32(8 + pkcs7.length), u16(0x0200), u16(2), pkcs7]), 8);
  winCert.writeUInt32LE(winCert.length, 0);
  const pe = Buffer.concat([pad(body, 8), winCert]);
  pe.writeUInt32LE(certOff, opt + 112 + 4 * 8);
  pe.writeUInt32LE(winCert.length, opt + 116 + 4 * 8);
  return pe;
}
fs.writeFileSync(path.join(out, 'IdleQuestSetup.exe'), buildPE());
expected.exe = { versionStrings, imports: ['IPHLPAPI.DLL', 'USER32.dll', 'steam_api64.dll'] };

// ---------------------------------------------------------------- MSIX
const appx = `<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10" xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="K1DDemo.IdleQuest" Publisher="CN=k1d Demo Studio, O=k1d Demo Studio, C=CN" Version="1.4.2.0" ProcessorArchitecture="x64"/>
  <Properties><DisplayName>Idle Quest</DisplayName><PublisherDisplayName>k1d Demo Studio</PublisherDisplayName></Properties>
  <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0"/></Dependencies>
  <Capabilities><Capability Name="internetClient"/><rescap:Capability Name="runFullTrust"/><DeviceCapability Name="location"/><DeviceCapability Name="webcam"/><DeviceCapability Name="microphone"/></Capabilities>
</Package>`;
fs.writeFileSync(path.join(out, 'IdleQuest.msix'), writeZip([
  { name: 'AppxManifest.xml', data: B(appx) },
  { name: 'AppxSignature.p7x', data: Buffer.concat([B('PKCX'), pkcs7]) },
  { name: 'config/endpoints.json', data: B(`{"api":"https://api.k1d-demo.cn/win","log":"https://k1d-demo-logs.cn-hangzhou.log.aliyuncs.com/w"}`) },
]));

// ---------------------------------------------------------------- Chrome extension (CRX3)
const extZip = writeZip([
  { name: 'manifest.json', data: B(JSON.stringify({ manifest_version: 3, name: 'Idle Quest Helper', version: '1.4.2', permissions: ['cookies', 'history', 'tabs', 'storage'], host_permissions: ['<all_urls>'], content_scripts: [{ matches: ['<all_urls>'], js: ['content.js'] }], background: { service_worker: 'bg.js' }, update_url: 'https://ext.k1d-demo.cn/update.xml' })) },
  { name: 'bg.js', data: B(`fetch("https://collect.k1d-demo.cn/ext/v1"); const key = "${FAKE_AWS_KEY}";`) },
  { name: 'content.js', data: B('document.title;') },
]);
const crxHeader = Buffer.from([0x12, 0x00]);
fs.writeFileSync(path.join(out, 'helper.crx'), Buffer.concat([B('Cr24'), u32(3), u32(crxHeader.length), crxHeader, extZip]));

// ---------------------------------------------------------------- HarmonyOS .hap
fs.writeFileSync(path.join(out, 'entry-default-signed.hap'), writeZip([
  { name: 'module.json', data: B(JSON.stringify({ app: { bundleName: 'com.k1d.demo.idlequest', vendor: 'k1d Demo Studio', versionCode: 1004002, versionName: '1.4.2', minAPIVersion: 12, targetAPIVersion: 12 }, module: { name: 'entry', type: 'entry', deviceTypes: ['phone', 'tablet'], requestPermissions: [{ name: 'ohos.permission.INTERNET' }, { name: 'ohos.permission.APPROXIMATELY_LOCATION', reason: '$string:loc_reason' }, { name: 'ohos.permission.APP_TRACKING_CONSENT' }, { name: 'ohos.permission.CAMERA' }], abilities: [{ name: 'EntryAbility', exported: true }] } })) },
  { name: 'ets/modules.abc', data: Buffer.concat([B('PANDA\0'), B('\0@umeng/common\0@umeng/analytics\0https://ulogs.umeng.com/h\0https://events.k1d-demo.cn/harmony\0')]) },
  { name: 'libs/arm64-v8a/libBugly.so', data: B('\x7fELF fake') },
  { name: 'resources.index', data: B('\0https://www.k1d-demo.example/privacy\0') },
]));

// ---------------------------------------------------------------- WeChat mini-program (.wxapkg)
function wxapkg(files) {
  const entries = Object.entries(files);
  const indexLen = 4 + entries.reduce((n, [name]) => n + 12 + Buffer.byteLength(name), 0);
  let dataOff = 14 + indexLen;
  const idx = [u32be(entries.length)];
  for (const [name, data] of entries) { const nb = B(name); idx.push(u32be(nb.length), nb, u32be(dataOff), u32be(data.length)); dataOff += data.length; }
  const head = Buffer.alloc(14); head[0] = 0xbe; head.writeUInt32BE(indexLen, 5); head.writeUInt32BE(dataOff - 14 - indexLen, 9); head[13] = 0xed;
  return Buffer.concat([head, ...idx, ...entries.map(([, d]) => d)]);
}
fs.writeFileSync(path.join(out, '__APP__.wxapkg'), wxapkg({
  '/app-config.json': B(JSON.stringify({ pages: ['pages/index/index'], permission: { 'scope.userLocation': { desc: '用于推荐附近的活动' } }, requiredPrivateInfos: ['getLocation'], plugins: { myPlugin: { provider: 'wx0000000000000000', version: '1.0.0' } }, global: { window: { navigationBarTitleText: 'Idle Quest' } } })),
  '/app-service.js': B('wx.getLocation({type:"gcj02"}); wx.request({url:"https://api.k1d-demo.cn/mp/v1"}); wx.request({url:"https://dashscope.aliyuncs.com/api/v1/services"}); wx.requestPayment({});'),
  '/pages/index/index.wxml': B('<button open-type="getPhoneNumber" bindgetphonenumber="onPhone">Login</button>'),
}));

// ---------------------------------------------------------------- macOS .app (zip) — re-rooted from the IPA fixture, plus Electron asar
{
  const ipa = await openZip(bytesSource(new Uint8Array(fs.readFileSync(path.join(root, 'tests', 'fixtures', 'k1d-demo.ipa')))));
  const entries = [];
  for (const e of ipa.entries) {
    if (!e.name.startsWith('Payload/IdleQuest.app/')) continue;
    let rel = e.name.slice('Payload/IdleQuest.app/'.length);
    if (rel === 'IdleQuest') rel = 'MacOS/IdleQuest';
    else if (rel === 'embedded.mobileprovision') continue;
    else {
      const m = /^Frameworks\/([^/]+)\.framework\/(.+)$/.exec(rel);
      if (m) rel = m[2] === 'Info.plist' ? `Frameworks/${m[1]}.framework/Versions/A/Resources/Info.plist` : `Frameworks/${m[1]}.framework/Versions/A/${m[2]}`;
    }
    entries.push({ name: `IdleQuest.app/Contents/${rel}`, data: Buffer.from(await ipa.readEntry(e)) });
  }
  entries.push({ name: 'IdleQuest.app/Contents/Resources/app.asar', data: asarBuf, method: 0 });
  fs.writeFileSync(path.join(out, 'IdleQuest-macos.zip'), writeZip(entries));
}

// ---------------------------------------------------------------- Linux ELF + .deb
function elf(needed, extra) {
  const dynstr = Buffer.concat([B('\0'), ...needed.map((n) => B(n + '\0'))]);
  const offsets = []; let o = 1; for (const n of needed) { offsets.push(o); o += n.length + 1; }
  const dynamic = Buffer.alloc((needed.length + 1) * 16);
  offsets.forEach((v, i) => { dynamic.writeBigInt64LE(1n, i * 16); dynamic.writeBigUInt64LE(BigInt(v), i * 16 + 8); });
  const rodata = B(extra);
  const shstr = B('\0.dynstr\0.dynamic\0.rodata\0.shstrtab\0');
  const parts = [dynstr, dynamic, rodata, shstr];
  let p = 64; const offs = parts.map((b) => { const r = p; p += align(b.length, 8); return r; });
  const shoff = p;
  const sh = (name, type, off, size, link) => { const b = Buffer.alloc(64); b.writeUInt32LE(name, 0); b.writeUInt32LE(type, 4); b.writeBigUInt64LE(BigInt(off), 24); b.writeBigUInt64LE(BigInt(size), 32); b.writeUInt32LE(link, 40); return b; };
  const shdrs = [Buffer.alloc(64), sh(1, 3, offs[0], dynstr.length, 0), sh(9, 6, offs[1], dynamic.length, 1), sh(18, 1, offs[2], rodata.length, 0), sh(26, 3, offs[3], shstr.length, 0)];
  const hdr = Buffer.alloc(64);
  hdr.write('\x7fELF', 0, 'latin1'); hdr[4] = 2; hdr[5] = 1; hdr[6] = 1;
  hdr.writeUInt16LE(3, 16); hdr.writeUInt16LE(0x3e, 18); hdr.writeUInt32LE(1, 20); hdr.writeBigUInt64LE(BigInt(shoff), 40);
  hdr.writeUInt16LE(64, 52); hdr.writeUInt16LE(64, 58); hdr.writeUInt16LE(shdrs.length, 60); hdr.writeUInt16LE(4, 62);
  return Buffer.concat([hdr, ...parts.map((b) => pad(b, 8)), ...shdrs]);
}
const elfBin = elf(['libsteam_api.so', 'libc.so.6'], `\0https://telemetry.k1d-demo.cn/linux\0${FAKE_ALIBABA_KEY}\0`);
fs.writeFileSync(path.join(out, 'idlequest'), elfBin);

function tar(files) {
  const blocks = [];
  for (const [name, data] of Object.entries(files)) {
    const h = Buffer.alloc(512);
    h.write(name, 0, 'utf8'); h.write('0000755\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
    h.write(data.length.toString(8).padStart(11, '0') + '\0', 124); h.write('00000000000\0', 136);
    h.write('        ', 148); h.write('0', 156); h.write('ustar\0', 257); h.write('00', 263);
    let sum = 0; for (const b of h) sum += b;
    h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
    blocks.push(h, pad(data, 512));
  }
  return Buffer.concat([...blocks, Buffer.alloc(1024)]);
}
function ar(members) {
  const parts = [B('!<arch>\n')];
  for (const [name, data] of members) {
    const h = B(`${name.padEnd(16)}${'0'.padEnd(12)}${'0'.padEnd(6)}${'0'.padEnd(6)}${'100644'.padEnd(8)}${String(data.length).padEnd(10)}\`\n`);
    parts.push(h, data, data.length % 2 ? B('\n') : Buffer.alloc(0));
  }
  return Buffer.concat(parts);
}
fs.writeFileSync(path.join(out, 'idlequest_1.4.2_amd64.deb'), ar([
  ['debian-binary', B('2.0\n')],
  ['control.tar.gz', zlib.gzipSync(tar({ './control': B('Package: idlequest\nVersion: 1.4.2\nArchitecture: amd64\nMaintainer: k1d Demo Studio <dev@k1d-demo.example>\nHomepage: https://www.k1d-demo.example\n') }))],
  ['data.tar.gz', zlib.gzipSync(tar({ './opt/idlequest/idlequest': elfBin, './opt/idlequest/resources/app.asar': asarBuf, './usr/share/applications/idlequest.desktop': B('[Desktop Entry]\nName=Idle Quest\nExec=/opt/idlequest/idlequest\nURL=https://www.k1d-demo.example\n') }))],
]));

// ---------------------------------------------------------------- RPM (lead + signature header + main header; no payload)
function rpmHeader(tags) {
  const idx = []; const store = [];
  let off = 0;
  for (const [tag, type, val] of tags) {
    const data = type === 8 ? Buffer.concat(val.map((s) => B(s + '\0'))) : B(val + '\0');
    idx.push(Buffer.concat([u32be(tag), u32be(type), u32be(off), u32be(type === 8 ? val.length : 1)]));
    store.push(data); off += data.length;
  }
  const s = Buffer.concat(store);
  return Buffer.concat([Buffer.from([0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0]), u32be(tags.length), u32be(s.length), ...idx, s]);
}
const lead = Buffer.alloc(96); lead.set([0xed, 0xab, 0xee, 0xdb, 3, 0]);
const sigHdr = rpmHeader([]);
fs.writeFileSync(path.join(out, 'idlequest-1.4.2-1.x86_64.rpm'), Buffer.concat([lead, pad(sigHdr, 8), rpmHeader([
  [1000, 6, 'idlequest'], [1001, 6, '1.4.2'], [1002, 6, '1'], [1004, 9, 'Idle Quest desktop client'], [1011, 6, 'k1d Demo Studio'],
  [1020, 6, 'https://www.k1d-demo.example'], [1022, 6, 'x86_64'], [1049, 8, ['libc.so.6', 'libsteam_api.so']], [1117, 8, ['idlequest', 'libsteam_api.so', 'app.asar']],
])]));

// ---------------------------------------------------------------- macOS installer .pkg (xar)
{
  const dist = B('<?xml version="1.0"?><installer-gui-script minSpecVersion="2"><title>Idle Quest</title><pkg-ref id="com.k1d.demo.idlequest.pkg" version="1.4.2" onConclusion="none">idlequest.pkg</pkg-ref></installer-gui-script>');
  const pinfo = B('<?xml version="1.0"?><pkg-info identifier="com.k1d.demo.idlequest.pkg" version="1.4.2" install-location="/Applications"><bundle id="com.k1d.demo.idlequest" path="./IdleQuest.app"/><scripts><postinstall file="./postinstall"/></scripts></pkg-info>');
  const post = B('#!/bin/sh\ncurl -s https://install.k1d-demo.cn/ping\n');
  const certB64 = leafDer.toString('base64');
  const fileXml = (id, name, off, data) => `<file id="${id}"><name>${name}</name><type>file</type><data><length>${data.length}</length><offset>${off}</offset><size>${data.length}</size><encoding style="application/octet-stream"/></data></file>`;
  const toc = B(`<?xml version="1.0" encoding="UTF-8"?><xar><toc><signature style="RSA"><offset>0</offset><size>256</size><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>${certB64}</X509Certificate></X509Data></KeyInfo></signature>${fileXml(1, 'Distribution', 256, dist)}<file id="2"><name>idlequest.pkg</name><type>directory</type>${fileXml(3, 'PackageInfo', 256 + dist.length, pinfo)}<file id="4"><name>Scripts</name><type>directory</type>${fileXml(5, 'postinstall', 256 + dist.length + pinfo.length, post)}</file></file></toc></xar>`);
  const tocZ = zlib.deflateSync(toc);
  const hdr = Buffer.alloc(28);
  hdr.write('xar!', 0, 'latin1'); hdr.writeUInt16BE(28, 4); hdr.writeUInt16BE(1, 6);
  hdr.writeBigUInt64BE(BigInt(tocZ.length), 8); hdr.writeBigUInt64BE(BigInt(toc.length), 16); hdr.writeUInt32BE(0, 24);
  fs.writeFileSync(path.join(out, 'IdleQuest.pkg'), Buffer.concat([hdr, tocZ, Buffer.alloc(256), dist, pinfo, post]));
}

fs.writeFileSync(path.join(root, 'tests', 'fixtures', 'formats-expected.json'), JSON.stringify(expected, null, 2) + '\n');
fs.rmSync(work, { recursive: true, force: true });
console.log('Wrote', fs.readdirSync(out).join(', '));
