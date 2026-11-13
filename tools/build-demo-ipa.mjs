// Builds tests/fixtures/k1d-demo.ipa: a synthetic, non-functional iOS app bundle with the structures
// the analyzer reads (binary + XML plists, Mach-O load commands and sections, code signature with
// CMS from openssl, privacy manifests, frameworks, provisioning profile, store metadata).
// Usage: node tools/build-demo-ipa.mjs   (needs openssl)
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeZip } from './ziplib.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outIpa = path.join(root, 'tests', 'fixtures', 'k1d-demo.ipa');
const expectedOut = path.join(root, 'tests', 'fixtures', 'ios-expected.json');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'k1d-ipa-'));
const run = (cmd, args) => execFileSync(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });

// ---------------------------------------------------------------- plist writers
function xmlEsc(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function xmlValue(v, ind = '') {
  if (v === true) return `${ind}<true/>`;
  if (v === false) return `${ind}<false/>`;
  if (typeof v === 'number') return `${ind}<integer>${v}</integer>`;
  if (typeof v === 'string') return `${ind}<string>${xmlEsc(v)}</string>`;
  if (Array.isArray(v)) return `${ind}<array>\n${v.map((x) => xmlValue(x, ind + '\t')).join('\n')}\n${ind}</array>`;
  return `${ind}<dict>\n${Object.entries(v).map(([k, x]) => `${ind}\t<key>${xmlEsc(k)}</key>\n${xmlValue(x, ind + '\t')}`).join('\n')}\n${ind}</dict>`;
}
function xmlPlist(v) {
  return Buffer.from(`<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n${xmlValue(v)}\n</plist>\n`);
}

// Binary plist (bplist00) writer, following Apple's CFBinaryPList format.
function binaryPlist(top) {
  const objects = [];
  const flatten = (v) => {
    const idx = objects.length;
    objects.push(null);
    if (Array.isArray(v)) objects[idx] = { t: 'array', refs: v.map(flatten) };
    else if (v && typeof v === 'object') {
      const ks = Object.keys(v);
      const keyRefs = ks.map(flatten);
      const valRefs = ks.map((k) => flatten(v[k]));
      objects[idx] = { t: 'dict', keyRefs, valRefs };
    } else objects[idx] = { t: 'scalar', v };
    return idx;
  };
  flatten(top);
  const refSize = 2;
  const header = (type, len) => (len < 15 ? Buffer.from([(type << 4) | len]) : Buffer.concat([Buffer.from([(type << 4) | 0xf]), intObj(len)]));
  function intObj(n) {
    if (n < 0x100) return Buffer.from([0x10, n]);
    if (n < 0x10000) { const b = Buffer.alloc(3); b[0] = 0x11; b.writeUInt16BE(n, 1); return b; }
    const b = Buffer.alloc(5); b[0] = 0x12; b.writeUInt32BE(n, 1); return b;
  }
  const refs = (list) => Buffer.concat(list.map((r) => { const b = Buffer.alloc(2); b.writeUInt16BE(r); return b; }));
  const enc = (o) => {
    if (o.t === 'array') return Buffer.concat([header(0xa, o.refs.length), refs(o.refs)]);
    if (o.t === 'dict') return Buffer.concat([header(0xd, o.keyRefs.length), refs(o.keyRefs), refs(o.valRefs)]);
    const v = o.v;
    if (v === true) return Buffer.from([0x09]);
    if (v === false) return Buffer.from([0x08]);
    if (typeof v === 'number') return intObj(v);
    const s = String(v);
    // eslint-disable-next-line no-control-regex
    if (/^[\x00-\x7f]*$/.test(s)) return Buffer.concat([header(0x5, s.length), Buffer.from(s, 'latin1')]);
    const u = Buffer.from(s, 'utf16le').swap16();
    return Buffer.concat([header(0x6, s.length), u]);
  };
  const body = [Buffer.from('bplist00', 'latin1')];
  const offsets = [];
  let pos = 8;
  for (const o of objects) { const b = enc(o); offsets.push(pos); body.push(b); pos += b.length; }
  const tableOffset = pos;
  const offTable = Buffer.alloc(objects.length * 4);
  offsets.forEach((o, i) => offTable.writeUInt32BE(o, i * 4));
  const trailer = Buffer.alloc(32);
  trailer[6] = 4; trailer[7] = refSize;
  trailer.writeBigUInt64BE(BigInt(objects.length), 8);
  trailer.writeBigUInt64BE(0n, 16);
  trailer.writeBigUInt64BE(BigInt(tableOffset), 24);
  return Buffer.concat([...body, offTable, trailer]);
}

// ---------------------------------------------------------------- Mach-O writer (thin arm64)
function name16(s) { const b = Buffer.alloc(16); b.write(s, 'latin1'); return b; }
function cstrings(list) { return Buffer.concat(list.map((s) => Buffer.from(s + '\0', 'utf8'))); }
function align(n, a) { return Math.ceil(n / a) * a; }

function machO({ cstrs = [], classNames = [], dylibs = [], encrypted = false, minOS = '15.0', signature = null, filetype = 2 }) {
  const cstrData = cstrings(cstrs);
  const clsData = cstrings(classNames);
  const cmds = [];
  // LC_SEGMENT_64 __TEXT with __cstring + __objc_classname (offsets patched below)
  const nsects = 2;
  const seg = Buffer.alloc(72 + nsects * 80);
  seg.writeUInt32LE(0x19, 0); seg.writeUInt32LE(seg.length, 4); name16('__TEXT').copy(seg, 8);
  seg.writeUInt32LE(nsects, 64);
  cmds.push(seg);
  for (const d of dylibs) {
    const nameOff = 24;
    const size = align(nameOff + Buffer.byteLength(d) + 1, 8);
    const c = Buffer.alloc(size);
    c.writeUInt32LE(0xc, 0); c.writeUInt32LE(size, 4); c.writeUInt32LE(nameOff, 8); c.writeUInt32LE(2, 12);
    c.write(d, nameOff, 'utf8');
    cmds.push(c);
  }
  const ver = (s) => { const [a, b = 0, c = 0] = s.split('.').map(Number); return (a << 16) | (b << 8) | c; };
  const bv = Buffer.alloc(24);
  bv.writeUInt32LE(0x32, 0); bv.writeUInt32LE(24, 4); bv.writeUInt32LE(2, 8); bv.writeUInt32LE(ver(minOS), 12); bv.writeUInt32LE(ver('18.0'), 16);
  cmds.push(bv);
  const enc = Buffer.alloc(24);
  enc.writeUInt32LE(0x2c, 0); enc.writeUInt32LE(24, 4);
  cmds.push(enc);
  const cs = Buffer.alloc(16);
  cs.writeUInt32LE(0x1d, 0); cs.writeUInt32LE(16, 4);
  if (signature) cmds.push(cs);

  const sizeofcmds = cmds.reduce((n, c) => n + c.length, 0);
  const headerSize = 32;
  const cstrOff = align(headerSize + sizeofcmds, 16);
  const clsOff = cstrOff + cstrData.length;
  const textEnd = align(clsOff + clsData.length, 16);
  // sections
  const sect = (i, sectname, off, size) => {
    const s = 72 + i * 80;
    name16(sectname).copy(seg, s); name16('__TEXT').copy(seg, s + 16);
    seg.writeBigUInt64LE(BigInt(size), s + 40); // size
    seg.writeUInt32LE(off, s + 48); // file offset
  };
  sect(0, '__cstring', cstrOff, cstrData.length);
  sect(1, '__objc_classname', clsOff, clsData.length);
  seg.writeBigUInt64LE(BigInt(textEnd), 48); // filesize
  // encryption covers the string sections when encrypted
  enc.writeUInt32LE(cstrOff, 8); enc.writeUInt32LE(textEnd - cstrOff, 12); enc.writeUInt32LE(encrypted ? 1 : 0, 16);
  const sigOff = textEnd;
  if (signature) { cs.writeUInt32LE(sigOff, 8); cs.writeUInt32LE(signature.length, 12); }

  const header = Buffer.alloc(32);
  header.writeUInt32LE(0xfeedfacf, 0); header.writeUInt32LE(0x0100000c, 4); header.writeUInt32LE(0, 8);
  header.writeUInt32LE(filetype, 12); header.writeUInt32LE(cmds.length, 16); header.writeUInt32LE(sizeofcmds, 20);
  const body = Buffer.alloc(textEnd);
  header.copy(body, 0);
  Buffer.concat(cmds).copy(body, headerSize);
  let text = Buffer.concat([cstrData, clsData]);
  if (encrypted) text = Buffer.from(text.map((b) => b ^ 0xa5)); // stand-in for FairPlay ciphertext
  text.copy(body, cstrOff);
  return signature ? Buffer.concat([body, signature]) : body;
}

// ---------------------------------------------------------------- code signature
function blob(magic, payload) {
  const b = Buffer.alloc(8);
  b.writeUInt32BE(magic, 0); b.writeUInt32BE(8 + payload.length, 4);
  return Buffer.concat([b, payload]);
}
function codeDirectory(identifier, teamId) {
  const hdr = Buffer.alloc(88);
  const ident = Buffer.from(identifier + '\0');
  const team = Buffer.from(teamId + '\0');
  hdr.writeUInt32BE(0xfade0c02, 0);
  hdr.writeUInt32BE(88 + ident.length + team.length, 4);
  hdr.writeUInt32BE(0x20400, 8); // version
  hdr.writeUInt32BE(88 + ident.length + team.length, 16); // hashOffset
  hdr.writeUInt32BE(88, 20); // identOffset
  hdr[36] = 32; hdr[37] = 2; hdr[39] = 12;
  hdr.writeUInt32BE(88 + ident.length, 48); // teamOffset
  return Buffer.concat([hdr, ident, team]);
}
function superBlob(blobs) {
  const count = blobs.length;
  let off = 12 + count * 8;
  const index = Buffer.alloc(count * 8);
  blobs.forEach(([type, b], i) => { index.writeUInt32BE(type, i * 8); index.writeUInt32BE(off, i * 8 + 4); off += b.length; });
  const head = Buffer.alloc(12);
  head.writeUInt32BE(0xfade0cc0, 0); head.writeUInt32BE(off, 4); head.writeUInt32BE(count, 8);
  return Buffer.concat([head, index, ...blobs.map(([, b]) => b)]);
}

// ---------------------------------------------------------------- certificates via openssl
const f = (n) => path.join(work, n);
run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', f('ca.key'), '-out', f('ca.pem'), '-days', '9125', '-subj', '/C=US/O=k1d Test CA/CN=k1d Test Root CA']);
run('openssl', ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', f('leaf.key'), '-out', f('leaf.csr'),
  '-subj', '/UID=K1DTEAM123/CN=Apple Distribution: k1d Demo Studio (K1DTEAM123)/OU=K1DTEAM123/O=k1d Demo Studio/C=CN']);
run('openssl', ['x509', '-req', '-in', f('leaf.csr'), '-CA', f('ca.pem'), '-CAkey', f('ca.key'), '-CAcreateserial', '-out', f('leaf.pem'), '-days', '365']);
run('openssl', ['x509', '-in', f('leaf.pem'), '-outform', 'DER', '-out', f('leaf.der')]);
const leafSha256 = createHash('sha256').update(fs.readFileSync(f('leaf.der'))).digest('hex');

const teamId = 'K1DTEAM123';
const bundleId = 'com.k1d.demo.idlequest';
const entitlements = {
  'application-identifier': `${teamId}.${bundleId}`,
  'com.apple.developer.team-identifier': teamId,
  'aps-environment': 'production',
  'com.apple.developer.associated-domains': ['applinks:link.k1d-demo.example', 'applinks:*.k1d-demo.example'],
  'keychain-access-groups': [`${teamId}.${bundleId}`],
};
const cd = codeDirectory(bundleId, teamId);
fs.writeFileSync(f('cd.bin'), cd);
run('openssl', ['cms', '-sign', '-binary', '-noattr', '-outform', 'DER', '-in', f('cd.bin'), '-signer', f('leaf.pem'), '-inkey', f('leaf.key'), '-certfile', f('ca.pem'), '-out', f('cd.cms')]);
const signature = superBlob([
  [0, cd],
  [5, blob(0xfade7171, xmlPlist(entitlements))],
  [0x10000, blob(0xfade0b01, fs.readFileSync(f('cd.cms')))],
]);

// provisioning profile: CMS-wrapped XML plist
const profile = {
  AppIDName: 'Idle Quest', Name: 'Idle Quest Ad Hoc', TeamName: 'k1d Demo Studio', TeamIdentifier: [teamId],
  CreationDate: '2026-11-01T00:00:00Z', ExpirationDate: '2027-11-01T00:00:00Z',
  ProvisionedDevices: ['00008110-000000000000001E', '00008110-000000000000002E'], Entitlements: entitlements,
};
fs.writeFileSync(f('profile.plist'), xmlPlist(profile));
run('openssl', ['cms', '-sign', '-nodetach', '-binary', '-outform', 'DER', '-in', f('profile.plist'), '-signer', f('leaf.pem'), '-inkey', f('leaf.key'), '-out', f('embedded.mobileprovision')]);

// ---------------------------------------------------------------- bundle contents
const app = 'Payload/IdleQuest.app/';
const info = {
  CFBundleIdentifier: bundleId, CFBundleExecutable: 'IdleQuest', CFBundleDisplayName: 'Idle Quest', CFBundleName: 'IdleQuest',
  CFBundleShortVersionString: '1.4.2', CFBundleVersion: '42', MinimumOSVersion: '15.0', DTPlatformVersion: '18.0', DTSDKName: 'iphoneos18.0',
  UIDeviceFamily: [1, 2],
  NSLocationWhenInUseUsageDescription: 'Find nearby players and events.',
  NSCameraUsageDescription: 'Scan QR codes to join guilds.',
  NSMicrophoneUsageDescription: 'Voice chat with your guild.',
  NSPhotoLibraryUsageDescription: 'Save screenshots of your base.',
  NSUserTrackingUsageDescription: 'Your data will be used to deliver personalized ads to you.',
  GADApplicationIdentifier: 'ca-app-pub-0000000000000000~0000000000',
  FacebookAppID: '1234567890', FacebookClientToken: 'k1ddemo0000000000000000000000000',
  CFBundleURLTypes: [{ CFBundleURLSchemes: ['fb1234567890', 'wx0123456789abcdef', 'idlequest'] }],
  LSApplicationQueriesSchemes: ['weixin', 'weixinULAPI', 'mqq', 'fbapi'],
  NSAppTransportSecurity: { NSAllowsArbitraryLoads: true, NSExceptionDomains: { 'log.k1d-demo.cn': { NSExceptionAllowsInsecureHTTPLoads: true, NSIncludesSubdomains: true } } },
  UIBackgroundModes: ['location', 'remote-notification'],
  K1DRemoteConfigURL: 'https://cfg.k1d-demo.cn/ios/v3',
  '中文名称': '放置冒险',
};
const privacy = (tracking, domains, collected) => xmlPlist({
  NSPrivacyTracking: tracking,
  NSPrivacyTrackingDomains: domains,
  NSPrivacyCollectedDataTypes: collected.map(([type, linked, track, purpose]) => ({
    NSPrivacyCollectedDataType: `NSPrivacyCollectedDataType${type}`, NSPrivacyCollectedDataTypeLinked: linked,
    NSPrivacyCollectedDataTypeTracking: track, NSPrivacyCollectedDataTypePurposes: [`NSPrivacyCollectedDataTypePurpose${purpose}`],
  })),
  NSPrivacyAccessedAPITypes: [{ NSPrivacyAccessedAPIType: 'NSPrivacyAccessedAPICategoryUserDefaults', NSPrivacyAccessedAPITypeReasons: ['CA92.1'] }],
});
const fwPlist = (exe, id, v) => xmlPlist({ CFBundleExecutable: exe, CFBundleIdentifier: id, CFBundleShortVersionString: v, CFBundlePackageType: 'FMWK' });

const SYS = ['Foundation', 'UIKit', 'AdSupport', 'AppTrackingTransparency', 'StoreKit', 'CoreLocation', 'AVFoundation'];
const entries = [
  { name: 'iTunesMetadata.plist', data: xmlPlist({ artistName: 'k1d Demo Studio', itemName: 'Idle Quest', itemId: 1234567890, genre: 'Games', softwareVersionBundleId: bundleId }) },
  { name: app + 'Info.plist', data: binaryPlist(info) },
  { name: app + 'IdleQuest', data: machO({
    cstrs: ['https://events.k1d-demo.cn/v1/track', 'https://k1d-demo-logs.cn-hangzhou.log.aliyuncs.com/ios', 'https://launches.appsflyer.com/api/', 'https://app-measurement.com/a', 'device_id'],
    classNames: ['AppDelegate', 'IQGameViewController', 'BUAdSDKManager', 'UMConfigure', 'JPUSHService', 'GADMobileAds', 'FIRAnalytics'],
    dylibs: [...SYS.map((n) => `/System/Library/Frameworks/${n}.framework/${n}`), '/usr/lib/libz.1.dylib',
      '@rpath/FBSDKCoreKit.framework/FBSDKCoreKit', '@rpath/AppsFlyerLib.framework/AppsFlyerLib', '@rpath/PAGAdSDK.framework/PAGAdSDK', '@rpath/UnityFramework.framework/UnityFramework'],
    signature,
  }) },
  { name: app + 'embedded.mobileprovision', data: fs.readFileSync(f('embedded.mobileprovision')) },
  { name: app + 'PrivacyInfo.xcprivacy', data: privacy(false, [], [['PreciseLocation', true, false, 'AppFunctionality'], ['PurchaseHistory', true, false, 'AppFunctionality'], ['GameplayContent', true, false, 'AppFunctionality']]) },
  { name: app + 'GoogleService-Info.plist', data: xmlPlist({ GOOGLE_APP_ID: '1:000000000000:ios:0000000000000000', DATABASE_URL: 'https://k1d-demo.firebaseio.com', PROJECT_ID: 'k1d-demo' }) },
  { name: app + 'config/endpoints.json', data: Buffer.from(JSON.stringify({ backup: 'https://k1d-demo-backup.cos.ap-guangzhou.myqcloud.com/cfg.json' })) },
  // Frameworks
  { name: app + 'Frameworks/FBSDKCoreKit.framework/Info.plist', data: fwPlist('FBSDKCoreKit', 'com.facebook.sdk.FBSDKCoreKit', '17.0.0') },
  { name: app + 'Frameworks/FBSDKCoreKit.framework/FBSDKCoreKit', data: machO({ cstrs: ['https://graph.facebook.com/v19.0'], classNames: ['FBSDKApplicationDelegate'], filetype: 6 }) },
  { name: app + 'Frameworks/FBSDKCoreKit.framework/PrivacyInfo.xcprivacy', data: privacy(true, ['ep1.facebook.com'], [['DeviceID', true, true, 'ThirdPartyAdvertising'], ['ProductInteraction', true, true, 'Analytics']]) },
  { name: app + 'Frameworks/AppsFlyerLib.framework/Info.plist', data: fwPlist('AppsFlyerLib', 'com.appsflyer.AppsFlyerLib', '6.15.0') },
  { name: app + 'Frameworks/AppsFlyerLib.framework/AppsFlyerLib', data: machO({ cstrs: ['https://launches.appsflyer.com/api/'], classNames: ['AppsFlyerLib'], filetype: 6 }) },
  { name: app + 'Frameworks/PAGAdSDK.framework/Info.plist', data: fwPlist('PAGAdSDK', 'com.bytedance.PAGAdSDK', '6.2.0') },
  { name: app + 'Frameworks/PAGAdSDK.framework/PAGAdSDK', data: machO({ cstrs: ['https://must-not-appear.k1d-demo.example/'], classNames: ['PAGSdk'], encrypted: true, filetype: 6 }) },
  { name: app + 'PAGAdSDK.bundle/PrivacyInfo.xcprivacy', data: privacy(true, ['api16-access-sg.pangle.io'], [['DeviceID', false, true, 'ThirdPartyAdvertising'], ['CoarseLocation', false, false, 'ThirdPartyAdvertising']]) },
  { name: app + 'Frameworks/UnityFramework.framework/Info.plist', data: fwPlist('UnityFramework', 'com.unity3d.framework', '2022.3') },
  { name: app + 'Frameworks/UnityFramework.framework/UnityFramework', data: machO({ cstrs: ['UnityPlayer'], filetype: 6 }) },
  { name: app + 'Frameworks/libswiftCore.dylib', data: machO({ filetype: 6 }) },
  // App extension
  { name: app + 'PlugIns/NotificationService.appex/Info.plist', data: xmlPlist({ CFBundleExecutable: 'NotificationService', CFBundleIdentifier: `${bundleId}.NotificationService`, NSExtension: { NSExtensionPointIdentifier: 'com.apple.usernotifications.service' } }) },
  { name: app + 'PlugIns/NotificationService.appex/NotificationService', data: machO({ cstrs: ['https://push.k1d-demo.cn/ack'], classNames: ['NotificationService'] }) },
];
const ipa = writeZip(entries);
fs.mkdirSync(path.dirname(outIpa), { recursive: true });
fs.writeFileSync(outIpa, ipa);

fs.writeFileSync(expectedOut, JSON.stringify({
  note: 'Ground truth for tests/ios.test.mjs. Values written by tools/build-demo-ipa.mjs; certificate fingerprint computed by openssl.',
  bundleId, version: '1.4.2', build: '42', minimumOS: '15.0', teamId,
  leafCertSha256: leafSha256,
  usageKeys: Object.keys(info).filter((k) => k.endsWith('UsageDescription')),
  linkedSystem: [...SYS].sort(),
  frameworks: ['AppsFlyerLib', 'FBSDKCoreKit', 'PAGAdSDK', 'UnityFramework'],
  expectedSdks: ['pangle', 'umeng', 'jpush', 'wechat_opensdk', 'qq_connect', 'meta_sdk', 'google_mobile_ads', 'firebase_analytics', 'appsflyer', 'unity_engine'],
  notExpectedSdks: ['tencent_gdt', 'applovin', 'google_play_billing'],
  ipaSha256: createHash('sha256').update(ipa).digest('hex'),
}, null, 2) + '\n');
fs.rmSync(work, { recursive: true, force: true });
console.log(`Wrote ${path.relative(root, outIpa)} (${ipa.length} bytes); leaf cert sha256 ${leafSha256}`);
