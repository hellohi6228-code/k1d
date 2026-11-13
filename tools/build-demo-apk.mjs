// Builds site/demo/k1d-demo.apk: a synthetic, non-functional APK that contains the
// signatures the analyzer looks for. It is used for the "Try the demo" button and tests.
//
// Requires: Android SDK build-tools (aapt2) + platform android.jar, and openssl.
// Usage: node tools/build-demo-apk.mjs
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { writeZip } from './ziplib.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const src = path.join(root, 'tools', 'demo-src');
const outApk = path.join(root, 'tests', 'fixtures', 'k1d-demo.apk');
const expectedOut = path.join(root, 'tests', 'fixtures', 'demo-expected.json');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'k1d-demo-'));

// ---------- locate tools ----------
function findSdk() {
  const candidates = [process.env.ANDROID_HOME, process.env.ANDROID_SDK_ROOT, path.join(os.homedir(), 'AppData/Local/Android/Sdk'), path.join(os.homedir(), 'Android/Sdk'), path.join(os.homedir(), 'Library/Android/sdk')];
  const sdk = candidates.find((c) => c && fs.existsSync(c));
  if (!sdk) throw new Error('Android SDK not found; set ANDROID_HOME');
  const bt = fs.readdirSync(path.join(sdk, 'build-tools')).sort().reverse()[0];
  const platform = fs.readdirSync(path.join(sdk, 'platforms')).sort().reverse()[0];
  const exe = process.platform === 'win32' ? '.exe' : '';
  return {
    aapt2: path.join(sdk, 'build-tools', bt, 'aapt2' + exe),
    dexdump: path.join(sdk, 'build-tools', bt, 'dexdump' + exe),
    androidJar: path.join(sdk, 'platforms', platform, 'android.jar'),
  };
}
const tools = findSdk();
function run(cmd, args) {
  try {
    return execFileSync(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] }).toString();
  } catch (e) {
    throw new Error(`${path.basename(cmd)} failed: ${e.stderr?.toString() || e.message}`);
  }
}

// ---------- 1. manifest + resources via aapt2 ----------
const compiled = path.join(work, 'res.zip');
run(tools.aapt2, ['compile', '--dir', path.join(src, 'res'), '-o', compiled]);
const linked = path.join(work, 'linked');
fs.mkdirSync(linked);
run(tools.aapt2, ['link', '-o', linked, '--output-to-dir', '-I', tools.androidJar, '--manifest', path.join(src, 'AndroidManifest.xml'), compiled]);

// ---------- 2. DEX files with SDK class names + embedded strings ----------
function uleb(n) {
  const out = [];
  do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; out.push(b); } while (n);
  return out;
}
function adler32(buf) {
  let a = 1, b = 0;
  for (const x of buf) { a = (a + x) % 65521; b = (b + a) % 65521; }
  return ((b << 16) | a) >>> 0;
}
function buildDex(classNames, extraStrings) {
  const types = classNames.map((c) => 'L' + c.replace(/\./g, '/') + ';');
  const strings = [...new Set([...types, ...extraStrings])].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
  const typeIdx = types.map((t) => strings.indexOf(t)).sort((a, b) => a - b);
  const stringIdsOff = 0x70;
  const typeIdsOff = stringIdsOff + strings.length * 4;
  const dataOff = typeIdsOff + typeIdx.length * 4;
  const data = [];
  const stringOffsets = [];
  for (const s of strings) {
    stringOffsets.push(dataOff + data.length);
    const bytes = Buffer.from(s, 'utf8');
    data.push(...uleb(s.length), ...bytes, 0);
  }
  while (data.length % 4) data.push(0);
  const mapOff = dataOff + data.length;
  const mapItems = [
    [0x0000, 1, 0],
    [0x0001, strings.length, stringIdsOff],
    [0x0002, typeIdx.length, typeIdsOff],
    [0x2002, strings.length, dataOff],
    [0x1000, 1, mapOff],
  ];
  const fileSize = mapOff + 4 + mapItems.length * 12;
  const buf = Buffer.alloc(fileSize);
  buf.write('dex\n035\0', 0, 'latin1');
  buf.writeUInt32LE(fileSize, 32);
  buf.writeUInt32LE(0x70, 36);
  buf.writeUInt32LE(0x12345678, 40);
  buf.writeUInt32LE(mapOff, 52);
  buf.writeUInt32LE(strings.length, 56);
  buf.writeUInt32LE(stringIdsOff, 60);
  buf.writeUInt32LE(typeIdx.length, 64);
  buf.writeUInt32LE(typeIdsOff, 68);
  buf.writeUInt32LE(fileSize - dataOff, 104);
  buf.writeUInt32LE(dataOff, 108);
  stringOffsets.forEach((o, i) => buf.writeUInt32LE(o, stringIdsOff + i * 4));
  typeIdx.forEach((t, i) => buf.writeUInt32LE(t, typeIdsOff + i * 4));
  Buffer.from(data).copy(buf, dataOff);
  buf.writeUInt32LE(mapItems.length, mapOff);
  mapItems.forEach(([type, size, off], i) => {
    const p = mapOff + 4 + i * 12;
    buf.writeUInt16LE(type, p);
    buf.writeUInt32LE(size, p + 4);
    buf.writeUInt32LE(off, p + 8);
  });
  createHash('sha1').update(buf.subarray(32)).digest().copy(buf, 12);
  buf.writeUInt32LE(adler32(buf.subarray(12)), 8);
  return buf;
}

const dex1Classes = [
  'com.k1d.demo.idlequest.MainActivity',
  'com.k1d.demo.idlequest.PromoReceiver',
  'com.k1d.demo.idlequest.net.EventUploader',
  'com.bytedance.sdk.openadsdk.TTAdSdk',
  'com.bytedance.sdk.openadsdk.TTAdConfig',
  'com.bytedance.sdk.openadsdk.TTAdNative',
  'com.bytedance.sdk.openadsdk.activity.TTFullScreenVideoActivity',
  'com.umeng.analytics.MobclickAgent',
  'com.umeng.commonsdk.UMConfigure',
  'com.umeng.commonsdk.statistics.common.DeviceConfig',
  'cn.jpush.android.api.JPushInterface',
  'cn.jpush.android.service.PushService',
  'cn.jiguang.api.JCoreInterface',
  'com.tencent.bugly.crashreport.CrashReport',
  'com.tencent.bugly.Bugly',
  'com.android.billingclient.api.BillingClient',
  'com.android.billingclient.api.BillingFlowParams',
];
const dex2Classes = [
  'com.google.firebase.analytics.FirebaseAnalytics',
  'com.google.android.gms.measurement.AppMeasurement',
  'com.google.android.gms.measurement.internal.zzfy',
  'com.google.android.gms.ads.MobileAds',
  'com.google.android.gms.ads.AdView',
  'com.google.android.gms.ads.identifier.AdvertisingIdClient',
  'com.appsflyer.AppsFlyerLib',
  'com.appsflyer.AppsFlyerConversionListener',
  'com.appsflyer.internal.AFa1xSDK',
  'com.unity3d.player.UnityPlayerActivity',
  'com.bun.miitmdid.core.MdidSdkHelper',
  'kotlin.collections.CollectionsKt',
  'androidx.core.app.NotificationCompat',
];
const dex1Strings = [
  'https://events.k1d-demo.cn/v1/track',
  'https://k1d-demo-logs.cn-hangzhou.log.aliyuncs.com/logstores/app',
  'http://203.0.113.7:8080/report',
  'https://pangle.io/',
  'https://bugly.qq.com/',
  'UMENG_APPKEY',
  'JPUSH_APPKEY',
  'device_id',
  'gaid',
  'http://schemas.android.com/apk/res/android',
];
const dex2Strings = [
  'https://app-measurement.com/a',
  'https://launches.appsflyer.com/api/',
  'https://googleads.g.doubleclick.net/mads/static/',
  'https://api.k1d-demo.example/v2/profile',
];
const dex1 = buildDex(dex1Classes, dex1Strings);
const dex2 = buildDex(dex2Classes, dex2Strings);
fs.writeFileSync(path.join(work, 'classes.dex'), dex1);
const dexdumpOut = run(tools.dexdump, ['-f', path.join(work, 'classes.dex')]);
if (!/string_ids_size\s*:\s*\d+/.test(dexdumpOut)) throw new Error('dexdump rejected generated DEX:\n' + dexdumpOut);

// ---------- 3. native libs (fake ELF payloads containing strings) ----------
function fakeElf(...strs) {
  return Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), Buffer.alloc(56), ...strs.map((s) => Buffer.from('\0' + s + '\0', 'latin1'))]);
}
const libs = {
  'lib/arm64-v8a/libBugly.so': fakeElf('https://android.bugly.qq.com/rqd/async'),
  'lib/arm64-v8a/libmsaoaidsec.so': fakeElf('oaid'),
  'lib/arm64-v8a/libunity.so': fakeElf('UnityPlayer'),
  'lib/arm64-v8a/libgame.so': fakeElf('wss://gw.k1d-demo.cn:8443/socket', 'https://cdn.k1d-demo.example/patch/'),
  'lib/armeabi-v7a/libunity.so': fakeElf('UnityPlayer'),
};

// ---------- 4. signing certificate (self-signed, synthetic) ----------
const keyPem = path.join(work, 'key.pem');
const certPem = path.join(work, 'cert.pem');
run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPem, '-out', certPem, '-days', '9125',
  '-subj', '/C=CN/ST=Guangdong/L=Shenzhen/O=k1d Demo Studio/CN=k1d demo signer']);
const certDer = path.join(work, 'cert.der');
run('openssl', ['x509', '-in', certPem, '-outform', 'DER', '-out', certDer]);
const p7 = path.join(work, 'CERT.RSA');
run('openssl', ['crl2pkcs7', '-nocrl', '-certfile', certPem, '-outform', 'DER', '-out', p7]);
const certBytes = fs.readFileSync(certDer);
const certSha256 = createHash('sha256').update(certBytes).digest('hex');

// ---------- 5. assemble zip with APK Signing Block (v2 layout, unsigned payload) ----------
const entries = [];
const add = (name, data, method = 8) => entries.push({ name, data: Buffer.from(data), method });
add('AndroidManifest.xml', fs.readFileSync(path.join(linked, 'AndroidManifest.xml')));
add('resources.arsc', fs.readFileSync(path.join(linked, 'resources.arsc')), 0);
add('classes.dex', dex1);
add('classes2.dex', dex2);
for (const [n, d] of Object.entries(libs)) add(n, d);
add('assets/remote_config.json', JSON.stringify({
  endpoint: 'https://cfg.k1d-demo.cn/remote/v3',
  backup: 'https://k1d-demo-backup.cos.ap-guangzhou.myqcloud.com/cfg.json',
  privacy: 'https://www.k1d-demo.example/privacy',
}, null, 2));
add('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\r\nCreated-By: k1d demo builder\r\n\r\n');
add('META-INF/CERT.RSA', fs.readFileSync(p7));

const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const lp = (buf) => Buffer.concat([u32(buf.length), buf]);
const signedData = Buffer.concat([lp(Buffer.alloc(0)), lp(lp(certBytes)), lp(Buffer.alloc(0))]);
const signer = Buffer.concat([lp(signedData), lp(Buffer.alloc(0)), lp(Buffer.alloc(0))]);
const v2Value = lp(lp(signer));
const pair = Buffer.concat([u64(4 + v2Value.length), u32(0x7109871a), v2Value]);
const blockSize = pair.length + 8 + 16;
const sigBlock = Buffer.concat([u64(blockSize), pair, u64(blockSize), Buffer.from('APK Sig Block 42', 'latin1')]);

const apk = writeZip(entries, { beforeCentralDirectory: sigBlock });
fs.mkdirSync(path.dirname(outApk), { recursive: true });
fs.writeFileSync(outApk, apk);

// ---------- 5b. Android App Bundle: same app, protobuf manifest (aapt2 --proto-format) ----------
const protoDir = path.join(work, 'proto');
fs.mkdirSync(protoDir);
run(tools.aapt2, ['link', '--proto-format', '-o', protoDir, '--output-to-dir', '-I', tools.androidJar, '--manifest', path.join(src, 'AndroidManifest.xml'), compiled]);
const aabEntries = [
  { name: 'BundleConfig.pb', data: Buffer.alloc(0) },
  { name: 'base/manifest/AndroidManifest.xml', data: fs.readFileSync(path.join(protoDir, 'AndroidManifest.xml')) },
  { name: 'base/resources.pb', data: fs.readFileSync(path.join(protoDir, 'resources.pb')) },
  { name: 'base/dex/classes.dex', data: dex1 },
  { name: 'base/dex/classes2.dex', data: dex2 },
  ...Object.entries(libs).map(([n, d]) => ({ name: 'base/' + n, data: d })),
  { name: 'base/assets/remote_config.json', data: entries.find((e) => e.name === 'assets/remote_config.json').data },
  { name: 'META-INF/MANIFEST.MF', data: Buffer.from('Manifest-Version: 1.0\r\n\r\n') },
  { name: 'META-INF/CERT.RSA', data: fs.readFileSync(p7) },
];
const outAab = outApk.replace(/\.apk$/, '.aab');
fs.writeFileSync(outAab, writeZip(aabEntries));
// oracle: aapt2 itself must be able to read the protobuf manifest we packaged
const protoApk = path.join(work, 'proto-check.apk');
fs.writeFileSync(protoApk, writeZip([
  { name: 'AndroidManifest.xml', data: fs.readFileSync(path.join(protoDir, 'AndroidManifest.xml')) },
  { name: 'resources.pb', data: fs.readFileSync(path.join(protoDir, 'resources.pb')) },
]));
const protoTree = run(tools.aapt2, ['dump', 'xmltree', '--file', 'AndroidManifest.xml', protoApk]);
if (!protoTree.includes('com.k1d.demo.idlequest')) throw new Error('aapt2 could not read proto manifest:\n' + protoTree);
const protoPerms = [...protoTree.matchAll(/E: uses-permission[\s\S]*?A: http:\/\/schemas\.android\.com\/apk\/res\/android:name\([^)]*\)="([^"]+)"/g)].map((m) => m[1]);

// ---------- 6. oracle: Google's aapt2 must be able to read our APK ----------
const badging = run(tools.aapt2, ['dump', 'badging', outApk]);
const pkgLine = badging.split('\n').find((l) => l.startsWith('package:'));
const perms = [...badging.matchAll(/uses-permission: name='([^']+)'/g)].map((m) => m[1]);

fs.mkdirSync(path.dirname(expectedOut), { recursive: true });
fs.writeFileSync(expectedOut, JSON.stringify({
  note: 'Ground truth for tests/analyze.test.mjs. Produced by tools/build-demo-apk.mjs from aapt2 + openssl, not by the analyzer.',
  aapt2PackageLine: pkgLine,
  package: /name='([^']+)'/.exec(pkgLine)[1],
  versionCode: Number(/versionCode='(\d+)'/.exec(pkgLine)[1]),
  versionName: /versionName='([^']+)'/.exec(pkgLine)[1],
  permissions: perms,
  certSha256,
  apkSha256: createHash('sha256').update(apk).digest('hex'),
  aabProtoPermissionsPerAapt2: protoPerms,
  classes: [...dex1Classes, ...dex2Classes].length,
  expectedSdks: ['pangle', 'umeng', 'jpush', 'tencent_bugly', 'google_play_billing', 'firebase_analytics', 'google_mobile_ads', 'appsflyer', 'unity_engine', 'msa_oaid'],
  notExpectedSdks: ['meta_sdk', 'tencent_gdt', 'applovin'],
}, null, 2) + '\n');

fs.rmSync(work, { recursive: true, force: true });
console.log(`Wrote ${path.relative(root, outApk)} (${apk.length} bytes)`);
console.log(pkgLine);
console.log(`permissions per aapt2: ${perms.length}; cert sha256 ${certSha256}`);
