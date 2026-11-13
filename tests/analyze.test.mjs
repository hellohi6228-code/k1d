// Android analysis against the synthetic fixtures built by tools/build-demo-apk.mjs.
// Ground truth (tests/fixtures/demo-expected.json) comes from aapt2 + openssl, not from our code.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeSource } from '../site/js/analyze.js';
import { bytesSource, openZip } from '../site/js/zip.js';
import { certFromPkcs7, sha256Hex, describeCert } from '../site/js/cert.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (p) => JSON.parse(fs.readFileSync(path.join(root, p), 'utf8'));
const kb = {
  sdks: readJson('site/kb/sdks.json'),
  infra: readJson('site/kb/infra.json'),
  permissions: readJson('site/kb/permissions.json'),
};
const expected = readJson('tests/fixtures/demo-expected.json');
const apkBytes = new Uint8Array(fs.readFileSync(path.join(root, 'tests/fixtures/k1d-demo.apk')));
const aabBytes = new Uint8Array(fs.readFileSync(path.join(root, 'tests/fixtures/k1d-demo.aab')));

const result = await analyzeSource(bytesSource(apkBytes), kb);
const aab = await analyzeSource(bytesSource(aabBytes), kb);

test('manifest matches aapt2', () => {
  assert.equal(result.platform, 'android');
  assert.equal(result.app.id, expected.package);
  assert.equal(Number(result.app.versionCode), expected.versionCode);
  assert.equal(result.app.versionName, expected.versionName);
  assert.equal(Number(result.app.minSdk), 24);
  assert.equal(result.app.targetSdk, 34);
  assert.deepEqual([...result.permissions.map((p) => p.name)].sort(), [...expected.permissions].sort());
});

test('application flags and components', () => {
  assert.equal(result.android.application.usesCleartextTraffic, true);
  assert.equal(result.android.application.allowBackup, true);
  const exported = result.android.exportedComponents.map((c) => c.name).sort();
  assert.deepEqual(exported, [
    'cn.jpush.android.service.PushService',
    'com.k1d.demo.idlequest.MainActivity',
    'com.k1d.demo.idlequest.PromoReceiver', // implicit export via intent-filter
  ]);
  const meta = Object.fromEntries(result.android.metaData.map((m) => [m.name, m.value]));
  assert.equal(meta.JPUSH_CHANNEL, 'developer-default');
  assert.equal(meta.UMENG_APPKEY, 'k1ddemo00000000000000000');
  assert.deepEqual(result.android.queriedPackages, ['com.tencent.mm']);
});

test('signing certificate fingerprint matches openssl (v2 block)', () => {
  assert.equal(result.cert.scheme, 'v2');
  assert.equal(result.cert.sha256, expected.certSha256);
  assert.equal(result.cert.subject.C, 'CN');
  assert.equal(result.cert.subject.O, 'k1d Demo Studio');
  assert.deepEqual(result.signatureSchemes.sort(), ['v1', 'v2']);
});

test('v1 PKCS#7 certificate path matches openssl', async () => {
  const zip = await openZip(bytesSource(apkBytes));
  const der = certFromPkcs7(await zip.readEntry('META-INF/CERT.RSA'));
  assert.equal(await sha256Hex(der), expected.certSha256);
  assert.equal(describeCert(der).subject.CN, 'k1d demo signer');
});

test('all DEX classes are read across multidex', () => {
  assert.equal(result.android.dex.length, 2);
  assert.ok(result.android.classes >= expected.classes);
});

test('expected SDKs detected, others not', () => {
  const ids = result.sdks.map((s) => s.id);
  for (const id of expected.expectedSdks) assert.ok(ids.includes(id), `missing ${id}; got ${ids.join(', ')}`);
  for (const id of expected.notExpectedSdks) assert.ok(!ids.includes(id), `unexpected ${id}`);
});

test('AdvertisingIdClient alone is not counted as AdMob code', () => {
  const admob = result.sdks.find((s) => s.id === 'google_mobile_ads');
  const code = admob.evidence.find((e) => e.type === 'code');
  assert.ok(!code.samples.some((s) => s.includes('.identifier.')));
});

test('China-nexus indicators on SDKs and endpoints', () => {
  const pangle = result.sdks.find((s) => s.id === 'pangle');
  assert.ok(pangle.cnNexus);
  assert.equal(pangle.confidence, 'high');
  const hosts = Object.fromEntries(result.endpoints.map((e) => [e.host, e]));
  assert.equal(hosts['k1d-demo-assets.oss-us-west-1.aliyuncs.com'].operator, 'Alibaba Cloud'); // from resources.arsc
  assert.ok(hosts['events.k1d-demo.cn'].cnIndicators.some((i) => i.type === 'cctld'));
  assert.equal(hosts['k1d-demo-backup.cos.ap-guangzhou.myqcloud.com'].operator, 'Tencent Cloud'); // from assets
  assert.ok(hosts['gw.k1d-demo.cn']); // from native lib
  assert.ok(hosts['pangle.io'].cnIndicators.some((i) => i.type === 'sdk_domain'));
  assert.equal(hosts['launches.appsflyer.com'].cnIndicators.length, 0);
  assert.equal(hosts['203.0.113.7'].isIp, true);
  assert.equal(hosts['203.0.113.7'].cleartext, true);
  assert.equal(hosts['schemas.android.com'], undefined);
});

test('config keys, native libs, capabilities', () => {
  assert.ok(result.configKeys.includes('UMENG_APPKEY'));
  const unity = result.android.nativeLibs.find((l) => l.name === 'libunity.so');
  assert.deepEqual(unity.abis.sort(), ['arm64-v8a', 'armeabi-v7a']);
  assert.equal(result.capabilities.billing, true);
  assert.equal(result.capabilities.advertisingId, true);
});

test('AAB: protobuf manifest gives the same facts as aapt2 reports', () => {
  assert.equal(aab.container, 'aab');
  assert.equal(aab.app.id, expected.package);
  assert.equal(aab.app.versionName, expected.versionName);
  assert.equal(Number(aab.app.versionCode), expected.versionCode);
  assert.equal(aab.app.targetSdk, 34);
  assert.deepEqual(aab.permissions.map((p) => p.name).sort(), [...expected.aabProtoPermissionsPerAapt2].sort());
  assert.equal(aab.android.application.usesCleartextTraffic, true);
  assert.deepEqual(aab.android.exportedComponents.map((c) => c.name).sort(), result.android.exportedComponents.map((c) => c.name).sort());
  assert.deepEqual(aab.sdks.map((s) => s.id).sort(), result.sdks.map((s) => s.id).sort());
  assert.equal(aab.cert.sha256, expected.certSha256); // v1 JAR signature
  assert.ok(aab.endpoints.some((e) => e.host === 'k1d-demo-assets.oss-us-west-1.aliyuncs.com'), 'URL in resources.pb');
  assert.deepEqual(aab.errors, []);
});

test('XAPK / APKM split bundle: base APK inside an outer zip', async () => {
  const { writeZip } = await import('../tools/ziplib.mjs');
  const xapk = writeZip([
    { name: 'manifest.json', data: Buffer.from(JSON.stringify({ package_name: expected.package })) },
    { name: `${expected.package}.apk`, data: Buffer.from(apkBytes), method: 0 },
    { name: 'config.arm64_v8a.apk', data: Buffer.from(apkBytes), method: 0 },
  ]);
  const r = await analyzeSource(bytesSource(new Uint8Array(xapk)), kb);
  assert.equal(r.container, 'bundle');
  assert.equal(r.app.id, expected.package);
  assert.equal(r.cert.sha256, expected.certSha256);
  assert.deepEqual(r.sdks.map((s) => s.id).sort(), result.sdks.map((s) => s.id).sort());
});

test('unrecognized input gets a generic scan with a stated limit, not an error', async () => {
  const r = await analyzeSource(bytesSource(new Uint8Array(100)), kb);
  assert.equal(r.container, 'unknown');
  assert.equal(r.limits.length, 1);
  await assert.rejects(analyzeSource(bytesSource(new Uint8Array(2)), kb), /NOT_A_ZIP/);
});
