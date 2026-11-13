// iOS (.ipa) analysis against the synthetic fixture built by tools/build-demo-ipa.mjs.
// The certificate fingerprint ground truth comes from openssl.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeSource } from '../site/js/analyze.js';
import { bytesSource } from '../site/js/zip.js';
import { parsePlist } from '../site/js/plist.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (p) => JSON.parse(fs.readFileSync(path.join(root, p), 'utf8'));
const kb = { sdks: readJson('site/kb/sdks.json'), infra: readJson('site/kb/infra.json'), permissions: readJson('site/kb/permissions.json') };
const expected = readJson('tests/fixtures/ios-expected.json');
const r = await analyzeSource(bytesSource(new Uint8Array(fs.readFileSync(path.join(root, 'tests/fixtures/k1d-demo.ipa')))), kb);

test('identifies the IPA and reads the binary Info.plist', () => {
  assert.equal(r.platform, 'ios');
  assert.equal(r.container, 'ipa');
  assert.equal(r.app.id, expected.bundleId);
  assert.equal(r.app.versionName, expected.version);
  assert.equal(r.app.versionCode, expected.build);
  assert.equal(r.app.minSdk, expected.minimumOS);
  assert.deepEqual(r.errors, []);
});

test('usage descriptions and capability frameworks become permissions', () => {
  const names = r.permissions.map((p) => p.name);
  for (const k of expected.usageKeys) assert.ok(names.includes(k), k);
  const loc = r.permissions.find((p) => p.name === 'NSLocationWhenInUseUsageDescription');
  assert.equal(loc.description, 'Find nearby players and events.');
  assert.ok(names.includes('AdSupport.framework'));
  assert.deepEqual(r.ios.linkedSystem, expected.linkedSystem);
});

test('code signature: team, identifier, entitlements and leaf certificate (openssl ground truth)', () => {
  assert.equal(r.ios.teamId, expected.teamId);
  assert.equal(r.ios.signingIdentifier, expected.bundleId);
  assert.equal(r.ios.entitlements['aps-environment'], 'production');
  assert.equal(r.cert.sha256, expected.leafCertSha256, 'must pick the leaf, not the CA');
  assert.equal(r.cert.subject.OU, expected.teamId);
  assert.equal(r.cert.subject.C, 'CN');
});

test('frameworks, bundles, extensions, provisioning and store metadata', () => {
  assert.deepEqual(r.ios.frameworks.map((f) => f.name), expected.frameworks);
  assert.equal(r.ios.frameworks.find((f) => f.name === 'PAGAdSDK').encrypted, true);
  assert.deepEqual(r.ios.bundles, ['PAGAdSDK']);
  assert.deepEqual(r.ios.dylibs, ['libswiftCore.dylib']);
  assert.equal(r.ios.extensions[0].type, 'com.apple.usernotifications.service');
  assert.equal(r.ios.provisioning.teamName, 'k1d Demo Studio');
  assert.equal(r.ios.provisioning.provisionedDevices, 2);
  assert.equal(r.ios.storeMetadata.artistName, 'k1d Demo Studio');
});

test('privacy manifests are aggregated', () => {
  const owners = r.ios.privacyManifests.map((p) => p.owner).sort();
  assert.deepEqual(owners, ['FBSDKCoreKit.framework', 'IdleQuest.app', 'PAGAdSDK.bundle']);
  const types = r.ios.declaredData.map((d) => d.type.replace('NSPrivacyCollectedDataType', '')).sort();
  assert.deepEqual(types, ['CoarseLocation', 'DeviceID', 'GameplayContent', 'PreciseLocation', 'ProductInteraction', 'PurchaseHistory']);
  assert.equal(r.capabilities.declaresTracking, true);
  assert.equal(r.capabilities.trackingPrompt, true);
});

test('SDK detection from frameworks, bundles, Info.plist keys, URL schemes and class names', () => {
  const ids = r.sdks.map((s) => s.id);
  for (const id of expected.expectedSdks) assert.ok(ids.includes(id), `missing ${id}; got ${ids.join(', ')}`);
  for (const id of expected.notExpectedSdks) assert.ok(!ids.includes(id), `unexpected ${id}`);
  const meta = r.sdks.find((s) => s.id === 'meta_sdk');
  assert.equal(meta.confidence, 'high');
  assert.deepEqual(new Set(meta.evidence.map((e) => e.type)), new Set(['framework', 'plist_key', 'url_scheme', 'query_scheme', 'domain']));
  assert.equal(r.sdks.find((s) => s.id === 'qq_connect').confidence, 'low', 'a queried scheme alone is weak evidence');
});

test('encrypted binaries are not read; readable ones are', () => {
  const hosts = r.endpoints.map((e) => e.host);
  assert.ok(!hosts.includes('must-not-appear.k1d-demo.example'));
  assert.ok(hosts.includes('events.k1d-demo.cn')); // main binary __cstring
  assert.ok(hosts.includes('push.k1d-demo.cn')); // app extension
  assert.ok(hosts.includes('cfg.k1d-demo.cn')); // Info.plist value
  assert.ok(hosts.includes('api16-access-sg.pangle.io')); // privacy-manifest tracking domain
  assert.ok(hosts.includes('link.k1d-demo.example')); // associated domains
  assert.ok(hosts.includes('k1d-demo.firebaseio.com')); // GoogleService-Info.plist
  const log = r.endpoints.find((e) => e.host === 'log.k1d-demo.cn');
  assert.equal(log.cleartext, true); // ATS insecure exception
  assert.equal(r.capabilities.cleartext, true);
});

test('binary plist parser handles a hand-assembled bplist00', () => {
  // { "a": 1, "b": [true, "hi"] } assembled byte by byte per Apple's CFBinaryPList layout
  const objs = [
    [0xd2, 0x01, 0x02, 0x03, 0x04], // dict(2) keys 1,2 vals 3,4
    [0x51, 0x61], // "a"
    [0x51, 0x62], // "b"
    [0x10, 0x01], // int 1
    [0xa2, 0x05, 0x06], // array(2) refs 5,6
    [0x09], // true
    [0x52, 0x68, 0x69], // "hi"
  ];
  const head = [...'bplist00'].map((c) => c.charCodeAt(0));
  const offsets = [];
  const body = [...head];
  for (const o of objs) { offsets.push(body.length); body.push(...o); }
  const tableOff = body.length;
  body.push(...offsets);
  const trailer = [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, objs.length, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, tableOff];
  body.push(...trailer);
  assert.deepEqual(parsePlist(new Uint8Array(body)), { a: 1, b: [true, 'hi'] });
});
