// Non-mobile formats against fixtures from tools/build-demo-formats.mjs (and IdleQuest.msi,
// created by Windows Installer itself via its COM API).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeSource } from '../site/js/analyze.js';
import { bytesSource } from '../site/js/zip.js';
import { buildRisks } from '../site/js/risks.js';
import { inferProfile } from '../site/js/profile.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (p) => JSON.parse(fs.readFileSync(path.join(root, p), 'utf8'));
const kb = { sdks: readJson('site/kb/sdks.json'), infra: readJson('site/kb/infra.json'), permissions: readJson('site/kb/permissions.json') };
const expected = readJson('tests/fixtures/formats-expected.json');
const scan = (name) => analyzeSource(bytesSource(new Uint8Array(fs.readFileSync(path.join(root, 'tests/fixtures/formats', name)))), kb);
const ids = (r) => r.sdks.map((s) => s.id);
const hosts = (r) => r.endpoints.map((e) => e.host);
const secretTypes = (r) => r.secrets.map((s) => s.type);

test('Windows EXE: version info, imports, privileges, Authenticode signer, embedded zip', async () => {
  const r = await scan('IdleQuestSetup.exe');
  assert.equal(r.platform, 'windows');
  assert.equal(r.app.name, 'Idle Quest');
  assert.equal(r.app.publisher, 'k1d Demo Studio');
  assert.equal(r.app.versionName, '1.4.2.0');
  assert.equal(r.cert.sha256, expected.signerSha256, 'signer picked by serial, not the CA');
  const caps = r.permissions.map((p) => p.name);
  for (const c of ['keyboard_hook', 'clipboard', 'hardware_ids', 'requireAdministrator']) assert.ok(caps.includes(c), c);
  for (const id of ['steamworks', 'easy_anticheat', 'sentry', 'mixpanel', 'electron_updater']) assert.ok(ids(r).includes(id), id);
  assert.ok(hosts(r).includes('telemetry.k1d-demo.cn'));
  assert.ok(hosts(r).includes('api.deepseek.com'), 'from app.asar inside the embedded zip');
  assert.deepEqual(secretTypes(r).sort(), ['alibaba_access_key', 'aws_access_key']);
  for (const s of r.secrets) assert.ok(s.value.includes('…'), 'secret values are masked');
});

test('Windows MSI made by Windows Installer: summary information', async () => {
  const r = await scan('IdleQuest.msi');
  assert.equal(r.container, 'msi');
  assert.equal(r.app.name, 'Idle Quest');
  assert.equal(r.app.publisher, 'k1d Demo Studio');
  const rows = Object.fromEntries(r.details[0].rows);
  assert.equal(rows['Package code'], '{11111111-2222-3333-4444-555555555555}');
  assert.ok(hosts(r).includes('www.k1d-demo.example'));
});

test('MSIX: identity, capabilities, signer', async () => {
  const r = await scan('IdleQuest.msix');
  assert.equal(r.container, 'msix');
  assert.equal(r.app.id, 'K1DDemo.IdleQuest');
  assert.equal(r.cert.sha256, expected.signerSha256);
  const p = Object.fromEntries(r.permissions.map((x) => [x.name, x.category]));
  assert.equal(p.location, 'location');
  assert.equal(p.webcam, 'camera');
  assert.equal(p.runFullTrust, 'other');
});

test('macOS .app zip: Info.plist, Mach-O, frameworks under Versions/A, code signature, Electron asar', async () => {
  const r = await scan('IdleQuest-macos.zip');
  assert.equal(r.platform, 'macos');
  assert.equal(r.app.id, 'com.k1d.demo.idlequest');
  assert.equal(r.ios.binary.arch, 'arm64');
  assert.deepEqual(r.ios.frameworks.map((f) => f.name), ['AppsFlyerLib', 'FBSDKCoreKit', 'PAGAdSDK', 'UnityFramework']);
  assert.equal(r.ios.frameworks.find((f) => f.name === 'FBSDKCoreKit').bundleId, 'com.facebook.sdk.FBSDKCoreKit');
  assert.equal(r.capabilities.electron, true);
  for (const id of ['meta_sdk', 'pangle', 'sentry', 'mixpanel']) assert.ok(ids(r).includes(id), id);
  assert.equal(r.ios.teamId, 'K1DTEAM123');
});

test('macOS .pkg: xar TOC, Distribution, PackageInfo, signing certificate, scripts', async () => {
  const r = await scan('IdleQuest.pkg');
  assert.equal(r.container, 'pkg');
  assert.equal(r.app.id, 'com.k1d.demo.idlequest.pkg');
  assert.equal(r.app.versionName, '1.4.2');
  assert.equal(r.cert.sha256, expected.signerSha256);
  assert.ok(hosts(r).includes('install.k1d-demo.cn'), 'URL in postinstall script');
});

test('Linux ELF, .deb and .rpm', async () => {
  const e = await scan('idlequest');
  assert.equal(e.container, 'elf');
  assert.ok(ids(e).includes('steamworks'), 'DT_NEEDED libsteam_api.so');
  assert.ok(secretTypes(e).includes('alibaba_access_key'));
  const d = await scan('idlequest_1.4.2_amd64.deb');
  assert.equal(d.app.id, 'idlequest');
  assert.equal(d.app.versionName, '1.4.2');
  for (const id of ['steamworks', 'sentry', 'electron_runtime']) assert.ok(ids(d).includes(id), id);
  const rpm = await scan('idlequest-1.4.2-1.x86_64.rpm');
  assert.equal(rpm.app.id, 'idlequest');
  assert.equal(rpm.app.versionName, '1.4.2-1');
  assert.equal(rpm.app.publisher, 'k1d Demo Studio');
});

test('HarmonyOS .hap: module.json, permissions, ohpm packages, native libs', async () => {
  const r = await scan('entry-default-signed.hap');
  assert.equal(r.platform, 'harmonyos');
  assert.equal(r.app.id, 'com.k1d.demo.idlequest');
  assert.equal(r.app.targetSdk, 12);
  const p = Object.fromEntries(r.permissions.map((x) => [x.name, x.category]));
  assert.equal(p['ohos.permission.APPROXIMATELY_LOCATION'], 'location');
  assert.equal(p['ohos.permission.APP_TRACKING_CONSENT'], 'advertising_id');
  assert.ok(ids(r).includes('umeng'));
  assert.ok(ids(r).includes('tencent_bugly'));
});

test('Chrome extension (CRX3): permissions, host access, remote update URL', async () => {
  const r = await scan('helper.crx');
  assert.equal(r.platform, 'browser-extension');
  assert.equal(r.app.name, 'Idle Quest Helper');
  const p = r.permissions.map((x) => x.name);
  for (const n of ['cookies', 'history', '<all_urls>']) assert.ok(p.includes(n), n);
  assert.ok(hosts(r).includes('ext.k1d-demo.cn'), 'non-store update_url');
});

test('WeChat mini-program (.wxapkg): APIs, scopes, PRC AI endpoint', async () => {
  const r = await scan('__APP__.wxapkg');
  assert.equal(r.platform, 'miniprogram');
  const p = r.permissions.map((x) => x.name);
  for (const n of ['wx.getLocation', 'wx.getPhoneNumber', 'scope.userLocation']) assert.ok(p.includes(n), n);
  const ai = r.sdks.find((s) => s.id === 'aliyun_dashscope');
  assert.equal(ai.confidence, 'medium');
  assert.ok(ai.cnNexus);
});

test('Electron app.asar: package.json, npm packages, credentials', async () => {
  const r = await scan('app.asar');
  assert.equal(r.platform, 'electron');
  assert.equal(r.app.versionName, '1.4.2');
  assert.ok(r.npmPackages.includes('@sentry/electron'));
  assert.ok(r.npmPackages.includes('mixpanel'));
  assert.ok(secretTypes(r).includes('aws_access_key'));
});

test('risk areas: automatic profile, signals and references (no user input)', async () => {
  const r = await scan('IdleQuestSetup.exe');
  const prof = inferProfile(r);
  assert.equal(prof.category, 'game', 'Steamworks / anti-cheat mean a game');
  assert.equal(prof.audience, 'mixed');
  const areas = buildRisks(r);
  const by = Object.fromEntries(areas.map((a) => [a.id, a]));
  assert.equal(by.security.status, 'signals');
  assert.ok(by.security.signals.some((s) => s.en.includes('Alibaba Cloud AccessKey ID')));
  assert.equal(by.intrusive.status, 'signals');
  assert.equal(by.ai.status, 'signals');
  assert.equal(by.children.status, 'signals', 'games are treated as possibly having child users');
  assert.match(by.children.signals[0].en, /^Likely mixed audience/);
  for (const a of areas) {
    assert.ok(['signals', 'none'].includes(a.status), `${a.id}: no status asks for input`);
    assert.ok(a.refs.length >= 1, `${a.id} has references`);
    for (const [, url] of a.refs) assert.match(url, /^https:\/\//);
    assert.ok(a.why.en && a.why.zh && a.unseen.en && a.unseen.zh, `${a.id} bilingual`);
  }
});

test('automatic profile: kids keywords, manifest category, consent defaults', () => {
  const base = { sdks: [], permissions: [], capabilities: {}, endpoints: [] };
  const kids = inferProfile({ ...base, app: { id: 'com.studio.babyshark.abc', name: null } });
  assert.equal(kids.audience, 'child');
  assert.equal(inferProfile({ ...base, app: { id: 'com.acme.schedule', name: null } }).category, 'other', '"edu" inside "schedule" is not a match');
  const vid = inferProfile({ ...base, app: { id: 'x.y' }, android: { application: { appCategory: 2 }, metaData: [] } });
  assert.equal(vid.category, 'video');
  const ga = inferProfile({ ...base, app: { id: 'x.y' }, android: { application: {}, metaData: [{ name: 'google_analytics_default_allow_ad_storage', value: 'true' }, { name: 'google_analytics_default_allow_analytics_storage', value: 'false' }] } });
  assert.deepEqual(ga.gaDefaults.granted, ['ad storage']);
  assert.deepEqual(ga.gaDefaults.denied, ['analytics storage']);
});

