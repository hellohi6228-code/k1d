// App file + recording of it, combined into one result (combine.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeSource } from '../site/js/analyze.js';
import { bytesSource } from '../site/js/zip.js';
import { buildRisks } from '../site/js/risks.js';
import { combineResults } from '../site/js/combine.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (p) => JSON.parse(fs.readFileSync(path.join(root, p), 'utf8'));
const kb = { sdks: readJson('site/kb/sdks.json'), infra: readJson('site/kb/infra.json'), permissions: readJson('site/kb/permissions.json') };
const scan = (p) => analyzeSource(bytesSource(new Uint8Array(fs.readFileSync(path.join(root, 'tests/fixtures', p)))), kb);

test('APK + capture: runtime evidence, runtime-only SDKs, match count, traffic kept', async () => {
  const apk = await scan('k1d-demo.apk');
  const r = combineResults(apk, await scan('formats/capture-raw.pcapng'), { recordingName: 'capture-raw.pcapng' });
  assert.equal(r.platform, 'android', 'the app stays the subject');
  assert.ok(r.traffic, 'traffic tab data kept');
  assert.equal(r.runtime.hostsContacted, 4);
  assert.equal(r.runtime.hostsMatchingApp, 2, 'events.k1d-demo.cn and track.k1d-demo.example share domains with the app file');
  const tiktok = r.sdks.find((s) => s.id === 'tiktok_sdk');
  assert.ok(tiktok.seenAtRuntime && tiktok.runtimeOnly, 'not in the APK, seen in the capture');
  assert.equal(r.sdks.find((s) => s.id === 'pangle').seenAtRuntime, false);
  assert.ok(r.endpoints.find((e) => e.host === 'events.k1d-demo.cn').seenAtRuntime);
  assert.ok(r.secrets.some((s) => s.type === 'aws_access_key'), 'credential from cleartext HTTP merged');
  const wt = buildRisks(r).find((a) => a.id === 'wiretap');
  assert.ok(wt.signals.some((s) => /^Confirmed by the recording: 0 of the \d+ tracking SDKs built into the app/.test(s.en)));
  assert.ok(wt.signals.some((s) => s.en.startsWith('Seen only in the recording, not found in the app file: TikTok SDK')));
});

test('IPA + iPhone App Privacy Report: the app\'s own entry confirms SDKs and sensor use', async () => {
  const ipa = await scan('k1d-demo.ipa');
  const r = combineResults(ipa, await scan('formats/App_Privacy_Report_v4_demo.ndjson'));
  assert.equal(r.runtime.report.bundleId, 'com.k1d.demo.idlequest');
  const meta = r.sdks.find((s) => s.id === 'meta_sdk');
  assert.ok(meta.seenAtRuntime && !meta.runtimeOnly, 'built-in Meta SDK confirmed by graph.facebook.com in the report');
  const by = Object.fromEntries(buildRisks(r).map((a) => [a.id, a]));
  assert.ok(by.wiretap.signals.some((s) => s.en.startsWith('Apple flagged 2 domain(s)')));
  assert.ok(by.foreign_data.signals.some((s) => s.en.startsWith('The iPhone App Privacy Report shows the app contacted 3 China-linked domain(s)')));
  assert.ok(by.intrusive.signals.some((s) => s.en === 'Confirmed by the iPhone App Privacy Report: the app used camera 1 time(s).'));
  assert.ok(by.location_health.signals.some((s) => s.en.includes('used location 1 time(s)')));
});

test('a report without this app adds nothing and says so', async () => {
  const apk = await scan('k1d-demo.apk');
  const rep = await scan('formats/App_Privacy_Report_v4_demo.ndjson');
  const r = combineResults({ ...apk, app: { ...apk.app, id: 'com.other.app' } }, rep);
  assert.equal(r.runtime.report, null);
  assert.ok(r.limits.some((l) => l.en.startsWith('The App Privacy Report has no activity for com.other.app')));
  assert.ok(!r.sdks.some((s) => s.seenAtRuntime));
});
