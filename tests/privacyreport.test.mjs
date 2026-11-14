// iPhone App Privacy Report (NDJSON) against the fixture from tools/build-demo-privacyreport.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeSource } from '../site/js/analyze.js';
import { bytesSource } from '../site/js/zip.js';
import { isPrivacyReport, parsePrivacyReport } from '../site/js/privacyreport.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (p) => JSON.parse(fs.readFileSync(path.join(root, p), 'utf8'));
const kb = { sdks: readJson('site/kb/sdks.json'), infra: readJson('site/kb/infra.json'), permissions: readJson('site/kb/permissions.json') };
const file = path.join(root, 'tests/fixtures/formats/App_Privacy_Report_v4_demo.ndjson');

test('App Privacy Report: sniffing and parsing (Apple record layout)', () => {
  const text = fs.readFileSync(file, 'utf8');
  assert.ok(isPrivacyReport(text));
  assert.ok(!isPrivacyReport('{"name":"x","version":"1.0.0"}'), 'package.json is not a report');
  const rep = parsePrivacyReport(text);
  assert.equal(rep.bad, 1, 'malformed line counted, not fatal');
  const game = rep.apps.find((a) => a.bundleId === 'com.k1d.demo.idlequest');
  assert.deepEqual(game.access.map((c) => [c.category, c.count, c.seconds]), [['camera', 1, 120], ['location', 1, 60]], 'begin/end pairs give durations');
  const tt = game.domains.find((d) => d.domain === 'analytics.us.tiktok.com');
  assert.equal(tt.hits, 42);
  assert.equal(tt.tracker, true, 'domainType 1');
  const safari = rep.apps.find((a) => a.bundleId === 'com.apple.mobilesafari');
  assert.equal(safari.domains[0].userInitiated, true);
  assert.equal(safari.domains[0].appInitiated, false);
});

test('App Privacy Report through analyzeSource: per-app China-linked domains, SDKs, flagged trackers', async () => {
  const r = await analyzeSource(bytesSource(new Uint8Array(fs.readFileSync(file))), kb);
  assert.equal(r.platform, 'iphone-report');
  assert.equal(r.container, 'ndjson');
  const apps = Object.fromEntries(r.privacyReport.apps.map((a) => [a.bundleId, a]));
  const game = apps['com.k1d.demo.idlequest'];
  assert.equal(r.privacyReport.apps[0].bundleId, 'com.k1d.demo.idlequest', 'apps with China-linked domains first');
  assert.equal(game.cnDomains, 3, 'TikTok SDK domain, .cn domain, and an owner named in the KB');
  assert.equal(game.trackers, 2);
  const owner = game.domains.find((d) => d.domain === 'stats.k1d-demo-partner.com');
  assert.equal(owner.cnIndicators[0].type, 'owner');
  assert.equal(game.domains.find((d) => d.domain === 'graph.facebook.com').sdk.id, 'meta_sdk');
  assert.equal(apps['com.k1d.demo.notes'].cnDomains, 0);
  assert.equal(apps['com.apple.mobilesafari'].appDomains, 0, 'websites the user opened are not counted as app activity');
  assert.ok(!r.endpoints.some((e) => e.host === 'news.k1d-demo.example'), 'browsing history stays out of the endpoint list');
  for (const id of ['tiktok_sdk', 'meta_sdk']) assert.ok(r.sdks.find((s) => s.id === id)?.evidence.some((e) => e.type === 'traffic'), id);
});
