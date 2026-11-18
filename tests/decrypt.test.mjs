// Decrypted-traffic analysis: identifiers in plain, URL-encoded and hashed forms, field names,
// before-consent timing, SDK attribution, pinning failures, and how it reaches risks and the report.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeFlows, parseFlows, idVariants } from '../cli/decrypt.mjs';
import { loadKb, scanFile } from '../cli/lib.mjs';
import { buildRisks } from '../site/js/risks.js';
import { renderReport } from '../cli/report.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const GAID = '38400000-8cf0-11bd-b23e-10b96e40000d';
const AID = '7c1c33223acb0e63';
const t0 = 1_800_000_000; // seconds
const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

const flows = [
  { t: t0 + 1.2, host: 'abc.conversions.appsflyersdk.com', method: 'POST', url: 'https://abc.conversions.appsflyersdk.com/api/v6.x/androidevent?app_id=com.k1d.demo', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ advertiserId: GAID, android_id: AID, model: 'sdk_gphone64_x86_64' }), bodySize: 300 },
  { t: t0 + 3.0, host: 'analytics.us.tiktok.com', method: 'POST', url: 'https://analytics.us.tiktok.com/api/v2/app_sdk/batch', headers: {}, body: `{"gaid_md5":"${md5(GAID)}"}`, bodySize: 60 },
  { t: t0 + 40, host: 'graph.facebook.com', method: 'GET', url: `https://graph.facebook.com/v18.0/activities?advertiser_id=${encodeURIComponent(GAID)}`, headers: {}, body: '', bodySize: 0 },
  { t: t0 + 41, host: 'cdn.k1d-demo.example', method: 'GET', url: 'https://cdn.k1d-demo.example/config.json', headers: {}, body: '', bodySize: 0 },
  { t: t0 + 42, tlsFailed: true, host: 'pinned.k1d-demo.example', error: 'client disconnected during handshake' },
];
const jsonl = `${flows.map((f) => JSON.stringify(f)).join('\n')}\nnot json\n`;

test('identifier variants include URL-encoded and hashed forms', () => {
  const v = idVariants({ gaid: GAID, model: 'sdk_gphone64_x86_64', short: 'abc' });
  const gaid = v.find((x) => x.name === 'gaid').forms;
  assert.ok(gaid.includes(md5(GAID)) && gaid.includes(sha256(GAID)) && gaid.includes(GAID.replace(/-/g, '')));
  assert.equal(v.find((x) => x.name === 'model').forms.some((f) => f.length === 32), false, 'model is not hashed');
  assert.equal(v.some((x) => x.name === 'short'), false, 'values under 6 characters are ignored');
});

test('analyzeFlows: who got which identifier, field names, hashing, timing, pinning', () => {
  const a = analyzeFlows(parseFlows(jsonl), { ids: { gaid: GAID, androidId: AID, model: 'sdk_gphone64_x86_64' }, sdkKb: loadKb().sdks, startMs: t0 * 1000, consentMs: (t0 + 30) * 1000 });
  assert.equal(a.requests, 4);
  const by = Object.fromEntries(a.hosts.map((h) => [h.host, h]));
  const af = by['abc.conversions.appsflyersdk.com'];
  assert.equal(af.sdk.id, 'appsflyer');
  assert.deepEqual(af.ids.gaid.fields, ['advertiserId']);
  assert.deepEqual(af.ids.androidId.fields, ['android_id']);
  assert.equal(af.ids.gaid.beforeConsent, true);
  assert.equal(af.first, 1.2);
  const tt = by['analytics.us.tiktok.com'];
  assert.equal(tt.ids.gaid.hashed, true);
  assert.deepEqual(tt.ids.gaid.fields, ['gaid_md5']);
  const fb = by['graph.facebook.com'];
  assert.deepEqual(fb.ids.gaid.fields, ['advertiser_id']);
  assert.equal(fb.ids.gaid.beforeConsent, false, 'sent after consent at 30s');
  assert.deepEqual(by['cdn.k1d-demo.example'].ids, {});
  assert.deepEqual(a.tlsFailed, [{ host: 'pinned.k1d-demo.example', error: 'client disconnected during handshake', system: false }]);
});

test('decrypted findings reach the risk areas and the evidence report', async () => {
  const r = await scanFile(path.join(root, 'tests/fixtures/k1d-demo.apk'));
  r.decrypted = analyzeFlows(parseFlows(jsonl), { ids: { gaid: GAID, androidId: AID }, sdkKb: loadKb().sdks, startMs: t0 * 1000, consentMs: (t0 + 30) * 1000 });
  const by = Object.fromEntries(buildRisks(r).map((x) => [x.id, x]));
  const wt = by.wiretap.signals.map((s) => s.en);
  assert.ok(wt.some((s) => s.startsWith('Decrypted traffic: 3 server(s) received a device identifier: AppsFlyer (advertising ID "advertiserId", Android ID "android_id")')), wt.join('\n'));
  assert.ok(wt.some((s) => s.startsWith('2 of them received it before consent was given')));
  assert.ok(wt.some((s) => s.includes('could not be inspected') && s.includes('pinned.k1d-demo.example')));
  assert.ok(by.children.signals.some((s) => s.en.startsWith('Decrypted traffic: the advertising ID (a persistent identifier) was sent to 3 server(s), some before consent')));
  const html = renderReport(r, { files: [] });
  assert.match(html, /Decrypted requests · 解密的请求/);
  assert.match(html, /gaid \(hashed\) <code>gaid_md5<\/code> <span class="pill warn">before consent/);
});
