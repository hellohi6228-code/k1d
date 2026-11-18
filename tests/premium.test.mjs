// Premium features: evidence report, store watch, portfolio dashboard, runtime UI helpers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanFile, snapshot } from '../cli/lib.mjs';
import { renderReport } from '../cli/report.mjs';
import { parsePlayListing, storeVersions, compareWatch, watchMarkdown, portfolioHtml } from '../cli/monitor.mjs';
import { parseUiNodes, findButton, BUTTONS } from '../tools/runtime/run.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fx = (p) => path.join(root, 'tests/fixtures', p);

test('evidence report: inputs with hashes, all risk areas bilingual, runtime table, white-label, timeline', async () => {
  const r = await scanFile(fx('k1d-demo.apk'), { recording: fx('formats/capture-raw.pcapng') });
  const html = renderReport(r, {
    files: [{ name: 'k1d-demo.apk', size: 1, sha256: 'a'.repeat(64) }], brand: 'Example LLP', brandNote: 'Matter 7',
    ctx: { consentAt: 5 }, timeline: [{ t: '2026-11-18T10:00:00.000Z', event: 'consent-accept', detail: 'tapped "Agree"' }],
  });
  assert.match(html, /Example LLP/);
  assert.match(html, /analysis by k1d/);
  assert.match(html, /<code>a{64}<\/code>/);
  assert.equal((html.match(/class="area /g) ?? []).length, 13);
  assert.match(html, /Network activity during the recording/);
  assert.match(html, /analytics\.us\.tiktok\.com<\/code> <span class="pill warn">before consent/);
  assert.match(html, /Consent tapped at 5s/);
  assert.match(html, /tapped &quot;Agree&quot;/);
  assert.match(html, /不构成法律意见/);
  for (const bad of [/\bviolat/i, /\billegal\b/i, /\bnon-?compliant\b/i, /违法|违规/]) assert.doesNotMatch(html, bad);
});

test('store watch: Play listing parsing, new and unchecked releases', async () => {
  assert.deepEqual(parsePlayListing('x[[["11.0.1"]],...Updated on</div><div class="xg1aie">Nov 20, 2026</div>'), { version: '11.0.1', updated: 'Nov 20, 2026' });
  const fakeFetch = async (url) => ({
    text: async () => 'a[[["11.0.1"]]b Updated on</div><div class="q">Nov 20, 2026<',
    json: async () => ({ results: [{ version: '7.6.2', currentVersionReleaseDate: '2026-11-19T07:00:00Z', trackName: 'Demo', bundleId: 'com.k1d.demo.idlequest' }] }),
    url,
  });
  const cur = await storeVersions({ app: 'com.k1d.demo.idlequest', iosId: 1 }, { fetchImpl: fakeFetch });
  assert.equal(cur.android.version, '11.0.1');
  assert.equal(cur.ios.version, '7.6.2');
  const snap = snapshot(await scanFile(fx('k1d-demo.apk')));
  snap.app.version = '11.0.1';
  const { rows, state } = compareWatch([cur], { 'com.k1d.demo.idlequest|android': { version: '11.0.0' }, 'com.k1d.demo.idlequest|ios': { version: '7.6.1' } }, [snap]);
  const android = rows.find((r) => r.platform === 'android');
  const ios = rows.find((r) => r.platform === 'ios');
  assert.deepEqual([android.isNew, android.checked], [true, true]);
  assert.deepEqual([ios.isNew, ios.checked], [true, false], 'new iOS release that never went through k1d check');
  assert.equal(state['com.k1d.demo.idlequest|ios'].version, '7.6.2');
  assert.match(watchMarkdown(rows), /\*\*1 live release\(s\) did not go through k1d check\.\*\*/);
});

test('portfolio dashboard: changes since the previous snapshot per app', async () => {
  const a = { ...snapshot(await scanFile(fx('k1d-demo.apk'))), _mtime: '2026-11-01' };
  const b = structuredClone(a);
  b._mtime = '2026-11-15';
  b.app.version = '1.5.0';
  b.sdks.push({ id: 'mintegral', name: 'Mintegral', category: 'ads', cn: true, confidence: 'high' });
  const html = portfolioHtml([a, b], { brand: 'Demo Group' });
  assert.match(html, /Demo Group/);
  assert.match(html, /SDK added: Mintegral \(China-nexus indicators\)/);
  assert.match(html, /<b>1<\/b>with changes since the previous check/);
});

test('runtime helpers: uiautomator XML → buttons for consent and age', () => {
  const xml = `<hierarchy><node text="Welcome" class="android.widget.TextView" clickable="false" bounds="[0,0][100,50]"/>
    <node text="How old are you?" class="android.widget.TextView" clickable="false" bounds="[0,60][400,120]"/>
    <node text="" class="android.widget.EditText" clickable="true" bounds="[0,130][400,200]"/>
    <node text="Reject all" class="android.widget.Button" clickable="true" bounds="[0,900][200,980]"/>
    <node text="Agree and continue" class="android.widget.Button" clickable="true" bounds="[220,900][620,980]"/></hierarchy>`;
  const nodes = parseUiNodes(xml);
  assert.equal(nodes.length, 5);
  assert.deepEqual([findButton(nodes, BUTTONS.decline).x, findButton(nodes, BUTTONS.decline).y], [100, 940]);
  assert.equal(findButton(nodes, BUTTONS.accept).text, 'Agree and continue');
  assert.ok(nodes.some((n) => BUTTONS.age.test(n.text)));
  assert.equal(findButton(parseUiNodes('<node text="同意" class="android.widget.TextView" clickable="true" bounds="[1,1][3,3]"/>'), BUTTONS.accept).text, '同意');
  assert.equal(findButton(nodes, /^accept$/i), undefined, 'no partial matches on longer labels');
});
