// App wording checks: age questions, subscription terms, odds, consent text, and coverage notes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeSource, uiTextTo } from '../site/js/analyze.js';
import { bytesSource } from '../site/js/zip.js';
import { buildRisks } from '../site/js/risks.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (p) => JSON.parse(fs.readFileSync(path.join(root, p), 'utf8'));
const kb = { sdks: readJson('site/kb/sdks.json'), infra: readJson('site/kb/infra.json'), permissions: readJson('site/kb/permissions.json') };

test('UI wording patterns: hits keep a snippet and source; near-misses do not match', () => {
  const facts = {};
  const scan = uiTextTo(facts);
  scan('<string name="age_title">How old are you?</string>', 'res/values/strings.xml');
  scan('Weekly plan $4.99, auto-renews until cancelled. Cancel anytime.', 'assets/paywall.json');
  scan('Legendary drop rate: 0.6%', 'assets/gacha.json');
  scan('我已阅读并同意《用户协议》和《隐私政策》', 'assets/zh.json');
  scan('storage usage and image page layout', 'assets/noise.json');
  assert.equal(facts.uiText.age[0].source, 'res/values/strings.xml');
  assert.match(facts.uiText.age[0].text, /How old are you/);
  assert.equal(facts.uiText.subscription.length, 1);
  assert.equal(facts.uiText.odds.length, 1);
  assert.equal(facts.uiText.consent.length, 1);
  scan('Your Age is used for nothing', 'x');
  assert.equal(facts.uiText.age.length, 2);
});

test('risk areas report found and not-found wording with coverage, instead of asking the user', async () => {
  const r = await analyzeSource(bytesSource(new Uint8Array(fs.readFileSync(path.join(root, 'tests/fixtures/k1d-demo.apk')))), kb);
  assert.ok(r.coverage.textFiles >= 0 && Array.isArray(r.coverage.encrypted));
  // Same result with wording and an encrypted script, to check the sentences built from it.
  const withText = {
    ...r,
    capabilities: { ...r.capabilities, billing: true },
    uiText: { age: [], subscription: [{ text: 'auto-renews weekly', source: 'base.apk!assets/paywall.json' }], odds: [], consent: [] },
    coverage: { textFiles: 120, textSkipped: 0, encrypted: ['base.apk!assets/main.jsc'] },
  };
  const by = Object.fromEntries(buildRisks(withText).map((a) => [a.id, a]));
  assert.ok(by.children.signals.some((s) => s.en === 'No age-question wording found in the 120 text files k1d read (1 encrypted script file(s) could not be read).'));
  assert.equal(by.subscriptions.status, 'signals');
  assert.ok(by.subscriptions.signals.some((s) => s.en.includes('“auto-renews weekly” (assets/paywall.json)')));
  const none = Object.fromEntries(buildRisks({ ...withText, uiText: { ...withText.uiText, subscription: [] } }).map((a) => [a.id, a]));
  assert.equal(none.subscriptions.status, 'none', 'billing alone is not a subscription finding');
  for (const a of Object.values(by)) assert.ok(a.unseen.en, `${a.id} states what was not scanned`);
});
