// Real signed binaries on the developer's machine. Ground truth = Windows' own
// Get-AuthenticodeSignature thumbprints and file version info (recorded 2026-11-13).
// Skipped automatically where the files don't exist (e.g., CI).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeSource } from '../site/js/analyze.js';
import { bytesSource } from '../site/js/zip.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (p) => JSON.parse(fs.readFileSync(path.join(root, p), 'utf8'));
const kb = { sdks: readJson('site/kb/sdks.json'), infra: readJson('site/kb/infra.json'), permissions: readJson('site/kb/permissions.json') };
const home = process.env.USERPROFILE ?? '';

const CASES = [
  { file: path.join(home, 'Downloads', 'Install-Block Blast!-GooglePlayGames.exe'), sha1: '607a3edaa64933e94422fc8f0c80388e0590986c', company: 'Google LLC', product: 'Google Play Games', version: '26.10.802.0' },
  { file: 'C:/Program Files/nodejs/node.exe', sha1: 'cecd9673e955ca766047dd43706d31e48a6bd3b5', company: 'Node.js', product: 'Node.js' },
  { file: 'C:/Program Files/GitHub CLI/gh.exe', sha1: 'd46d892961f59ab8adcff8a441913cdd91c55172', company: 'GitHub', product: 'GitHub CLI' },
];

for (const c of CASES) {
  test(`real binary: ${path.basename(c.file)}`, { skip: !fs.existsSync(c.file) && 'file not present' }, async () => {
    const r = await analyzeSource(bytesSource(new Uint8Array(fs.readFileSync(c.file))), kb);
    assert.equal(r.platform, 'windows');
    assert.equal(r.cert.sha1, c.sha1, 'signer thumbprint must match Windows');
    assert.equal(r.app.publisher, c.company);
    assert.equal(r.app.name, c.product);
    if (c.version) assert.equal(r.app.versionName, c.version);
    assert.ok(!r.endpoints.some((e) => /\.(com|net|org)\d/.test(e.host)), 'no DER junk glued to hosts');
    assert.equal(!!r.notice, c.product === 'Google Play Games', 'installer stubs say they are not the app');
  });
}

const asar = path.join(home, 'AppData/Local/Programs/antigravity/resources/app.asar');
test('real Electron app.asar', { skip: !fs.existsSync(asar) && 'file not present' }, async () => {
  const r = await analyzeSource(bytesSource(new Uint8Array(fs.readFileSync(asar))), kb);
  assert.equal(r.container, 'asar');
  assert.ok(r.app.name);
  assert.ok(r.endpoints.length > 0);
});
