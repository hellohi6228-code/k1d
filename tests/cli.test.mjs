// CLI: snapshots, release diff, policy, license keys, and the unlicensed check path.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { scanFile, snapshot, diffSnapshots, applyPolicy, changesMarkdown } from '../cli/lib.mjs';
import { signLicense, verifyLicense } from '../cli/license.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fx = (p) => path.join(root, 'tests/fixtures', p);

test('snapshot of the demo APK is stable and small', async () => {
  const s = snapshot(await scanFile(fx('k1d-demo.apk')), { file: fx('k1d-demo.apk') });
  assert.equal(s.k1d, 1);
  assert.equal(s.app.id, 'com.k1d.demo.idlequest');
  assert.ok(s.sdks.some((x) => x.id === 'pangle' && x.cn));
  assert.ok(s.hosts.some((h) => h.host === 'events.k1d-demo.cn' && h.cn.length));
  assert.ok(JSON.stringify(s).length < 64 * 1024, 'baseline fits comfortably in a repo');
  const again = snapshot(await scanFile(fx('k1d-demo.apk')), { file: fx('k1d-demo.apk') });
  assert.deepEqual(diffSnapshots(s, again), [], 'same build, no changes');
});

test('release diff and policy: new China-linked SDK and host block; removals do not', async () => {
  const a = snapshot(await scanFile(fx('k1d-demo.apk')));
  const b = structuredClone(a);
  b.app.version = '1.5.0';
  b.sdks.push({ id: 'mintegral', name: 'Mintegral', category: 'ads', cn: true, confidence: 'high', seenAtRuntime: false });
  b.hosts.push({ host: 'new-bucket.oss-us-west-1.aliyuncs.com', cn: ['Alibaba Cloud'], cleartext: false });
  b.hosts = b.hosts.filter((h) => h.host !== 'www.k1d-demo.example');
  b.consentDefaults = { ...b.consentDefaults, granted: [...b.consentDefaults.granted, 'ad storage'] };
  const changes = diffSnapshots(a, b);
  assert.equal(changes[0].severity, 'high');
  const kinds = changes.map((c) => c.kind);
  for (const k of ['new-cn-sdk', 'new-cn-host', 'removed-host', 'consent-default']) assert.ok(kinds.includes(k), k);
  const policy = applyPolicy(changes);
  assert.equal(policy.pass, false);
  assert.ok(!policy.blocking.some((c) => c.kind === 'removed-host'));
  assert.match(changesMarkdown(a, b, changes, policy), /\| high \(blocking\) \| SDK added: Mintegral \(China-nexus indicators\)/);
  assert.equal(applyPolicy(changes, ['new-secret']).pass, true, 'custom --fail-on');
});

test('license keys: valid, wrong app, expired, tampered', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ type: 'spki', format: 'pem' });
  const priv = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const key = signLicense({ v: 1, org: 'Demo', plan: 'pro', apps: ['com.k1d.demo.idlequest'], exp: '2030-01-01' }, priv);
  assert.equal(verifyLicense(key, { appId: 'com.k1d.demo.idlequest', publicKeyPem: pub }).ok, true);
  assert.match(verifyLicense(key, { appId: 'com.other', publicKeyPem: pub }).reason, /does not cover com\.other/);
  assert.match(verifyLicense(key, { publicKeyPem: pub, today: new Date('2030-02-01') }).reason, /expired/);
  const [body, sig] = key.split('.');
  const forged = `${Buffer.from(Buffer.from(body, 'base64url').toString().replace('com.k1d.demo.idlequest', '*')).toString('base64url')}.${sig}`;
  assert.match(verifyLicense(forged, { publicKeyPem: pub }).reason, /signature is not valid/);
  assert.match(verifyLicense(key).reason, /signature is not valid/, 'a key signed by someone else fails against the k1d public key');
});

test('k1d check without a license exits 3 and points to the plans; scan and diff stay free', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'k1d-'));
  const env = { ...process.env, K1D_LICENSE: '' };
  const check = spawnSync(process.execPath, [path.join(root, 'cli/k1d.mjs'), 'check', fx('k1d-demo.apk'), '--baseline', path.join(tmp, 'b.json')], { env, encoding: 'utf8' });
  assert.equal(check.status, 3);
  assert.match(check.stderr, /publishers\.html/);
  assert.ok(!fs.existsSync(path.join(tmp, 'b.json')), 'nothing written without a license');
  const scan = spawnSync(process.execPath, [path.join(root, 'cli/k1d.mjs'), 'scan', fx('k1d-demo.apk'), '--snapshot', path.join(tmp, 's.json')], { env, encoding: 'utf8' });
  assert.equal(scan.status, 0, scan.stderr);
  const diff = spawnSync(process.execPath, [path.join(root, 'cli/k1d.mjs'), 'diff', path.join(tmp, 's.json'), fx('k1d-demo.apk')], { env, encoding: 'utf8' });
  assert.equal(diff.status, 0, diff.stderr);
  assert.match(diff.stdout, /No changes/);
});
