#!/usr/bin/env node
// k1d command line. Same analyzer as the website, run locally; nothing is uploaded.
//
//   k1d scan  <app> [--recording <pcap|ndjson>] [--json <out.json>] [--snapshot <out.json>]
//   k1d diff  <old.apk|old.json> <new.apk|new.json> [--markdown]
//   k1d check <app> --baseline <baseline.json> [--fail-on a,b] [--update-baseline]   (Pro license)
//   k1d license                                                                      (show the K1D_LICENSE in use)
//
// scan and diff are free. check is the release gate for build pipelines and needs a Pro, Monitoring
// or Enterprise license key in K1D_LICENSE (or --license).
import fs from 'node:fs';
import { scanFile, snapshot, diffSnapshots, applyPolicy, changesMarkdown, loadSnapshotOrScan, DEFAULT_FAIL_ON } from './lib.mjs';
import { verifyLicense } from './license.mjs';

const argv = process.argv.slice(2);
const cmd = argv[0];
const flags = {};
const pos = [];
for (let i = 1; i < argv.length; i++) {
  const a = argv[i];
  if (a.startsWith('--')) {
    const k = a.slice(2);
    const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
    flags[k] = v;
  } else pos.push(a);
}
const out = (s) => process.stdout.write(`${s}\n`);
const fail = (msg, code = 2) => { process.stderr.write(`k1d: ${msg}\n`); process.exit(code); };
const PUBLISHERS = 'https://hellohi6228-code.github.io/k1d/publishers.html';

async function main() {
  if (cmd === 'scan') {
    if (!pos[0]) fail('usage: k1d scan <app> [--recording <file>] [--json out.json] [--snapshot out.json]');
    const r = await scanFile(pos[0], { recording: flags.recording || null });
    const s = snapshot(r, { file: pos[0] });
    if (flags.json) fs.writeFileSync(flags.json, JSON.stringify(r, null, 1));
    if (flags.snapshot) fs.writeFileSync(flags.snapshot, `${JSON.stringify(s, null, 1)}\n`);
    out(`${s.app.id ?? s.file} ${s.app.version ?? ''} (${s.app.platform})`);
    out(`  SDKs: ${s.sdks.length} (${s.sdks.filter((x) => x.cn).length} with China-nexus indicators)`);
    out(`  Endpoints: ${s.hosts.length} (${s.hosts.filter((x) => x.cn.length).length} China-linked)`);
    out(`  Permissions: ${s.permissions.length} · Credentials: ${s.secrets.length}`);
    out(`  App type: ${s.profile.category} · Likely audience: ${s.profile.audience}`);
    out(`  Risk areas with findings: ${Object.entries(s.risks).filter(([, v]) => v === 'signals').map(([k]) => k).join(', ') || 'none'}`);
    if (r.runtime) out(`  Recording: ${r.runtime.hostsMatchingApp} of ${r.runtime.hostsContacted} servers belong to this app; ${s.sdks.filter((x) => x.seenAtRuntime).length} SDKs seen connecting`);
    return;
  }
  if (cmd === 'diff') {
    if (pos.length < 2) fail('usage: k1d diff <old> <new> [--markdown]');
    const [a, b] = await Promise.all([loadSnapshotOrScan(pos[0]), loadSnapshotOrScan(pos[1])]);
    const changes = diffSnapshots(a, b);
    if (flags.markdown) out(changesMarkdown(a, b, changes, null));
    else if (!changes.length) out('No changes in SDKs, endpoints, permissions, credentials or consent defaults.');
    else for (const c of changes) out(`[${c.severity}] ${c.en}`);
    return;
  }
  if (cmd === 'check') {
    if (!pos[0] || !flags.baseline) fail('usage: k1d check <app> --baseline <baseline.json> [--fail-on a,b] [--update-baseline]');
    const b = await loadSnapshotOrScan(pos[0]);
    const lic = verifyLicense(flags.license || process.env.K1D_LICENSE, { appId: b.app.id });
    if (!lic.ok) fail(`${lic.reason}\n  k1d check is part of k1d Pro. Plans: ${PUBLISHERS}\n  (k1d scan and k1d diff stay free.)`, 3);
    const failOn = typeof flags['fail-on'] === 'string' ? flags['fail-on'].split(',').map((x) => x.trim()) : DEFAULT_FAIL_ON;
    let a = null;
    if (fs.existsSync(flags.baseline)) a = JSON.parse(fs.readFileSync(flags.baseline, 'utf8'));
    if (!a) {
      fs.writeFileSync(flags.baseline, `${JSON.stringify(b, null, 1)}\n`);
      out(`No baseline yet: saved ${flags.baseline} from this build. Commit it; later builds are compared with it.`);
      return;
    }
    const changes = diffSnapshots(a, b);
    const policy = applyPolicy(changes, failOn);
    const md = changesMarkdown(a, b, changes, policy);
    out(md);
    if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${md}\n`);
    if (policy.pass && flags['update-baseline']) fs.writeFileSync(flags.baseline, `${JSON.stringify(b, null, 1)}\n`);
    process.exit(policy.pass ? 0 : 1);
  }
  if (cmd === 'license') {
    const lic = verifyLicense(flags.license || process.env.K1D_LICENSE);
    if (!lic.ok) fail(lic.reason, 3);
    out(JSON.stringify(lic.license, null, 1));
    return;
  }
  out('k1d: scan | diff | check | license. See cli/README.md.');
  process.exit(cmd ? 2 : 0);
}

main().catch((err) => fail(err.message || String(err)));
