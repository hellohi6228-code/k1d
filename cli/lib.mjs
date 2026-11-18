// Shared CLI logic: scan files in Node, reduce a result to a stable snapshot, compare snapshots,
// and apply a release policy. Uses the same analyzer as the website (site/js).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeSource } from '../site/js/analyze.js';
import { buildRisks } from '../site/js/risks.js';
import { inferProfile } from '../site/js/profile.js';
import { combineResults, RUNTIME_PLATFORMS } from '../site/js/combine.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (p) => JSON.parse(fs.readFileSync(path.join(root, p), 'utf8'));
let kbCache = null;
export const loadKb = () => (kbCache ??= { sdks: readJson('site/kb/sdks.json'), infra: readJson('site/kb/infra.json'), permissions: readJson('site/kb/permissions.json') });

// Random-access file source (no need to load a 2 GB bundle into memory).
export function nodeFileSource(file) {
  const fd = fs.openSync(file, 'r');
  const size = fs.fstatSync(fd).size;
  return {
    size,
    async read(offset, length) {
      const n = Math.max(0, Math.min(length, size - offset));
      const buf = Buffer.allocUnsafe(n);
      let done = 0;
      while (done < n) {
        const r = fs.readSync(fd, buf, done, n - done, offset + done);
        if (!r) break;
        done += r;
      }
      return new Uint8Array(buf.buffer, buf.byteOffset, done);
    },
    close() { fs.closeSync(fd); },
  };
}

export async function scanFile(file, { recording = null, onProgress } = {}) {
  const kb = loadKb();
  const run = async (f) => {
    const src = nodeFileSource(f);
    try { return await analyzeSource(src, kb, { onProgress }); } finally { src.close(); }
  };
  let r = await run(file);
  if (recording) {
    const rec = await run(recording);
    if (RUNTIME_PLATFORMS.has(r.platform) || !RUNTIME_PLATFORMS.has(rec.platform)) throw new Error('--recording needs an app file first and a .pcap/.pcapng or App Privacy Report second');
    r = combineResults(r, rec, { recordingName: path.basename(recording) });
  }
  return r;
}

// Snapshot: the stable, comparable subset of a result. Small enough to commit as a baseline.
export function snapshot(r, { file = null } = {}) {
  const prof = inferProfile(r);
  const risks = buildRisks(r);
  return {
    k1d: 1,
    analyzer: r.analyzer.version,
    kb: r.analyzer.kbVersion,
    file: file ? path.basename(file) : null,
    app: { id: r.app?.id ?? null, name: r.app?.name ?? null, version: r.app?.versionName ?? null, build: r.app?.versionCode ?? null, platform: r.platform, targetSdk: r.app?.targetSdk ?? null },
    sdks: r.sdks.map((s) => ({ id: s.id, name: s.name.en, category: s.category, cn: Boolean(s.cnNexus), confidence: s.confidence, seenAtRuntime: Boolean(s.seenAtRuntime) })).sort((a, b) => a.id.localeCompare(b.id)),
    hosts: r.endpoints.map((e) => ({ host: e.host, cn: e.cnIndicators.map((i) => i.operator ?? i.type), cleartext: e.cleartext })).sort((a, b) => a.host.localeCompare(b.host)),
    permissions: r.permissions.map((p) => ({ name: p.name, level: p.level ?? null })).sort((a, b) => a.name.localeCompare(b.name)),
    secrets: (r.secrets ?? []).map((s) => ({ type: s.type, value: s.value, level: s.level })),
    consentDefaults: prof.gaDefaults,
    profile: { category: prof.category, audience: prof.audience },
    risks: Object.fromEntries(risks.map((a) => [a.id, a.status])),
    coverage: r.coverage ? { textFiles: r.coverage.textFiles, encrypted: r.coverage.encrypted.length } : null,
  };
}

const TRACKING = new Set(['ads', 'analytics', 'attribution', 'session-replay']);

// Changes from one snapshot to the next. Each change: { kind, severity: high|medium|info, en }
export function diffSnapshots(a, b) {
  const out = [];
  const add = (kind, severity, en) => out.push({ kind, severity, en });
  const by = (list, key) => new Map(list.map((x) => [x[key], x]));
  const sa = by(a.sdks, 'id');
  const sb = by(b.sdks, 'id');
  for (const [id, s] of sb) if (!sa.has(id)) add(s.cn ? 'new-cn-sdk' : TRACKING.has(s.category) ? 'new-tracking-sdk' : 'new-sdk', s.cn || TRACKING.has(s.category) ? 'high' : 'medium', `SDK added: ${s.name}${s.cn ? ' (China-nexus indicators)' : ''} [${s.category}]`);
  for (const [id, s] of sa) if (!sb.has(id)) add('removed-sdk', 'info', `SDK removed: ${s.name}`);
  const ha = by(a.hosts, 'host');
  const hb = by(b.hosts, 'host');
  for (const [h, x] of hb) if (!ha.has(h)) add(x.cn.length ? 'new-cn-host' : x.cleartext ? 'new-cleartext-host' : 'new-host', x.cn.length ? 'high' : x.cleartext ? 'medium' : 'info', `Endpoint added: ${h}${x.cn.length ? ` (China-nexus: ${x.cn.join(', ')})` : ''}${x.cleartext ? ' (cleartext)' : ''}`);
  for (const [h] of ha) if (!hb.has(h)) add('removed-host', 'info', `Endpoint removed: ${h}`);
  const pa = by(a.permissions, 'name');
  const pb = by(b.permissions, 'name');
  for (const [n, p] of pb) if (!pa.has(n)) add(p.level === 'high' ? 'new-high-permission' : 'new-permission', p.level === 'high' ? 'high' : 'medium', `Permission added: ${n}${p.level ? ` (${p.level})` : ''}`);
  for (const [n] of pa) if (!pb.has(n)) add('removed-permission', 'info', `Permission removed: ${n}`);
  const ka = new Set(a.secrets.map((s) => `${s.type}:${s.value}`));
  for (const s of b.secrets) if (!ka.has(`${s.type}:${s.value}`)) add('new-secret', 'high', `Hard-coded credential added: ${s.type} ${s.value}`);
  for (const k of ['granted', 'collection']) {
    const added = (b.consentDefaults?.[k] ?? []).filter((x) => !(a.consentDefaults?.[k] ?? []).includes(x));
    if (added.length) add('consent-default', 'high', `${k === 'granted' ? 'Consent default set to granted' : 'Collection turned on'} in the manifest: ${added.join(', ')}`);
  }
  for (const [id, st] of Object.entries(b.risks ?? {})) if (a.risks?.[id] !== st && st === 'signals') add('risk-area', 'medium', `Risk area now has findings: ${id}`);
  if (a.app.targetSdk !== b.app.targetSdk) add('target-sdk', 'info', `Target SDK: ${a.app.targetSdk} → ${b.app.targetSdk}`);
  const order = { high: 0, medium: 1, info: 2 };
  return out.sort((x, y) => order[x.severity] - order[y.severity]);
}

export const DEFAULT_FAIL_ON = ['new-cn-sdk', 'new-cn-host', 'new-secret', 'new-tracking-sdk', 'new-high-permission', 'consent-default'];

export function applyPolicy(changes, failOn = DEFAULT_FAIL_ON) {
  const blocking = changes.filter((c) => failOn.includes(c.kind));
  return { pass: blocking.length === 0, blocking };
}

export function changesMarkdown(a, b, changes, policy) {
  const head = `### k1d release check: ${b.app.id ?? b.file} ${a.app.version ?? '?'} → ${b.app.version ?? '?'}\n\n`;
  const status = policy ? (policy.pass ? '**Result: no blocking changes.**\n\n' : `**Result: ${policy.blocking.length} blocking change(s).**\n\n`) : '';
  if (!changes.length) return `${head}${status}No changes in SDKs, endpoints, permissions, credentials or consent defaults.\n`;
  return `${head}${status}| Severity | Change |\n|---|---|\n${changes.map((c) => `| ${c.severity}${policy?.blocking.includes(c) ? ' (blocking)' : ''} | ${c.en.replace(/\|/g, '\\|')} |`).join('\n')}\n`;
}

export function loadSnapshotOrScan(p, opts) {
  if (/\.json$/i.test(p)) {
    const j = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (j.k1d !== 1) throw new Error(`${p} is not a k1d snapshot`);
    return Promise.resolve(j);
  }
  return scanFile(p, opts).then((r) => snapshot(r, { file: p }));
}
