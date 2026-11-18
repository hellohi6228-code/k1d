// Decrypted-traffic analysis (from tools/runtime/k1d_flows.py): which servers received which device
// identifiers, under which field names, and when. Identifiers are matched as plain text, URL-encoded,
// upper/lower case, and as MD5 / SHA-1 / SHA-256 hashes (SDKs often send hashed IDs).
import crypto from 'node:crypto';
import { SYSTEM_HOSTS } from '../site/js/profile.js';

const hash = (alg, s) => crypto.createHash(alg).update(s).digest('hex');
const hostMatches = (host, suffix) => host === suffix || host.endsWith(`.${suffix}`);
const LABELS = {
  gaid: ['advertising ID (GAID)', '广告 ID（GAID）'],
  androidId: ['Android ID', 'Android ID'],
  model: ['device model', '设备型号'],
  serial: ['device serial', '设备序列号'],
};
export const idLabel = (k) => LABELS[k] ?? [k, k];

// ids: { gaid: '38400000-…', androidId: '…', model: 'sdk_gphone64_x86_64' }
export function idVariants(ids) {
  const out = [];
  for (const [name, value] of Object.entries(ids)) {
    if (!value || String(value).length < 6) continue;
    const v = String(value);
    const forms = new Set([v, v.toLowerCase(), v.toUpperCase(), encodeURIComponent(v)]);
    if (name !== 'model') for (const alg of ['md5', 'sha1', 'sha256']) { forms.add(hash(alg, v)); forms.add(hash(alg, v.toLowerCase())); forms.add(hash(alg, v).toUpperCase()); }
    if (name === 'gaid') forms.add(v.replace(/-/g, ''));
    out.push({ name, forms: [...forms].filter((f) => f.length >= 6) });
  }
  return out;
}

// Field names next to a value: "key":"value", key=value, <key>value<
function fieldNames(text, form) {
  const names = new Set();
  const e = form.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  for (const re of [new RegExp(`"([\\w.\\-]{1,40})"\\s*:\\s*"${e}"`, 'g'), new RegExp(`[?&;\\s]([\\w.\\-]{1,40})=${e}`, 'g'), new RegExp(`<([\\w.\\-]{1,40})>${e}<`, 'g')]) {
    for (const m of text.matchAll(re)) names.add(m[1]);
  }
  return [...names];
}

export function parseFlows(jsonl) {
  return jsonl.split('\n').filter((l) => l.trim()).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
}

// flows: parsed records; sdkKb: kb.sdks; startMs / consentMs: epoch ms (optional)
export function analyzeFlows(flows, { ids = {}, sdkKb = null, startMs = null, consentMs = null } = {}) {
  const variants = idVariants(ids);
  const sdkDomains = [];
  for (const s of sdkKb?.sdks ?? []) for (const d of s.domains ?? []) sdkDomains.push({ suffix: d, sdk: s });
  const sdkOf = (host) => sdkDomains.filter((d) => hostMatches(host, d.suffix)).sort((a, b) => b.suffix.length - a.suffix.length)[0]?.sdk ?? null;
  const hosts = new Map();
  const idEvents = [];
  const tlsFailed = new Map();
  let requests = 0;
  for (const f of flows) {
    if (f.tlsFailed) { if (f.host && !tlsFailed.has(f.host)) tlsFailed.set(f.host, f.error ?? ''); continue; }
    requests += 1;
    const ms = f.t * 1000;
    const rel = startMs ? +((ms - startMs) / 1000).toFixed(1) : null;
    const h = hosts.get(f.host) ?? { host: f.host, sdk: sdkOf(f.host), system: SYSTEM_HOSTS.test(f.host), requests: 0, first: rel, bytesSent: 0, ids: {}, examples: [] };
    h.requests += 1;
    h.bytesSent += f.bodySize ?? 0;
    if (h.examples.length < 3) h.examples.push(`${f.method} ${f.url.replace(/^https?:\/\/[^/]+/, '').slice(0, 120)}`);
    const hay = `${f.url}\n${Object.entries(f.headers ?? {}).map(([k, v]) => `${k}: ${v}`).join('\n')}\n${f.body ?? ''}`;
    for (const v of variants) {
      const form = v.forms.find((x) => hay.includes(x));
      if (!form) continue;
      const hashed = form.length >= 32 && /^[0-9a-f]+$/i.test(form) && !String(ids[v.name]).toLowerCase().includes(form.toLowerCase()) ? 'hashed' : 'plain';
      const names = fieldNames(hay, form);
      const entry = h.ids[v.name] ?? { fields: new Set(), first: rel, hashed: false, beforeConsent: false };
      for (const n of names) entry.fields.add(n);
      if (hashed === 'hashed') entry.hashed = true;
      if (consentMs && ms < consentMs) entry.beforeConsent = true;
      h.ids[v.name] = entry;
      idEvents.push({ t: rel, host: f.host, id: v.name, fields: names, hashed: hashed === 'hashed', beforeConsent: Boolean(consentMs && ms < consentMs) });
    }
    hosts.set(f.host, h);
  }
  const hostList = [...hosts.values()].map((h) => ({
    ...h, sdk: h.sdk ? { id: h.sdk.id, name: h.sdk.name, category: h.sdk.category, cnNexus: Boolean(h.sdk.cn_nexus) } : null,
    ids: Object.fromEntries(Object.entries(h.ids).map(([k, e]) => [k, { ...e, fields: [...e.fields] }])),
  })).sort((a, b) => Object.keys(b.ids).length - Object.keys(a.ids).length || (a.first ?? 0) - (b.first ?? 0));
  return { requests, hosts: hostList, idEvents, tlsFailed: [...tlsFailed].map(([host, error]) => ({ host, error, system: SYSTEM_HOSTS.test(host) })), idsChecked: Object.keys(ids).filter((k) => ids[k]) };
}
