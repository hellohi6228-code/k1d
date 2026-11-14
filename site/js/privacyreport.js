// iPhone / iPad App Privacy Report (Settings → Privacy & Security → App Privacy Report → Share).
// Format (Apple, "Inspecting app activity data"): NDJSON, one dictionary per line.
//   type "access":          accessor.identifier (bundle ID), category, identifier (pairs begin/end),
//                           kind intervalBegin|intervalEnd, timeStamp
//   type "networkActivity": bundleID, domain, domainOwner, domainType (1 = identified by Apple as
//                           possibly collecting information across apps and sites), initiatedType
//                           AppInitiated|NonAppInitiated, hits, firstTimeStamp, timeStamp, context
// The phone keeps the last seven days.

export const ACCESS_CATEGORIES = ['camera', 'microphone', 'location', 'photos', 'contacts', 'mediaLibrary', 'screenRecording'];

// Cheap sniff on the first bytes of a file.
export function isPrivacyReport(text) {
  const first = text.trimStart().split('\n', 1)[0];
  if (!first.startsWith('{')) return false;
  try {
    const o = JSON.parse(first);
    return o.type === 'access' || o.type === 'networkActivity' || !!o.accessor || (!!o.bundleID && !!o.domain);
  } catch {
    return /"type"\s*:\s*"(access|networkActivity)"/.test(first);
  }
}

const ms = (s) => { const t = Date.parse(s ?? ''); return Number.isNaN(t) ? null : t; };

export function parsePrivacyReport(text) {
  const apps = new Map();
  const app = (id) => {
    if (!apps.has(id)) apps.set(id, { bundleId: id, domains: new Map(), access: new Map() });
    return apps.get(id);
  };
  const open = new Map(); // access identifier -> begin record
  let lines = 0;
  let bad = 0;
  let start = Infinity;
  let end = -Infinity;
  const seen = (t) => { if (t != null) { start = Math.min(start, t); end = Math.max(end, t); } };
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    lines += 1;
    let o;
    try { o = JSON.parse(line); } catch { bad += 1; continue; }
    if (o.type === 'networkActivity' || (o.bundleID && o.domain)) {
      if (!o.bundleID || !o.domain) continue;
      const a = app(String(o.bundleID));
      const key = String(o.domain).toLowerCase();
      const first = ms(o.firstTimeStamp) ?? ms(o.timeStamp);
      const last = ms(o.timeStamp) ?? first;
      seen(first); seen(last);
      const d = a.domains.get(key) ?? { domain: key, hits: 0, first: null, last: null, owner: '', tracker: false, appInitiated: false, userInitiated: false, contexts: new Set() };
      d.hits += Number(o.hits) || 0;
      if (first != null && (d.first == null || first < d.first)) d.first = first;
      if (last != null && (d.last == null || last > d.last)) d.last = last;
      if (o.domainOwner) d.owner = String(o.domainOwner);
      if (Number(o.domainType) === 1) d.tracker = true;
      if (o.initiatedType === 'NonAppInitiated') d.userInitiated = true; else d.appInitiated = true;
      if (o.context && d.contexts.size < 5) d.contexts.add(String(o.context));
      a.domains.set(key, d);
    } else if (o.type === 'access' || o.accessor) {
      const id = o.accessor?.identifier;
      if (!id || !o.category) continue;
      const a = app(String(id));
      const t = ms(o.timeStamp);
      seen(t);
      const c = a.access.get(o.category) ?? { category: String(o.category), count: 0, first: null, last: null, seconds: 0 };
      if (o.kind === 'intervalEnd') {
        const b = open.get(o.identifier);
        if (b && t != null && b.t != null) c.seconds += Math.max(0, (t - b.t) / 1000);
        open.delete(o.identifier);
      } else {
        c.count += 1;
        if (o.identifier) open.set(o.identifier, { t });
      }
      if (t != null && (c.first == null || t < c.first)) c.first = t;
      if (t != null && (c.last == null || t > c.last)) c.last = t;
      a.access.set(o.category, c);
    }
  }
  return {
    lines, bad,
    start: Number.isFinite(start) ? new Date(start).toISOString() : null,
    end: Number.isFinite(end) ? new Date(end).toISOString() : null,
    apps: [...apps.values()].map((a) => ({
      bundleId: a.bundleId,
      domains: [...a.domains.values()].map((d) => ({ ...d, contexts: [...d.contexts] })).sort((x, y) => y.hits - x.hits),
      access: [...a.access.values()].map((c) => ({ ...c, seconds: Math.round(c.seconds) })),
    })),
  };
}

// Owners named in the knowledge base as PRC-headquartered (infra operators, China-nexus SDK vendors).
export function cnOwnerMatcher(kb) {
  const names = new Set();
  for (const o of kb.infra?.operators ?? []) names.add(o.operator);
  for (const s of kb.sdks?.sdks ?? []) if (s.cn_nexus && s.vendor) names.add(s.vendor);
  const words = [...names].map((n) => n.split(/[\s/(,]/)[0]).filter((w) => w.length >= 4 && !/^(Google|Apple|Amazon|Meta|Microsoft)$/i.test(w));
  const re = words.length ? new RegExp(`\\b(${[...new Set(words)].map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})\\b`, 'i') : null;
  return (owner) => (re && owner ? owner.match(re)?.[0] ?? null : null);
}
