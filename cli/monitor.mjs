// Monitoring and portfolio views.
//  - storeVersions: current public version of an app on Google Play (listing page) and the App Store
//    (Apple's public lookup API). Only public metadata is read; no app files are downloaded.
//  - watch: compares current store versions with the last run and with the builds that went through
//    k1d check (snapshot files), and lists releases that shipped without a check.
//  - portfolio: one HTML dashboard across many apps' snapshots.
import fs from 'node:fs';
import path from 'node:path';
import { diffSnapshots } from './lib.mjs';

const UA = 'Mozilla/5.0 (k1d monitor; +https://hellohi6228-code.github.io/k1d/)';

export function parsePlayListing(html) {
  const version = html.match(/\[\[\["(\d+(?:\.\d+)+[^"]{0,20})"\]\]/)?.[1] ?? null;
  const updated = html.match(/Updated on<\/div><div[^>]*>([^<]+)</)?.[1] ?? null;
  return { version, updated };
}

export async function storeVersions(entry, { fetchImpl = fetch } = {}) {
  const out = { app: entry.app, android: null, ios: null, errors: [] };
  if (entry.app && entry.android !== false) {
    try {
      const html = await fetchImpl(`https://play.google.com/store/apps/details?id=${encodeURIComponent(entry.app)}&hl=en_US&gl=${entry.country ?? 'US'}`, { headers: { 'user-agent': UA } }).then((r) => r.text());
      out.android = parsePlayListing(html);
    } catch (e) { out.errors.push(`Google Play: ${e.message}`); }
  }
  if (entry.iosId) {
    try {
      const j = await fetchImpl(`https://itunes.apple.com/lookup?id=${encodeURIComponent(entry.iosId)}&country=${entry.country ?? 'us'}`).then((r) => r.json());
      const x = j.results?.[0];
      out.ios = x ? { version: x.version, updated: x.currentVersionReleaseDate?.slice(0, 10) ?? null, name: x.trackName, bundleId: x.bundleId } : null;
    } catch (e) { out.errors.push(`App Store: ${e.message}`); }
  }
  return out;
}

export function loadSnapshots(dir) {
  if (!dir || !fs.existsSync(dir)) return [];
  const files = fs.statSync(dir).isDirectory() ? fs.readdirSync(dir).filter((f) => f.endsWith('.json')).map((f) => path.join(dir, f)) : [dir];
  return files.map((f) => { try { const j = JSON.parse(fs.readFileSync(f, 'utf8')); return j.k1d === 1 ? { ...j, _file: f, _mtime: fs.statSync(f).mtime.toISOString() } : null; } catch { return null; } }).filter(Boolean);
}

// Returns { rows: [{ app, platform, version, updated, previous, isNew, checked }], state }
export function compareWatch(current, prevState = {}, snapshots = []) {
  const rows = [];
  const state = {};
  for (const c of current) {
    for (const platform of ['android', 'ios']) {
      const v = c[platform];
      if (!v?.version) continue;
      const key = `${c.app}|${platform}`;
      const previous = prevState[key]?.version ?? null;
      const ids = new Set([c.app, v.bundleId].filter(Boolean));
      const checked = snapshots.some((s) => ids.has(s.app.id) && s.app.version === v.version && (platform === 'ios' ? s.app.platform === 'ios' : s.app.platform !== 'ios'));
      rows.push({ app: c.app, platform, version: v.version, updated: v.updated, previous, isNew: previous != null && previous !== v.version, checked });
      state[key] = { version: v.version, updated: v.updated, seen: new Date().toISOString().slice(0, 10) };
    }
  }
  return { rows, state };
}

export function watchMarkdown(rows, errors = []) {
  const flag = (r) => (r.checked ? 'checked by k1d' : '**not checked**');
  const lines = rows.map((r) => `| ${r.app} | ${r.platform} | ${r.version}${r.isNew ? ` (new, was ${r.previous})` : ''} | ${r.updated ?? ''} | ${flag(r)} |`);
  const unchecked = rows.filter((r) => !r.checked);
  return `### k1d store watch\n\n${unchecked.length ? `**${unchecked.length} live release(s) did not go through k1d check.**\n\n` : 'Every live release went through k1d check.\n\n'}| App | Platform | Store version | Updated | Status |\n|---|---|---|---|---|\n${lines.join('\n')}\n${errors.length ? `\nErrors: ${errors.join('; ')}\n` : ''}`;
}

// ---------------------------------------------------------------- portfolio dashboard
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

export function portfolioHtml(snapshots, { title = 'k1d portfolio', brand = null } = {}) {
  const byApp = new Map();
  for (const s of snapshots) {
    const k = `${s.app.id ?? s.file}|${s.app.platform}`;
    if (!byApp.has(k)) byApp.set(k, []);
    byApp.get(k).push(s);
  }
  const rows = [...byApp.values()].map((list) => {
    list.sort((a, b) => String(a._mtime ?? '').localeCompare(String(b._mtime ?? '')));
    const last = list.at(-1);
    const prev = list.length > 1 ? list.at(-2) : null;
    const changes = prev ? diffSnapshots(prev, last).filter((c) => c.severity !== 'info') : [];
    const found = Object.entries(last.risks ?? {}).filter(([, v]) => v === 'signals').map(([k]) => k);
    return { last, prev, changes, found, cnSdks: last.sdks.filter((x) => x.cn).length, cnHosts: last.hosts.filter((x) => x.cn.length).length, tracking: last.sdks.filter((x) => ['ads', 'analytics', 'attribution', 'session-replay'].includes(x.category)).length };
  }).sort((a, b) => b.changes.length - a.changes.length || b.cnSdks + b.cnHosts - (a.cnSdks + a.cnHosts));
  const total = rows.length;
  const withChanges = rows.filter((r) => r.changes.length).length;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title>
<style>body{margin:0;font:13.5px/1.5 -apple-system,"Segoe UI",Roboto,"PingFang SC",sans-serif;color:#15201e;background:#f7f8f7}main{max-width:1200px;margin:0 auto;padding:28px 18px}
h1{font-size:22px;margin:0 0 4px}.muted{color:#5a6a66;font-size:12px}.stats{display:flex;gap:12px;margin:14px 0;flex-wrap:wrap}.stat{background:#fff;border:1px solid #dde4e2;border-radius:8px;padding:10px 14px}.stat b{font-size:20px;display:block}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #dde4e2;border-radius:8px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #dde4e2;vertical-align:top}th{background:#f1f4f3;font-size:12px}
.pill{display:inline-block;border-radius:999px;padding:0 7px;font-size:11px;background:#f1f4f3;margin:1px}.warn{background:#fff1e7;color:#9a3412}.cn{background:#fdecea;color:#b42318}code{font:11.5px ui-monospace,Consolas,monospace}
@media(max-width:700px){table{font-size:12px}}</style></head><body><main>
<h1>${esc(brand ?? title)}</h1><p class="muted">Generated ${esc(new Date().toISOString())} from ${snapshots.length} k1d snapshot(s). Factual technical observations, not legal advice.</p>
<div class="stats"><div class="stat"><b>${total}</b>apps</div><div class="stat"><b>${withChanges}</b>with changes since the previous check</div><div class="stat"><b>${rows.filter((r) => r.cnSdks || r.cnHosts).length}</b>with China-nexus SDKs or endpoints</div></div>
<table><thead><tr><th>App</th><th>Version</th><th>SDKs</th><th>China-nexus</th><th>Risk areas with findings</th><th>Changes since previous check</th></tr></thead><tbody>
${rows.map((r) => `<tr><td><code>${esc(r.last.app.id)}</code><div class="muted">${esc(r.last.app.platform)}</div></td><td>${esc(r.last.app.version ?? '')}${r.prev ? `<div class="muted">prev ${esc(r.prev.app.version ?? '')}</div>` : ''}</td>
<td>${r.last.sdks.length}<div class="muted">${r.tracking} tracking</div></td><td>${r.cnSdks || r.cnHosts ? `<span class="pill cn">${r.cnSdks} SDK · ${r.cnHosts} hosts</span>` : '—'}</td>
<td>${r.found.map((f) => `<span class="pill warn">${esc(f)}</span>`).join(' ') || '—'}</td>
<td>${r.changes.length ? `<ul style="margin:0;padding-left:16px">${r.changes.slice(0, 6).map((c) => `<li>${esc(c.en)}</li>`).join('')}${r.changes.length > 6 ? `<li class="muted">+${r.changes.length - 6} more</li>` : ''}</ul>` : (r.prev ? 'none' : '<span class="muted">first check</span>')}</td></tr>`).join('')}
</tbody></table></main></body></html>`;
}
