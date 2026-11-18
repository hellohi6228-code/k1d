// Evidence report: one self-contained bilingual (EN/ZH) HTML file from a scan (optionally combined
// with a recording). Print to PDF for counsel. Contains file hashes, tool versions and timestamps so
// the findings can be reproduced, plus every risk area, SDK, China-linked endpoint and runtime host.
import { buildRisks, LIMITATIONS } from '../site/js/risks.js';
import { inferProfile, SYSTEM_HOSTS } from '../site/js/profile.js';

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const kb = (n) => (n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1024).toFixed(1)} KB`);
const bi = (s) => `<p>${esc(s.en)}</p><p class="zh">${esc(s.zh)}</p>`;
const AUD = { child: ['Children', '儿童'], mixed: ['Mixed: may include children and teens', '混合受众：可能包含儿童和青少年'], general: ['General audience', '一般受众'] };
const STATUS = { signals: ['Found', '有发现'], none: ['Nothing found', '未发现'] };

export function renderReport(r, { files = [], generatedAt = new Date().toISOString(), brand = null, brandNote = null, ctx = {}, timeline = null } = {}) {
  const prof = inferProfile(r);
  const areas = buildRisks(r, ctx);
  const found = areas.filter((a) => a.status === 'signals');
  const cnSdks = r.sdks.filter((s) => s.cnNexus);
  const cnHosts = r.endpoints.filter((e) => e.cnIndicators.length);
  const tracking = r.sdks.filter((s) => ['ads', 'analytics', 'attribution', 'session-replay'].includes(s.category));
  const t = r.traffic;
  const cAt = ctx.consentAt ?? prof.consent?.at ?? null;
  const start = prof.consent?.appStart ?? null;
  const sdkFor = new Map();
  for (const s of r.sdks) for (const e of s.evidence) if (e.type === 'traffic') for (const h of e.samples) sdkFor.set(h, s.name.en);
  const appName = r.app?.name && r.app.name !== r.app.id ? `${r.app.name} (${r.app.id})` : r.app?.id ?? files[0]?.name ?? 'app';
  const by = brand ? esc(brand) : 'k1d';

  const stat = (n, en, zh) => `<div class="stat"><div class="n">${esc(n)}</div><div class="l">${esc(en)}<br><span class="zh">${esc(zh)}</span></div></div>`;
  const runtimeRows = t ? t.hosts.filter((h) => h.flows > 0 && !SYSTEM_HOSTS.test(h.host)).map((h) => `<tr>
      <td>${start != null && h.relFirst != null ? `${(h.relFirst - start).toFixed(1)}` : '—'}</td>
      <td><code>${esc(h.host)}</code>${cAt != null && h.relFirst != null && h.relFirst < cAt ? ' <span class="pill warn">before consent · 同意前</span>' : ''}</td>
      <td>${esc(sdkFor.get(h.host) ?? '')}${h.cnIndicators.length ? ` <span class="pill cn">CN</span> ${esc(h.cnIndicators.map((i) => i.operator ?? i.type).join(', '))}` : ''}</td>
      <td>${kb(h.up)}</td><td>${kb(h.down)}</td></tr>`).join('') : '';

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(appName)} — evidence report</title>
<style>
:root{--text:#15201e;--muted:#5a6a66;--border:#dde4e2;--accent:#0f766e;--soft:#f1f4f3;--warn:#9a3412;--warn-soft:#fff1e7;--cn:#b42318;--cn-soft:#fdecea}
*{box-sizing:border-box}body{margin:0;background:#fff;color:var(--text);font:13.5px/1.55 -apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif}
main{max-width:900px;margin:0 auto;padding:32px 20px 48px}header{border-bottom:2px solid var(--accent);padding-bottom:12px;margin-bottom:16px}
.brand{color:var(--accent);font-weight:800}h1{font-size:22px;margin:6px 0}h2{font-size:16px;margin:26px 0 8px;border-bottom:1px solid var(--border);padding-bottom:4px}
h3{font-size:14px;margin:14px 0 4px}p{margin:4px 0}.zh{color:#34433f}.muted{color:var(--muted);font-size:12px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:12px 0}.stat{border:1px solid var(--border);border-radius:8px;padding:10px}.stat .n{font-size:20px;font-weight:800}.stat .l{font-size:11.5px;color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:12px;margin:6px 0}th,td{text-align:left;border-bottom:1px solid var(--border);padding:5px 6px;vertical-align:top}th{background:var(--soft)}
code{font:11.5px ui-monospace,Consolas,monospace;overflow-wrap:anywhere}.pill{display:inline-block;border-radius:999px;padding:0 7px;font-size:11px;background:var(--soft)}
.pill.warn{background:var(--warn-soft);color:var(--warn)}.pill.cn{background:var(--cn-soft);color:var(--cn)}
.area{border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin:10px 0}.area.signals{border-left:4px solid var(--warn)}
.area ul{margin:4px 0;padding-left:18px}.refs{font-size:11.5px;color:var(--muted)}.refs a{color:var(--accent)}
.note{background:var(--soft);border-radius:8px;padding:10px 12px;font-size:12.5px}
@media(max-width:640px){.stats{grid-template-columns:repeat(2,1fr)}}@media print{main{padding:0}.area,table{break-inside:avoid}a{color:inherit}}
</style></head><body><main>
<header><div class="brand">${by}${brand ? ' <span class="muted">· analysis by k1d</span>' : ''}</div>
<h1>Evidence report: ${esc(appName)} ${esc(r.app?.versionName ?? '')}</h1>
<p class="zh">证据报告：${esc(appName)} ${esc(r.app?.versionName ?? '')}</p>
<p class="muted">Generated ${esc(generatedAt)} · analyzer ${esc(r.analyzer.version)} · knowledge base ${esc(r.analyzer.kbVersion)} · platform ${esc(r.platform)}${brandNote ? ` · ${esc(brandNote)}` : ''}</p></header>

<div class="note">Factual technical observations, not legal advice. This report does not say whether any law applies; ownership, user counts, contracts and runtime behavior decide that. Draft risk notes are not expert-reviewed.<br><span class="zh">本报告为事实性技术观察，不构成法律意见，也不判断任何法律是否适用。风险说明为草稿，未经专家审核。</span></div>

<h2>1. Inputs · 输入文件</h2>
<table><thead><tr><th>File</th><th>Size</th><th>SHA-256</th></tr></thead><tbody>
${files.map((f) => `<tr><td>${esc(f.name)}</td><td>${esc(f.size)} bytes</td><td><code>${esc(f.sha256)}</code></td></tr>`).join('')}
</tbody></table>
${r.runtime ? `<p>Recording: ${esc(r.runtime.recordingName ?? '')}${t ? ` · ${t.duration ?? '?'} s · ${t.packets} packets` : ''} · ${r.runtime.hostsMatchingApp} of ${r.runtime.hostsContacted} recorded servers belong to this app or its SDKs.</p>` : ''}

<h2>2. Summary · 摘要</h2>
<div class="stats">
${stat(found.length, `of ${areas.length} risk areas with findings`, `个风险领域有发现（共 ${areas.length} 个）`)}
${stat(r.sdks.length, `SDKs (${tracking.length} ads/analytics/attribution)`, `个 SDK（${tracking.length} 个广告/统计/归因）`)}
${stat(cnSdks.length + cnHosts.length, `China-nexus SDKs + endpoints (${cnSdks.length} + ${cnHosts.length})`, `中国关联 SDK + 接口`)}
${stat(t ? kb(t.upTotal) : (r.secrets?.length ?? 0), t ? 'sent by the device during the recording' : 'hard-coded credentials (masked)', t ? '录制期间设备发送的数据' : '硬编码凭据（已遮蔽）')}
</div>
<p>App type: <strong>${esc(prof.category)}</strong> · Likely audience: <strong>${esc(AUD[prof.audience][0])}</strong>${cAt != null ? (ctx.consentAt != null ? ` · Consent tapped at ${cAt}s` : ` · Consent service first contacted at ${cAt}s (${esc(prof.consent?.service ?? '')})`) : ''}</p>
<p class="zh">应用类型：${esc(prof.category)} · 可能受众：${esc(AUD[prof.audience][1])}</p>
${[...prof.categoryBasis, ...prof.audienceBasis].slice(0, 4).map((b) => `<p class="muted">${esc(b.en)} · ${esc(b.zh)}</p>`).join('')}

<h2>3. Risk areas · 风险领域</h2>
${areas.map((a) => `<div class="area ${a.status}"><h3>${esc(a.title.en)} · ${esc(a.title.zh)} <span class="pill ${a.status === 'signals' ? 'warn' : ''}">${esc(STATUS[a.status][0])} · ${esc(STATUS[a.status][1])}</span></h3>
  ${a.signals.length ? `<ul>${a.signals.map((s) => `<li>${esc(s.en)}<br><span class="zh">${esc(s.zh)}</span></li>`).join('')}</ul>` : ''}
  <p><strong>Why this may matter · 可能的影响</strong></p>${bi(a.why)}
  <p><strong>Not scanned · 未扫描</strong></p>${bi(a.unseen)}
  <p class="refs">${a.refs.map(([l, u]) => `<a href="${esc(u)}">${esc(l)}</a>`).join(' · ')}</p></div>`).join('')}

${timeline?.length ? `<h3>Test timeline · 测试时间线</h3><table><thead><tr><th>Time (UTC)</th><th>Step</th><th>Detail</th></tr></thead><tbody>${timeline.map((e) => `<tr><td>${esc(e.t.slice(11, 19))}</td><td>${esc(e.event)}</td><td>${esc(e.detail)}</td></tr>`).join('')}</tbody></table>` : ''}
${t ? `<h2>4. Network activity during the recording · 录制期间的网络活动</h2>
<p class="muted">Seconds are counted from the app's first connection. Operating-system hosts are omitted. Sizes are payload bytes; encrypted contents are not visible. · 秒数从应用首次联网起算；省略操作系统主机；加密内容不可见。</p>
<table><thead><tr><th>s</th><th>Server</th><th>SDK / China-nexus</th><th>Sent</th><th>Received</th></tr></thead><tbody>${runtimeRows}</tbody></table>` : ''}

<h2>${t ? 5 : 4}. SDKs · SDK</h2>
<table><thead><tr><th>SDK</th><th>Category</th><th>China-nexus</th><th>Evidence</th></tr></thead><tbody>
${r.sdks.map((s) => `<tr><td><strong>${esc(s.name.en)}</strong>${s.seenAtRuntime ? ` <span class="pill warn">${s.runtimeOnly ? 'only in recording' : 'connected in recording'}</span>` : ''}<br><span class="muted">${esc(s.vendor)}</span></td><td>${esc(s.category)}</td><td>${s.cnNexus ? `<span class="pill cn">CN</span> ${esc(typeof s.cnNexus === 'string' ? s.cnNexus : '')}` : ''}</td><td class="muted">${esc(s.evidence.slice(0, 3).map((e) => `${e.type}: ${e.signature ?? ''}`).join(' · '))}</td></tr>`).join('')}
</tbody></table>

<h2>${t ? 6 : 5}. China-linked endpoints · 中国关联接口</h2>
${cnHosts.length ? `<table><thead><tr><th>Host</th><th>Indicator</th></tr></thead><tbody>${cnHosts.map((e) => `<tr><td><code>${esc(e.host)}</code></td><td>${esc(e.cnIndicators.map((i) => `${i.operator ? `${i.operator}: ` : ''}${i.text}`).join('; '))}</td></tr>`).join('')}</tbody></table>` : '<p>None found.</p>'}

<h2>${t ? 7 : 6}. Data access and credentials · 数据访问与凭据</h2>
<table><thead><tr><th>Permission / capability</th><th>Level</th></tr></thead><tbody>
${r.permissions.filter((p) => p.level === 'high' || p.level === 'medium').map((p) => `<tr><td><code>${esc(p.name)}</code></td><td>${esc(p.level)}</td></tr>`).join('') || '<tr><td colspan="2">None at high or medium level.</td></tr>'}
</tbody></table>
${(r.secrets ?? []).length ? `<table><thead><tr><th>Credential (masked)</th><th>Where</th></tr></thead><tbody>${r.secrets.map((s) => `<tr><td>${esc(s.label)} <code>${esc(s.value)}</code></td><td class="muted">${esc(s.sources.slice(0, 2).join(', '))}</td></tr>`).join('')}</tbody></table>` : ''}

<h2>${t ? 8 : 7}. Coverage and limits · 覆盖范围与局限</h2>
${r.coverage ? `<p>Text files read: ${r.coverage.textFiles}. Encrypted or compiled script files not readable: ${r.coverage.encrypted.length}.</p>` : ''}
<ul>${(r.limits ?? []).map((l) => `<li>${esc(l.en)}<br><span class="zh">${esc(l.zh)}</span></li>`).join('')}${LIMITATIONS.en.map((l, i) => `<li>${esc(l)}<br><span class="zh">${esc(LIMITATIONS.zh[i])}</span></li>`).join('')}</ul>
<p class="muted" style="margin-top:20px">Reproduce: run the same analyzer and knowledge-base versions on files with the SHA-256 values above. · 复现方法：使用相同版本的分析器和知识库，分析上述 SHA-256 对应的文件。</p>
</main></body></html>`;
}
