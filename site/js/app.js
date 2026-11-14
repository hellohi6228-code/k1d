import { analyzeSource, ANALYZER_VERSION } from './analyze.js';
import { fileSource } from './zip.js';
import { sha256Hex } from './cert.js';
import { TERMS, TERMS_VERSION, t } from './i18n.js';
import { checkPolicy } from './policy.js';
import { buildRisks, LIMITATIONS } from './risks.js';
import { inferProfile, SYSTEM_HOSTS } from './profile.js';
import { GUIDES } from './guides.js';
import { combineResults, RUNTIME_PLATFORMS } from './combine.js';

const MAX_HASH_BYTES = 512 * 1024 * 1024;
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function storageGet(k) { try { return localStorage.getItem(k); } catch { return null; } }
function storageSet(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } }

const state = {
  lang: storageGet('k1d.lang') || ((navigator.language || '').toLowerCase().startsWith('zh') ? 'zh' : 'en'),
  kb: null,
  file: null,
  consent: null,
  fileSha256: null,
  recFile: null, // recording added to an app file (combine.js)
  recSha256: null,
  reuseApp: null,
  appResult: null,
  result: null,
  policyText: '',
  policy: null,
  tab: 'sdks',
  showAllEndpoints: false,
  view: 'start',
};

const L = (key, vars) => t(state.lang, key, vars);
const pick = (obj) => (obj ? obj[state.lang] ?? obj.en : '');
const isIos = () => Boolean(state.result?.ios); // iOS and macOS app bundles
const PLATFORM_LABELS = {
  android: 'Android', ios: 'iOS', macos: 'macOS', windows: 'Windows', linux: 'Linux', harmonyos: 'HarmonyOS',
  'browser-extension': 'Browser extension', miniprogram: 'WeChat mini-program', electron: 'Electron', archive: 'Archive', unknown: 'Unknown', traffic: 'Network capture', 'iphone-report': 'iPhone App Privacy Report',
};

// Knowledge-base indicator texts are stored in English; translate the known patterns for ZH.
const CN_PATTERNS = [
  [/^Parent company \((.+)\) headquartered in PRC$/, '母公司（$1）总部位于中国'],
  [/^Vendor \((.+)\) headquartered in PRC$/, '提供方（$1）总部位于中国'],
  [/^Vendor headquartered in PRC$/, '提供方总部位于中国'],
  [/^Industry alliance based in PRC$/, '总部位于中国的行业联盟'],
  [/^Operator headquartered in PRC$/, '运营方总部位于中国'],
  [/^Operator's parent headquartered in PRC$/, '运营方的母公司总部位于中国'],
  [/^\.cn country-code domain$/, '.cn 国家代码顶级域名'],
];
function cnText(s) {
  if (state.lang !== 'zh' || !s) return s;
  const m = /^Domain listed for (.+?); (.+)$/.exec(s);
  if (m) return `知识库中 ${m[1]} 的域名；${cnText(m[2])}`;
  for (const [re, zh] of CN_PATTERNS) if (re.test(s)) return s.replace(re, zh);
  return s;
}

const prettyType = (t0) => t0.replace(/^NSPrivacyCollectedDataType/, '').replace(/([a-z])([A-Z])/g, '$1 $2');

// ---------------------------------------------------------------- views
function show(view) {
  state.view = view;
  for (const v of ['start', 'consent', 'progress', 'error', 'results']) $(`view-${v}`).hidden = v !== view;
  window.scrollTo({ top: 0 });
}

// **bold** and `code` in guide text; everything else is escaped.
const fmtGuide = (s) => esc(s).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>').replace(/`(.+?)`/g, '<code>$1</code>');

function renderGuides() {
  const g = GUIDES[state.lang];
  const open = new Set([...document.querySelectorAll('#guides details[open]')].map((d) => d.id));
  $('guides').innerHTML = `<h3 id="guides-title">${esc(g.title)}</h3><p class="muted small">${esc(g.intro)}</p>
    ${g.list.map((x) => `<details id="guide-${x.id}" ${open.has(`guide-${x.id}`) ? 'open' : ''}>
      <summary>${esc(x.title)}</summary>
      <p class="small">${fmtGuide(x.what)}</p>
      <ol class="steps">${x.steps.map((s) => `<li>${fmtGuide(s)}</li>`).join('')}</ol>
      ${x.note ? `<p class="muted small">${fmtGuide(x.note)}</p>` : ''}
    </details>`).join('')}`;
}

function applyStatic() {
  document.documentElement.lang = state.lang === 'zh' ? 'zh-CN' : 'en';
  for (const el of document.querySelectorAll('[data-i18n]')) el.textContent = L(el.dataset.i18n);
  renderGuides();
  for (const b of document.querySelectorAll('[data-lang]')) b.setAttribute('aria-pressed', String(b.dataset.lang === state.lang));
}

function rerender() {
  applyStatic();
  if (state.view === 'consent') renderConsent();
  if (state.view === 'results') renderResults();
}

function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

// ---------------------------------------------------------------- start
// One file, or an app file plus a recording of it (either order; sorted out after analysis).
function pickFile(fileOrList, { reuseApp = null } = {}) {
  const list = fileOrList instanceof File ? [fileOrList] : [...(fileOrList ?? [])];
  if (!list.length) return;
  state.file = list[0];
  state.recFile = list[1] ?? null;
  state.reuseApp = reuseApp;
  state.result = null;
  state.policy = null;
  state.policyText = '';
  state.consent = null;
  $('c-agree').checked = false;
  renderConsent();
  show('consent');
}

function initStart() {
  const dz = $('dropzone');
  const input = $('file-input');
  input.addEventListener('change', () => pickFile(input.files));
  dz.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
  for (const ev of ['dragenter', 'dragover']) dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('drag'); });
  for (const ev of ['dragleave', 'drop']) dz.addEventListener(ev, () => dz.classList.remove('drag'));
  dz.addEventListener('drop', (e) => { e.preventDefault(); pickFile(e.dataTransfer.files); });
  for (const b of document.querySelectorAll('.js-restart')) b.addEventListener('click', () => { $('file-input').value = ''; show('start'); });
  $('rec-input').addEventListener('change', (e) => {
    const rec = e.target.files[0];
    e.target.value = '';
    if (rec && state.appResult) { const app = state.file; pickFile([app, rec], { reuseApp: state.appResult }); }
  });
}

// ---------------------------------------------------------------- consent
function scopeText() {
  return [
    `${L('scopeFile')}: ${scopeFiles().map((f) => f.name).join(' + ')}`,
    `${L('scopeSize')}: ${scopeFiles().reduce((n, f) => n + f.size, 0)} bytes`,
    `${L('scopeTechniques')}: ${L('scopeTechniquesValue')}`,
    `${L('scopeValidity')}: ${L('scopeValidityValue')}`,
  ].join('\n');
}

const scopeFiles = () => [state.file, state.recFile].filter(Boolean);

function renderConsent() {
  const f = { name: scopeFiles().map((x) => x.name).join(' + '), size: scopeFiles().reduce((n, x) => n + x.size, 0) };
  $('scope-list').innerHTML = `
    <dt>${esc(L('scopeFile'))}</dt><dd><code>${esc(f.name)}</code></dd>
    <dt>${esc(L('scopeSize'))}</dt><dd>${esc(fmtBytes(f.size))}</dd>
    <dt>${esc(L('scopeTechniques'))}</dt><dd>${esc(L('scopeTechniquesValue'))}</dd>
    <dt>${esc(L('scopeValidity'))}</dt><dd>${esc(L('scopeValidityValue'))}</dd>`;
  $('terms-text').textContent = TERMS[state.lang];
  $('c-agree-label').textContent = L('consentCheckbox', { v: TERMS_VERSION });
  $('c-submit').textContent = L('consentButton', { file: f.name });
  $('c-agree').checked = false;
  updateConsentButton();
}

function updateConsentButton() {
  const ok = $('c-agree').checked;
  $('c-submit').disabled = !ok;
  $('c-hint').hidden = ok;
}

function initConsent() {
  $('c-agree').addEventListener('input', updateConsentButton);
  $('c-agree').addEventListener('change', updateConsentButton);
  $('c-cancel').addEventListener('click', () => { $('file-input').value = ''; show('start'); });
  $('consent-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if ($('c-submit').disabled) return;
    state.consent = {
      termsVersion: TERMS_VERSION,
      termsLocale: state.lang,
      termsSha256: await sha256Hex(new TextEncoder().encode(TERMS[state.lang])),
      acceptedAt: new Date().toISOString(),
      name: $('c-name').value.trim() || null,
      role: $('c-role').value.trim() || null,
      organization: $('c-org').value.trim() || null,
      checkboxText: L('consentCheckbox', { v: TERMS_VERSION }),
      buttonText: L('consentButton', { file: scopeFiles().map((x) => x.name).join(' + ') }),
      scopeText: scopeText(),
      userAgent: navigator.userAgent,
      recordedWhere: 'local browser only (static site, no server)',
    };
    runAnalysis();
  });
}

// ---------------------------------------------------------------- analysis
async function runAnalysis() {
  show('progress');
  const setProgress = (p) => {
    let text = L(`step_${p.step}`, { i: p.i, n: p.n });
    if (p.detail) text += ` — ${p.detail}`;
    $('progress-text').textContent = text;
  };
  try {
    const hash = async (f) => (f.size <= MAX_HASH_BYTES ? sha256Hex(new Uint8Array(await f.arrayBuffer())) : null);
    setProgress({ step: 'hash' });
    let first = state.reuseApp ? { result: state.reuseApp, sha: state.fileSha256 } : { result: null, sha: await hash(state.file) };
    if (!first.result) first.result = await analyzeSource(fileSource(state.file), state.kb, { onProgress: setProgress });
    state.fileSha256 = first.sha;
    state.recSha256 = null;
    state.appResult = null;
    if (state.recFile) {
      const second = { result: await analyzeSource(fileSource(state.recFile), state.kb, { onProgress: setProgress }), sha: await hash(state.recFile) };
      let [app, rec] = [first, second];
      if (RUNTIME_PLATFORMS.has(app.result.platform) && !RUNTIME_PLATFORMS.has(rec.result.platform)) {
        [app, rec] = [rec, app];
        [state.file, state.recFile] = [state.recFile, state.file];
      }
      if (RUNTIME_PLATFORMS.has(app.result.platform) || !RUNTIME_PLATFORMS.has(rec.result.platform)) throw new Error('NEED_APP_AND_RECORDING');
      state.fileSha256 = app.sha;
      state.recSha256 = rec.sha;
      state.appResult = app.result;
      state.result = combineResults(app.result, rec.result, { recordingName: state.recFile.name });
    } else {
      state.result = first.result;
      if (!RUNTIME_PLATFORMS.has(first.result.platform)) state.appResult = first.result;
    }
    state.reuseApp = null;
    state.tab = 'risks';
    state.showAllEndpoints = false;
    renderResults();
    show('results');
  } catch (err) {
    console.error(err);
    const code = String(err?.message || err);
    const key = `err_${code}`;
    $('error-text').textContent = L(key) !== key ? L(key) : L('err_generic', { msg: code });
    show('error');
  }
}

// ---------------------------------------------------------------- results
function stats(r) {
  if (r.privacyReport) {
    const apps = r.privacyReport.apps.filter((a) => !a.apple);
    const flagged = new Set(apps.flatMap((a) => a.domains.filter((d) => d.tracker && d.appInitiated).map((d) => d.domain)));
    const cnApps = apps.filter((a) => a.cnDomains).length;
    return [
      { n: apps.length, l: L('appsRecorded') },
      { n: cnApps, l: L('appsCnStat'), cls: cnApps ? 'cn' : '' },
      { n: flagged.size, l: L('trackerDomains') },
      { n: apps.filter((a) => a.access.some((c) => ['camera', 'microphone', 'location'].includes(c.category))).length, l: L('appsSensitive') },
    ];
  }
  const cn = r.sdks.filter((s) => s.cnNexus).length;
  const sensitive = r.permissions.filter((p) => p.level === 'high' || p.level === 'medium').length;
  return [
    { n: r.sdks.length, l: L('sdkCount') },
    { n: cn, l: L('cnCount'), cls: cn ? 'cn' : '' },
    { n: sensitive, l: L('permCount') },
    { n: r.endpoints.length, l: L('endpointCount') },
  ];
}

function tabs() {
  const r = state.result;
  if (r.privacyReport) return ['apps', 'sdks', 'endpoints', 'export'];
  if (r.traffic && !r.runtime) return ['risks', 'traffic', 'sdks', 'endpoints', 'policy', 'export'];
  const list = ['risks'];
  if (r.traffic) list.push('traffic');
  list.push('sdks', 'permissions', 'endpoints');
  if (isIos()) list.push('declared');
  list.push('details', 'policy', 'export');
  return list;
}

function tabCount(tab) {
  const r = state.result;
  return {
    sdks: r.sdks.length, permissions: r.permissions.length, endpoints: r.endpoints.length,
    declared: r.ios ? r.ios.declaredData.length : undefined, risks: r.privacyReport ? undefined : currentRisks().filter((a) => a.status === 'signals').length,
    traffic: r.traffic ? r.traffic.hosts.filter((h) => h.flows > 0).length : undefined,
    apps: r.privacyReport ? r.privacyReport.apps.filter((a) => !a.apple).length : undefined,
  }[tab];
}

function currentRisks() {
  return buildRisks(state.result, {}, state.policy);
}

function renderResults() {
  const r = state.result;
  const platform = `${PLATFORM_LABELS[r.platform] ?? r.platform} · ${String(r.container).toUpperCase()}`;
  const id = r.app.id ?? state.file.name;
  $('r-title').innerHTML = `<span class="platform">${esc(platform)}</span>${r.app.name && r.app.name !== id ? `${esc(r.app.name)} ` : ''}<span class="${r.app.name && r.app.name !== id ? 'muted' : ''}">${esc(id)}</span> <span class="muted">${esc(r.app.versionName ?? '')}${r.app.versionCode != null ? ` (${esc(r.app.versionCode)})` : ''}</span>`;
  const minLine = r.privacyReport
    ? L('aprMeta', { from: fmtDate(r.privacyReport.start), to: fmtDate(r.privacyReport.end), n: r.privacyReport.records })
    : r.traffic && !r.runtime
    ? L('trafficMeta', { packets: r.traffic.packets, s: r.traffic.duration ?? '?', flows: r.traffic.flows })
    : r.platform === 'android'
    ? L('minTarget', { min: r.app.minSdk ?? '?', target: r.app.targetSdk ?? '?' })
    : r.ios ? L('minIos', { min: r.app.minSdk ?? '?', target: r.app.targetSdk ?? '?' })
      : r.app.publisher ? `${L('publisher')}: ${r.app.publisher}` : '';
  $('r-meta').innerHTML = `${esc(state.file.name)} · ${esc(fmtBytes(state.file.size))} · ${esc(minLine)}<br>
    ${esc(L('fileHash'))}: <code>${esc(state.fileSha256 ?? L('notComputed'))}</code><br>
    ${esc(L('analyzedIn', { s: (r.durationMs / 1000).toFixed(1), v: ANALYZER_VERSION, kb: r.analyzer.kbVersion }))}${r.notice ? `<div class="banner" style="margin-top:12px"><strong>${esc(pick(r.notice))}</strong></div>` : ''}`;
  const rt = r.runtime;
  if (rt) $('r-meta').innerHTML += `<br><strong>${esc(L('withRecording'))}</strong> ${esc(rt.recordingName ?? '')} · ${esc(L('recordingMatch', { m: rt.hostsMatchingApp, n: rt.hostsContacted }))}`;
  $('r-addrec').innerHTML = state.appResult && !rt
    ? `<div class="card addrec"><div><strong>${esc(L('addRecTitle'))}</strong><p class="muted small" style="margin:4px 0 0">${esc(L('addRecBody'))}</p></div><button type="button" class="btn btn-secondary" id="addrec-btn">${esc(L('addRecButton'))}</button></div>`
    : '';
  $('addrec-btn')?.addEventListener('click', () => $('rec-input').click());
  $('r-stats').innerHTML = stats(r).map((s) => `<div class="stat ${s.cls ?? ''}"><div class="n">${s.n}</div><div class="l">${esc(s.l)}</div></div>`).join('');
  const list = tabs();
  if (!list.includes(state.tab)) state.tab = list.includes('apps') ? 'apps' : 'sdks';
  $('r-tabs').innerHTML = list.map((tab) => {
    const c = tabCount(tab);
    return `<button type="button" role="tab" data-tab="${tab}" aria-selected="${state.tab === tab}">${esc(L(`tab_${tab}`))}${c !== undefined ? `<span class="count">${c}</span>` : ''}</button>`;
  }).join('');
  renderPanel();
}

function renderPanel() {
  const fn = {
    risks: panelRisks, traffic: panelTraffic, apps: panelApps, sdks: panelSdks, permissions: panelPermissions, endpoints: panelEndpoints, declared: panelDeclared,
    details: panelDetails, policy: panelPolicy, export: panelExport,
  }[state.tab];
  $('r-panel').innerHTML = fn();
  bindPanel();
}

function evidenceLine(e) {
  const sig = `<code>${esc(e.signature)}</code>`;
  let s = esc(L(`evidence_${e.type}`, { n: e.count, sig: '\u0000' })).replace('\u0000', sig);
  if (e.samples?.length && !['native', 'config_key', 'plist_key', 'query_scheme', 'ios_class'].includes(e.type)) {
    s += `<br><code>${e.samples.slice(0, 3).map(esc).join('<br>')}</code>`;
  }
  return `<li>${s}</li>`;
}

function encryptedBanner() {
  const r = state.result;
  const enc = isIos() && r.ios.binary?.encrypted ? `<div class="banner">${esc(L('encryptedBanner'))}</div>` : '';
  return enc + (r.limits ?? []).map((l) => `<div class="banner">${esc(pick(l))}</div>`).join('');
}

function sdkTable(sdks) {
  return `<div class="table-wrap"><table>
    <thead><tr><th>${esc(L('colSdk'))}</th><th>${esc(L('colCategory'))}</th><th>${esc(L('colCnNexus'))}</th><th>${esc(L('colConfidence'))}</th><th>${esc(L('colEvidence'))}</th></tr></thead>
    <tbody>${sdks.map((s) => `<tr>
      <td><strong>${esc(pick(s.name))}</strong><div class="sub">${esc(s.vendor)}</div>${s.seenAtRuntime ? ` <span class="pill warn">${esc(L(s.runtimeOnly ? 'onlyAtRuntime' : 'seenAtRuntime'))}</span>` : ''}</td>
      <td>${esc(L(`category_${s.category}`))}</td>
      <td>${s.cnNexus ? `<span class="pill cn">CN</span> <span class="sub">${esc(cnText(s.cnNexus))}</span>` : '<span class="muted">—</span>'}</td>
      <td><span class="pill ${s.confidence === 'high' ? 'high' : ''}">${esc(L(`conf_${s.confidence}`))}</span></td>
      <td><ul class="ev">${s.evidence.map(evidenceLine).join('')}</ul></td>
    </tr>`).join('')}</tbody></table></div>`;
}

function panelSdks() {
  const r = state.result;
  return `${encryptedBanner()}<div class="banner">${esc(L('kbSeedBanner'))}</div>
    <p class="note-line">${esc(L('codePresentNote'))}</p>
    ${r.sdks.length ? sdkTable(r.sdks) : `<p>${esc(L('noSdks'))}</p>`}`;
}

function levelPill(level) {
  return level ? `<span class="pill ${level === 'high' ? 'warn' : ''}">${esc(L(`sev_${level}`))}</span>` : '';
}

function panelPermissions() {
  const r = state.result;
  const cats = state.kb.permissions.categories;
  const order = { high: 0, medium: 1, low: 2 };
  if (r.platform !== 'android') {
    if (!r.permissions.length) return `<p class="muted">${esc(L('noPermissions'))}</p>`;
    const rows = [...r.permissions].sort((a, b) => (order[a.level] ?? 3) - (order[b.level] ?? 3));
    return `<p class="note-line">${esc(L(isIos() ? 'iosPermNote' : r.platform === 'windows' ? 'winPermNote' : 'genericPermNote'))}</p>
      <div class="table-wrap"><table>
      <thead><tr><th>${esc(L(isIos() ? 'colIosKey' : 'colPermission'))}</th><th>${esc(L('colDataCategory'))}</th><th>${esc(L('colLevel'))}</th><th>${esc(L(isIos() ? 'colExplanation' : 'colNote'))}</th></tr></thead>
      <tbody>${rows.map((p) => `<tr><td><code>${esc(p.name)}</code></td><td>${esc(pick(cats[p.category]))}</td><td>${levelPill(p.level)}</td><td>${p.kind === 'usage' ? `“${esc(p.description)}”` : `<span class="sub">${esc(p.description)}</span>`}</td></tr>`).join('')}</tbody></table></div>`;
  }
  const sensitive = r.permissions.filter((p) => p.level).sort((a, b) => order[a.level] - order[b.level]);
  const other = r.permissions.filter((p) => !p.level);
  return `<div class="table-wrap"><table>
    <thead><tr><th>${esc(L('colPermission'))}</th><th>${esc(L('colDataCategory'))}</th><th>${esc(L('colLevel'))}</th></tr></thead>
    <tbody>${sensitive.map((p) => `<tr><td><code>${esc(p.name)}</code></td><td>${esc(pick(cats[p.category]))}</td><td>${levelPill(p.level)}</td></tr>`).join('')}</tbody></table></div>
    ${other.length ? `<h3 style="margin-top:18px">${esc(L('otherPermissions'))}</h3><ul class="list-plain">${other.map((p) => `<li><code>${esc(p.name)}</code></li>`).join('')}</ul>` : ''}`;
}

function panelEndpoints() {
  const r = state.result;
  if (!r.endpoints.length) return `<p>${esc(L('noEndpoints'))}</p>`;
  const limit = 150;
  const rows = state.showAllEndpoints ? r.endpoints : r.endpoints.slice(0, limit);
  return `${encryptedBanner()}<p class="note-line">${esc(L('endpointsNote'))}</p>
    <div class="table-wrap"><table>
    <thead><tr><th>${esc(L('colHost'))}</th><th>${esc(L('colOperator'))}</th><th>${esc(L('colExample'))}</th><th>${esc(L('colFoundIn'))}</th></tr></thead>
    <tbody>${rows.map((e) => `<tr>
      <td><code>${esc(e.host)}</code> ${e.isIp ? `<span class="pill">${esc(L('ipLiteral'))}</span>` : ''} ${e.cleartext ? `<span class="pill warn">${esc(L('cleartext'))}</span>` : ''}</td>
      <td>${e.cnIndicators.map((i) => `<span class="pill cn">CN</span> <span class="sub">${esc(i.operator ? `${i.operator}: ` : '')}${esc(cnText(i.text))}</span>`).join('<br>') || (e.operator ? esc(e.operator) : '<span class="muted">—</span>')}</td>
      <td><code>${esc(e.urls[0])}</code>${e.urls.length > 1 ? ` <span class="sub">+${e.urls.length - 1}</span>` : ''}</td>
      <td class="sub">${e.sources.slice(0, 3).map(esc).join('<br>')}</td>
    </tr>`).join('')}</tbody></table></div>
    ${!state.showAllEndpoints && r.endpoints.length > limit ? `<p><button type="button" class="btn btn-secondary" id="show-all-endpoints">${esc(L('showAll', { n: r.endpoints.length }))}</button></p>` : ''}`;
}

function yesNo(v, warnWhenTrue = false) {
  if (v === null || v === undefined) return `<span class="muted">${esc(L('notSet'))}</span>`;
  if (v === true) return warnWhenTrue ? `<span class="pill warn">${esc(L('yes'))}</span>` : esc(L('yes'));
  if (v === false) return esc(L('no'));
  return `<code>${esc(v)}</code>`;
}

function panelDeclared() {
  const ios = state.result.ios;
  const cats = state.kb.permissions.categories;
  if (!ios.privacyManifests.length) return `<p>${esc(L('noDeclared'))}</p>`;
  return `<p class="note-line">${esc(L('declaredIntro'))}</p>
    <div class="table-wrap"><table>
    <thead><tr><th>${esc(L('colDataType'))}</th><th>${esc(L('colDataCategory'))}</th><th>${esc(L('colLinked'))}</th><th>${esc(L('colTracking'))}</th><th>${esc(L('colDeclaredBy'))}</th></tr></thead>
    <tbody>${ios.declaredData.map((d) => `<tr><td><strong>${esc(prettyType(d.type))}</strong></td><td>${esc(pick(cats[d.category]))}</td>
      <td>${yesNo(d.linked)}</td><td>${yesNo(d.tracking, true)}</td><td class="sub">${[...new Set(d.owners)].map(esc).join('<br>')}</td></tr>`).join('')}</tbody></table></div>
    <h3 style="margin-top:18px">${esc(L('manifestsTitle'))}</h3>
    <div class="table-wrap"><table>
    <thead><tr><th>${esc(L('colManifest'))}</th><th>${esc(L('colTracking'))}</th><th>${esc(L('colTrackingDomains'))}</th></tr></thead>
    <tbody>${ios.privacyManifests.map((p) => `<tr><td><code>${esc(p.owner)}</code></td><td>${yesNo(p.tracking, true)}</td><td>${p.trackingDomains.map((d) => `<code>${esc(d)}</code>`).join('<br>') || '<span class="muted">—</span>'}</td></tr>`).join('')}</tbody></table></div>`;
}

function certCard() {
  const r = state.result;
  const c = r.cert;
  const dn = (o) => Object.entries(o ?? {}).map(([k, v]) => `${k}=${v}`).join(', ');
  const iosRows = isIos() ? `
      <dt>${esc(L('teamId'))}</dt><dd>${r.ios.teamId ? `<code>${esc(r.ios.teamId)}</code>` : '—'}</dd>
      <dt>${esc(L('signingId'))}</dt><dd>${r.ios.signingIdentifier ? `<code>${esc(r.ios.signingIdentifier)}</code>` : '—'}</dd>` : '';
  return `<div class="card"><h3>${esc(L('signingTitle'))}</h3>${c ? `<dl class="kv">
      <dt>${esc(L('certScheme'))}</dt><dd>${esc(r.signatureSchemes.join(', '))}</dd>
      <dt>${esc(L('certSha'))}</dt><dd><code>${esc(c.sha256)}</code></dd>
      <dt>${esc(L('certSubject'))}</dt><dd>${esc(dn(c.subject))} ${c.subject?.C === 'CN' ? '<span class="pill cn">C=CN</span>' : ''}</dd>
      <dt>${esc(L('certIssuer'))}</dt><dd>${esc(dn(c.issuer))}</dd>
      <dt>${esc(L('certValidity'))}</dt><dd>${esc(c.notBefore ?? '?')} → ${esc(c.notAfter ?? '?')}</dd>${iosRows}
    </dl><p class="muted small">${esc(L('certNote'))}</p>` : `<p>${esc(L('noCert'))}</p>${iosRows ? `<dl class="kv">${iosRows}</dl>` : ''}`}</div>`;
}

const listOrDash = (arr, fmt = (x) => `<code>${esc(x)}</code>`) => (arr?.length ? `<div class="chips">${arr.map(fmt).join('')}</div>` : '<span class="muted">—</span>');

function panelDetailsAndroid() {
  const r = state.result;
  const a = r.android;
  return `<div class="grid-2">${certCard()}
    <div class="card"><h3>${esc(L('appFlags'))}</h3><dl class="kv">
      ${['usesCleartextTraffic', 'allowBackup', 'debuggable', 'networkSecurityConfig'].map((k) => `<dt>${esc(L(`flag_${k}`))}</dt><dd>${yesNo(a.application[k], true)}</dd>`).join('')}
    </dl></div></div>
  <div class="card"><h3>${esc(L('exportedComponents', { n: a.exportedComponents.length, total: a.componentCount }))}</h3>
    <ul class="list-plain">${a.exportedComponents.map((x) => `<li><span class="pill">${esc(x.type)}</span> <code>${esc(x.name)}</code></li>`).join('') || '<li class="muted">—</li>'}</ul></div>
  <div class="grid-2">
    <div class="card"><h3>${esc(L('metaData'))}</h3><ul class="list-plain">${a.metaData.map((m) => `<li><code>${esc(m.name)}</code> = <code>${esc(m.value)}</code></li>`).join('') || '<li class="muted">—</li>'}</ul></div>
    <div class="card"><h3>${esc(L('configKeys'))}</h3>${listOrDash(r.configKeys)}
      <h3 style="margin-top:14px">${esc(L('queries'))}</h3>${listOrDash(a.queriedPackages)}</div>
  </div>
  <div class="card"><h3>${esc(L('nativeLibs'))}</h3><ul class="list-plain">${a.nativeLibs.map((l) => `<li><code>${esc(l.name)}</code> <span class="muted small">${esc(l.abis.join(', '))}</span></li>`).join('') || '<li class="muted">—</li>'}</ul></div>`;
}

function panelDetailsIos() {
  const r = state.result;
  const ios = r.ios;
  const b = ios.binary;
  const prov = ios.provisioning;
  const meta = ios.storeMetadata;
  const ents = Object.entries(ios.entitlements ?? {});
  const entVal = (v) => (Array.isArray(v) ? v.join(', ') : typeof v === 'object' && v ? JSON.stringify(v) : String(v));
  return `${encryptedBanner()}<div class="grid-2">${certCard()}
    <div class="card"><h3>${esc(L('binaryTitle'))}</h3>${b ? `<dl class="kv">
      <dt>${esc(L('arch'))}</dt><dd>${esc(b.arch)}${b.fat ? ` <span class="sub">(${b.fat} slices)</span>` : ''}</dd>
      <dt>${esc(L('encryption'))}</dt><dd>${b.encrypted ? `<span class="pill warn">${esc(L('encryptedYes'))}</span>` : esc(L('encryptedNo'))}</dd>
      <dt>${esc(L('readableClasses'))}</dt><dd>${esc(ios.objcClasses)}</dd>
    </dl>` : '<p class="muted">—</p>'}</div></div>
  <div class="grid-2">
    <div class="card"><h3>${esc(L('distributionTitle'))}</h3>
      ${meta ? `<h4 class="muted small">${esc(L('storeMeta'))}</h4><dl class="kv">
        <dt>${esc(L('seller'))}</dt><dd>${esc(meta.artistName ?? '—')}</dd>
        <dt>${esc(L('itemId'))}</dt><dd>${esc(meta.itemId ?? '—')}</dd></dl>` : ''}
      ${prov ? `<h4 class="muted small">${esc(L('provisioning'))}</h4><dl class="kv">
        <dt>${esc(L('provType'))}</dt><dd>${esc(prov.type)}</dd>
        <dt>${esc(L('teamName'))}</dt><dd>${esc(prov.teamName ?? '—')}</dd>
        <dt>${esc(L('teamId'))}</dt><dd>${esc((prov.teamIds ?? []).join(', '))}</dd>
        <dt>${esc(L('expires'))}</dt><dd>${esc(prov.expires ?? '—')}</dd>
        <dt>${esc(L('devices'))}</dt><dd>${esc(prov.provisionsAllDevices ? 'all' : prov.provisionedDevices)}</dd></dl>` : `<p class="muted small">${esc(L('noProvisioning'))}</p>`}
    </div>
    <div class="card"><h3>${esc(L('atsTitle'))}</h3><dl class="kv">
      <dt>${esc(L('atsArbitrary'))}</dt><dd>${yesNo(ios.ats ? ios.ats.allowsArbitraryLoads : null, true)}</dd>
      <dt>${esc(L('atsExceptions'))}</dt><dd>${ios.ats?.exceptionDomains.length ? ios.ats.exceptionDomains.map((d) => `<code>${esc(d.domain)}</code>${d.insecureHttp ? ` <span class="pill warn">${esc(L('insecureHttp'))}</span>` : ''}`).join('<br>') : '—'}</dd>
    </dl></div>
  </div>
  <div class="card"><h3>${esc(L('frameworksTitle', { n: ios.frameworks.length }))}</h3>
    <ul class="list-plain">${ios.frameworks.map((f) => `<li><code>${esc(f.name)}</code> <span class="sub">${esc([f.bundleId, f.version].filter(Boolean).join(' · '))}</span>${f.encrypted ? ` <span class="pill">${esc(L('encryptedYes'))}</span>` : ''}</li>`).join('') || '<li class="muted">—</li>'}
    ${ios.dylibs.map((d) => `<li><code>${esc(d)}</code></li>`).join('')}</ul></div>
  <div class="grid-2">
    <div class="card"><h3>${esc(L('systemFrameworks'))}</h3>${listOrDash(ios.linkedSystem)}</div>
    <div class="card"><h3>${esc(L('extensionsTitle'))}</h3><ul class="list-plain">${ios.extensions.map((x) => `<li><code>${esc(x.name)}</code> <span class="sub">${esc(x.type ?? '')}</span></li>`).join('') || '<li class="muted">—</li>'}</ul></div>
  </div>
  <div class="grid-2">
    <div class="card"><h3>${esc(L('urlSchemes'))}</h3>${listOrDash(ios.urlSchemes)}
      <h3 style="margin-top:14px">${esc(L('queriedSchemes'))}</h3>${listOrDash(ios.queriesSchemes)}</div>
    <div class="card"><h3>${esc(L('backgroundModes'))}</h3>${listOrDash(ios.backgroundModes)}
      <h3 style="margin-top:14px">${esc(L('associatedDomains'))}</h3>${listOrDash(ios.associatedDomains)}</div>
  </div>
  <div class="grid-2">
    <div class="card"><h3>${esc(L('entitlementsTitle'))}</h3><ul class="list-plain">${ents.map(([k, v]) => `<li><code>${esc(k)}</code> = <code>${esc(entVal(v))}</code></li>`).join('') || '<li class="muted">—</li>'}</ul></div>
    <div class="card"><h3>${esc(L('configKeys'))}</h3>${listOrDash(r.configKeys)}</div>
  </div>`;
}

function genericSections(details) {
  return details.map((d) => `<div class="card"><h3>${esc(pick(d.title))}</h3>
    ${d.rows?.length ? `<dl class="kv">${d.rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>` : ''}
    ${(d.lists ?? []).filter((l) => l.items?.length).map((l) => `<h4 class="muted small" style="margin:12px 0 6px">${esc(l.title)} (${l.items.length})</h4>
      <ul class="list-plain">${l.items.slice(0, 200).map((x) => `<li><code>${esc(x)}</code></li>`).join('')}</ul>`).join('')}
  </div>`).join('');
}

function secretsCard() {
  const s = state.result.secrets ?? [];
  if (!s.length) return '';
  return `<div class="card"><h3>${esc(L('secretsTitle'))}</h3><p class="muted small">${esc(L('secretsNote'))}</p>
    <div class="table-wrap"><table><thead><tr><th>${esc(L('colSecret'))}</th><th>${esc(L('colValue'))}</th><th>${esc(L('colFoundIn'))}</th></tr></thead><tbody>
    ${s.map((x) => `<tr><td>${esc(x.label)} ${levelPill(x.level)}</td><td><code>${esc(x.value)}</code></td><td class="sub">${x.sources.map(esc).join('<br>')}</td></tr>`).join('')}
    </tbody></table></div></div>`;
}

const fmtKB = (n) => (n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1024).toFixed(1)} KB`);

// Read-only summary of what was inferred automatically (profile.js), with the evidence.
function profileCard() {
  const p = inferProfile(state.result);
  const basis = (list) => list.length ? `<div class="sub">${list.slice(0, 3).map((b) => esc(pick(b))).join(' ')}</div>` : '';
  const rows = [
    [L('autoCategory'), L(`cat_${p.category}`), p.categoryBasis],
    [L('autoAudience'), L(`audience_${p.audience}`), p.audienceBasis],
  ];
  if (p.consent) rows.push([L('autoConsent'), p.consent.at != null ? L('consentSeen', { s: p.consent.at, service: p.consent.service }) : L('consentNotSeen'), []]);
  return `<div class="card"><h3>${esc(L('autoTitle'))}</h3><dl class="kv">${rows.map(([k, v, b]) => `<dt>${esc(k)}</dt><dd>${esc(v)}${basis(b)}</dd>`).join('')}</dl></div>`;
}

function panelTraffic() {
  const t = state.result.traffic;
  const sdkFor = new Map();
  for (const s of state.result.sdks) for (const e of s.evidence) if (e.type === 'traffic') for (const h of e.samples) sdkFor.set(h, pick(s.name));
  const rows = t.hosts.filter((h) => h.flows > 0 || h.protocols.includes('DNS only'));
  const cAt = inferProfile(state.result).consent?.at ?? null;
  return `<div class="stats">
      <div class="stat"><div class="n">${t.hosts.filter((h) => h.flows > 0).length}</div><div class="l">${esc(L('hostsContacted'))}</div></div>
      <div class="stat ${t.hosts.some((h) => h.cnIndicators.length && h.flows) ? 'cn' : ''}"><div class="n">${t.hosts.filter((h) => h.cnIndicators.length && h.flows).length}</div><div class="l">${esc(L('cnHostsContacted'))}</div></div>
      <div class="stat"><div class="n">${esc(fmtKB(t.upTotal))}</div><div class="l">${esc(L('bytesSent'))}</div></div>
      <div class="stat"><div class="n">${esc(fmtKB(t.downTotal))}</div><div class="l">${esc(L('bytesReceived'))}</div></div>
    </div>
    ${profileCard()}
    <p class="note-line">${esc(L('trafficNote'))}</p>
    <div class="table-wrap"><table>
    <thead><tr><th>${esc(L('colFirstSeen'))}</th><th>${esc(L('colHost'))}</th><th>${esc(L('colOperator'))}</th><th>${esc(L('colProtocol'))}</th><th>${esc(L('colSent'))}</th><th>${esc(L('colReceived'))}</th></tr></thead>
    <tbody>${rows.map((h) => `<tr>
      <td>${h.relFirst != null ? `${h.relFirst}s` : '—'}${cAt != null && h.relFirst != null && h.relFirst < cAt ? ` <span class="pill warn">${esc(L('beforeConsent'))}</span>` : ''}</td>
      <td><code>${esc(h.host)}</code>${SYSTEM_HOSTS.test(h.host) ? ` <span class="pill">${esc(L('systemHost'))}</span>` : ''}<div class="sub">${esc(h.ips.slice(0, 2).join(', '))}</div></td>
      <td>${h.cnIndicators.map((i) => `<span class="pill cn">CN</span> <span class="sub">${esc(i.operator ? `${i.operator}: ` : '')}${esc(cnText(i.text))}</span>`).join('<br>') || ''}${sdkFor.has(h.host) ? `<div class="sub">${esc(sdkFor.get(h.host))}</div>` : ''}${!h.cnIndicators.length && !sdkFor.has(h.host) ? '<span class="muted">—</span>' : ''}</td>
      <td class="sub">${esc(h.protocols.join(', '))}</td>
      <td>${esc(fmtKB(h.up))}</td><td>${esc(fmtKB(h.down))}</td>
    </tr>`).join('')}</tbody></table></div>
    ${t.http.length ? `<h3 style="margin-top:18px">${esc(L('cleartextRequests'))} (${t.http.length})</h3>
      <div class="table-wrap"><table><thead><tr><th>${esc(L('colFirstSeen'))}</th><th>${esc(L('colRequest'))}</th></tr></thead><tbody>
      ${t.http.slice(0, 200).map((q) => `<tr><td>${q.relTs ?? '—'}s</td><td><code>${esc(q.method)} ${esc(q.host)}${esc(q.path)}</code>${q.body ? `<p class="excerpt">${esc(q.body.slice(0, 600))}</p>` : ''}</td></tr>`).join('')}
      </tbody></table></div>` : ''}`;
}

const fmtDate = (iso) => (iso ? new Date(iso).toLocaleString(state.lang === 'zh' ? 'zh-CN' : 'en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '?');

// iPhone App Privacy Report: one row per app, expandable to its domains and data access.
function panelApps() {
  const rep = state.result.privacyReport;
  const apps = rep.apps.filter((a) => a.appDomains || a.access.length);
  const accessPills = (a) => a.access.map((c) => `<span class="pill ${['camera', 'microphone', 'location', 'contacts', 'screenRecording'].includes(c.category) ? 'warn' : ''}">${esc(L(`access_${c.category}`) || c.category)}</span>`).join(' ');
  const domainRow = (d) => `<tr>
      <td><code>${esc(d.domain)}</code>${d.userInitiated && !d.appInitiated ? ` <span class="pill">${esc(L('userOpened'))}</span>` : ''}${d.owner ? `<div class="sub">${esc(d.owner)}</div>` : ''}</td>
      <td>${d.cnIndicators.map((i) => `<span class="pill cn">CN</span> <span class="sub">${esc(i.operator ? `${i.operator}: ` : '')}${esc(cnText(i.text))}</span>`).join('<br>')}${d.sdk ? `<div class="sub">${esc(pick(d.sdk.name))}</div>` : ''}${d.tracker ? ` <span class="pill warn">${esc(L('appleFlagged'))}</span>` : ''}</td>
      <td>${esc(d.hits)}</td><td class="sub">${esc(fmtDate(d.first ? new Date(d.first).toISOString() : null))}<br>${esc(fmtDate(d.last ? new Date(d.last).toISOString() : null))}</td>
    </tr>`;
  const accessRows = (a) => a.access.length ? `<p class="small">${a.access.map((c) => `${esc(L(`access_${c.category}`) || c.category)}: ${esc(L('accessTimes', { n: c.count }))}${c.last ? ` · ${esc(L('lastUsed'))} ${esc(fmtDate(new Date(c.last).toISOString()))}` : ''}`).join('<br>')}</p>` : '';
  const summaryPills = (a) => [
    `<span class="pill">${esc(L('nDomains', { n: a.appDomains }))}</span>`,
    a.cnDomains ? `<span class="pill cn">${esc(L('nCn', { n: a.cnDomains }))}</span>` : '',
    a.trackers ? `<span class="pill warn">${esc(L('nFlagged', { n: a.trackers }))}</span>` : '',
    accessPills(a),
  ].filter(Boolean).join(' ');
  return `<p class="note-line">${esc(L('aprIntro'))}</p>
    ${apps.map((a) => `<details class="card app-card">
      <summary><code>${esc(a.bundleId)}</code><span class="app-pills">${summaryPills(a)}</span></summary>
      ${accessRows(a)}
      <div class="table-wrap"><table><thead><tr><th>${esc(L('colHost'))}</th><th>${esc(L('colOperator'))}</th><th>${esc(L('colHits'))}</th><th>${esc(L('colFirstLast'))}</th></tr></thead>
      <tbody>${a.domains.map(domainRow).join('')}</tbody></table></div>
    </details>`).join('')}`;
}

function panelDetails() {
  const r = state.result;
  let main;
  if (r.platform === 'android') main = panelDetailsAndroid();
  else if (r.ios) main = panelDetailsIos();
  else main = `${encryptedBanner()}<div class="grid-2">${certCard()}<div class="card"><h3>${esc(L('packagesTitle'))}</h3>${listOrDash(r.npmPackages?.slice(0, 300))}</div></div>`;
  return `${main}${secretsCard()}${genericSections(r.details ?? [])}`;
}

function matchCell(m) {
  if (!m) return `<span class="pill warn">${esc(L('notFound'))}</span>`;
  return `<span class="pill ok">${esc(L('found'))}</span><p class="excerpt">${esc(m.text)}</p>`;
}

function policyResultsHtml(p) {
  return `<p class="muted small" style="margin-top:14px">${esc(L('policyLimit'))}</p>
    <h3 style="margin-top:18px">${esc(L('policySdkTitle'))}</h3>
    <div class="table-wrap"><table><thead><tr><th>${esc(L('colSdk'))}</th><th>${esc(L('excerpt'))}</th></tr></thead><tbody>
    ${p.sdkChecks.map((c) => `<tr><td><strong>${esc(pick(c.name))}</strong><div class="sub">${esc(c.vendor)}</div>${c.cnNexus ? '<span class="pill cn">CN</span>' : ''}</td><td>${matchCell(c.match)}</td></tr>`).join('')}
    </tbody></table></div>
    <h3 style="margin-top:18px">${esc(L('policyCatTitle'))}</h3>
    <div class="table-wrap"><table><thead><tr><th>${esc(L('colDataCategory'))}</th><th>${esc(L('excerpt'))}</th></tr></thead><tbody>
    ${p.categoryChecks.map((c) => `<tr><td><strong>${esc(pick(c.label))}</strong><div class="sub">${c.permissions.map(esc).join('<br>')}</div></td><td>${matchCell(c.match)}</td></tr>`).join('')}
    </tbody></table></div>
    <h3 style="margin-top:18px">${esc(L('policyStatementsTitle'))}</h3>
    ${p.statements.length ? p.statements.map((s) => `<p class="excerpt">${esc(s.text)}</p>`).join('') : `<p class="muted">${esc(L('noStatements'))}</p>`}`;
}

function panelPolicy() {
  return `<p class="note-line">${esc(L('policyIntro'))}</p>
    <textarea id="policy-text" class="policy" placeholder="${esc(L('policyPlaceholder'))}">${esc(state.policyText)}</textarea>
    <div class="actions"><button type="button" class="btn btn-primary" id="policy-check">${esc(L('policyCheck'))}</button></div>
    ${state.policy ? policyResultsHtml(state.policy) : ''}`;
}

function limitationsHtml() {
  return `<h3 style="margin-top:22px">${esc(L('limitationsTitle'))}</h3>
    <ul class="list-plain">${LIMITATIONS[state.lang].map((x) => `<li>${esc(x)}</li>`).join('')}</ul>`;
}

const STATUS_PILL = { signals: 'warn', none: 'ok' };

function risksHtml(areas) {
  return areas.map((a) => `<article class="note risk-${a.status}">
      <div class="risk-head"><h3>${esc(pick(a.title))}</h3><span class="pill ${STATUS_PILL[a.status]}">${esc(L(`status_${a.status}`))}</span></div>
      ${a.signals.length ? `<h4>${esc(L('observation'))}</h4><ul class="list-plain">${a.signals.map((s) => `<li>${esc(pick(s))}</li>`).join('')}</ul>` : `<p class="muted small">${esc(L('riskNone'))}</p>`}
      <h4>${esc(L('whyMatters'))}</h4><p>${esc(pick(a.why))}</p>
      <h4>${esc(L('unseenTitle'))}</h4><p>${esc(pick(a.unseen))}</p>
      <p class="cite">${a.refs.map(([label, url]) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a>`).join(' · ')}</p>
    </article>`).join('');
}

function panelRisks() {
  const areas = currentRisks();
  const n = areas.filter((a) => a.status === 'signals').length;
  return `<div class="banner">${esc(L('notesBanner'))}</div>
    ${profileCard()}
    <p class="note-line">${esc(L('riskSummary', { n, total: areas.length }))}</p>
    ${risksHtml(areas)}
    ${limitationsHtml()}`;
}

function consentRecordHtml() {
  const c = state.consent;
  return `<dl class="kv">
      <dt>${esc(L('consentAt'))}</dt><dd>${esc(c.acceptedAt)}</dd>
      ${c.name ? `<dt>${esc(L('nameLabel'))}</dt><dd>${esc(c.name)}</dd>` : ''}
      ${c.role ? `<dt>${esc(L('roleLabel'))}</dt><dd>${esc(c.role)}</dd>` : ''}
      ${c.organization ? `<dt>${esc(L('orgLabel'))}</dt><dd>${esc(c.organization)}</dd>` : ''}
      <dt>${esc(L('termsTitle'))}</dt><dd>v${esc(c.termsVersion)} (${esc(c.termsLocale)}) · SHA-256 <code>${esc(c.termsSha256)}</code></dd>
    </dl>`;
}

function panelExport() {
  return `<p class="note-line">${esc(L('exportIntro'))}</p>
    <div class="actions"><button type="button" class="btn btn-primary" id="dl-json">${esc(L('downloadJson'))}</button>
    <button type="button" class="btn btn-secondary" id="do-print">${esc(L('print'))}</button></div>
    <div class="card"><h3>${esc(L('consentRecord'))}</h3>${consentRecordHtml()}</div>`;
}

function bindPanel() {
  $('show-all-endpoints')?.addEventListener('click', () => { state.showAllEndpoints = true; renderPanel(); });
  $('policy-check')?.addEventListener('click', () => {
    state.policyText = $('policy-text').value;
    state.policy = state.policyText.trim() ? checkPolicy(state.policyText, state.result, state.kb.permissions) : null;
    renderResults();
  });
  $('policy-text')?.addEventListener('input', (e) => { state.policyText = e.target.value; });
  $('dl-json')?.addEventListener('click', downloadJson);
  $('do-print')?.addEventListener('click', printReport);
}

// ---------------------------------------------------------------- export
function reportObject() {
  return {
    generatedBy: `k1d static analyzer ${ANALYZER_VERSION}`,
    generatedAt: new Date().toISOString(),
    disclaimer: { en: t('en', 'disclaimer'), zh: t('zh', 'disclaimer') },
    confirmation: state.consent,
    file: { name: state.file.name, size: state.file.size, sha256: state.fileSha256 },
    recording: state.recFile ? { name: state.recFile.name, size: state.recFile.size, sha256: state.recSha256 } : null,
    appProfile: inferProfile(state.result),
    result: state.result,
    policyCheck: state.policy,
    riskAreas: { status: 'draft_not_expert_reviewed', items: currentRisks() },
    limitations: LIMITATIONS,
  };
}

function downloadJson() {
  const blob = new Blob([JSON.stringify(reportObject(), null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `k1d-${state.result.app.id}-${state.result.app.versionName ?? 'unknown'}.json`.replace(/[^\w.-]+/g, '_');
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

function printReport() {
  const r = state.result;
  const saved = state.showAllEndpoints;
  state.showAllEndpoints = true;
  const sections = [
    ['tab_sdks', r.sdks.length ? sdkTable(r.sdks) : `<p>${esc(L('noSdks'))}</p>`],
    ['tab_permissions', panelPermissions()],
    ['tab_endpoints', panelEndpoints()],
  ];
  if (isIos()) sections.push(['tab_declared', panelDeclared()]);
  sections.push(['tab_details', panelDetails()]);
  if (state.policy) sections.push(['tab_policy', policyResultsHtml(state.policy)]);
  state.showAllEndpoints = saved;
  $('print-report').innerHTML = `
    <h1>${$('r-title').innerHTML}</h1>
    <p>${$('r-meta').innerHTML}</p>
    <p><strong>${esc(L('disclaimer'))}</strong></p>
    <div class="stats">${$('r-stats').innerHTML}</div>
    ${sections.map(([k, html]) => `<section><h2>${esc(L(k))}</h2>${html}</section>`).join('')}
    <section><h2>${esc(L('tab_risks'))}</h2><div class="banner">${esc(L('notesBanner'))}</div>${risksHtml(currentRisks())}${limitationsHtml()}</section>
    <section><h2>${esc(L('consentRecord'))}</h2>${consentRecordHtml()}</section>`;
  window.print();
}

// ---------------------------------------------------------------- boot
async function loadKb() {
  const get = (p) => fetch(p).then((r) => { if (!r.ok) throw new Error(`${p}: ${r.status}`); return r.json(); });
  const [sdks, infra, permissions] = await Promise.all([get('kb/sdks.json'), get('kb/infra.json'), get('kb/permissions.json')]);
  return { sdks, infra, permissions };
}

async function boot() {
  for (const b of document.querySelectorAll('[data-lang]')) {
    b.addEventListener('click', () => { state.lang = b.dataset.lang; storageSet('k1d.lang', state.lang); rerender(); });
  }
  $('r-tabs').addEventListener('click', (e) => {
    const b = e.target.closest('[data-tab]');
    if (!b) return;
    state.tab = b.dataset.tab;
    renderResults();
  });
  initStart();
  initConsent();
  applyStatic();
  show('start');
  try {
    state.kb = await loadKb();
  } catch (err) {
    $('error-text').textContent = L('err_generic', { msg: err.message });
    show('error');
  }
}

boot();
