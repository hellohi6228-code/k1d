// One result from an app file plus a recording of that app running (a .pcap/.pcapng capture, or an
// iPhone App Privacy Report that contains the app). The app file says what is built in; the
// recording says what actually connected. Each SDK and endpoint is marked seenAtRuntime when the
// recording shows it, so the risk areas can say which built-in trackers were confirmed.
import { SYSTEM_HOSTS } from './profile.js';

export const RUNTIME_PLATFORMS = new Set(['traffic', 'iphone-report']);

const base = (h) => h.split('.').slice(-2).join('.');

export function combineResults(app, rec, { recordingName = null } = {}) {
  const out = { ...app, limits: [...(app.limits ?? [])] };
  let hosts; // hosts the app contacted during the recording
  let reportEntry = null;
  if (rec.privacyReport) {
    reportEntry = rec.privacyReport.apps.find((a) => a.bundleId === app.app?.id) ?? null;
    hosts = new Set((reportEntry?.domains ?? []).filter((d) => d.appInitiated).map((d) => d.domain));
    if (!reportEntry) out.limits.push({ en: `The App Privacy Report has no activity for ${app.app?.id ?? 'this app'}; nothing from it was added.`, zh: `App 隐私报告中没有 ${app.app?.id ?? '该应用'} 的活动，未加入任何内容。` });
  } else {
    out.traffic = rec.traffic;
    hosts = new Set(rec.traffic.hosts.filter((h) => h.flows > 0 && !SYSTEM_HOSTS.test(h.host)).map((h) => h.host));
  }

  // SDKs: add runtime evidence to built-in SDKs; add SDKs that only showed up at runtime.
  const byId = new Map(app.sdks.map((s) => [s.id, { ...s, evidence: [...s.evidence], seenAtRuntime: false }]));
  for (const s of rec.sdks) {
    const ev = s.evidence.filter((e) => e.type === 'traffic').map((e) => ({ ...e, samples: e.samples.filter((h) => hosts.has(h)) })).filter((e) => e.samples.length);
    if (!ev.length) continue;
    const x = byId.get(s.id);
    if (x) { x.evidence.push(...ev); x.seenAtRuntime = true; x.confidence = 'high'; } else byId.set(s.id, { ...s, evidence: ev, seenAtRuntime: true, runtimeOnly: true });
  }
  out.sdks = [...byId.values()];

  // Endpoints: same idea.
  const ep = new Map(app.endpoints.map((e) => [e.host, { ...e, seenAtRuntime: false }]));
  for (const e of rec.endpoints) {
    if (!hosts.has(e.host)) continue;
    const x = ep.get(e.host);
    if (x) { x.seenAtRuntime = true; if (e.traffic) x.traffic = e.traffic; } else ep.set(e.host, { ...e, seenAtRuntime: true, runtimeOnly: true });
  }
  out.endpoints = [...ep.values()].sort((a, b) => b.cnIndicators.length - a.cnIndicators.length || Number(b.seenAtRuntime) - Number(a.seenAtRuntime) || a.host.localeCompare(b.host));

  // Credentials seen in cleartext HTTP.
  const secrets = new Map((app.secrets ?? []).map((s) => [`${s.type}:${s.value}`, s]));
  for (const s of rec.secrets ?? []) if (!secrets.has(`${s.type}:${s.value}`)) secrets.set(`${s.type}:${s.value}`, s);
  out.secrets = [...secrets.values()];
  out.limits.push(...(rec.limits ?? []));

  // Does the recording look like this app? Count contacted hosts the app file also references
  // (same registrable domain) or that belong to SDKs built into the app.
  const appDomains = new Set(app.endpoints.map((e) => base(e.host)));
  const builtInSdkHosts = new Set(out.sdks.filter((s) => !s.runtimeOnly && s.seenAtRuntime).flatMap((s) => s.evidence.filter((e) => e.type === 'traffic').flatMap((e) => e.samples)));
  const matched = [...hosts].filter((h) => appDomains.has(base(h)) || builtInSdkHosts.has(h));
  out.runtime = {
    kind: rec.platform, container: rec.container, recordingName,
    hostsContacted: hosts.size, hostsMatchingApp: matched.length,
    report: reportEntry,
  };
  if (hosts.size >= 3 && matched.length === 0) {
    out.limits.unshift({ en: 'None of the servers in the recording are referenced by the app file or its SDKs. The recording may be of a different app.', zh: '录制中的服务器均未被该应用文件或其 SDK 引用，录制的可能是其他应用。' });
  }
  return out;
}
