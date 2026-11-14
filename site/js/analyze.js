// Orchestrates static analysis of app packages on every platform k1d supports:
// Android (APK, AAB, XAPK/APKS/APKM), iOS (IPA), macOS (.app zip, .pkg, Mach-O), Windows
// (EXE/DLL, MSI, MSIX/APPX), Linux (ELF, .deb, .rpm), HarmonyOS (.hap/.app), browser
// extensions (.crx/.xpi/.zip), WeChat mini-programs (.wxapkg), Electron (app.asar).
import { openZip, bytesSource } from './zip.js';
import { parseAXML, parseProtoXml, summarizeManifest, parseArscStrings } from './axml.js';
import { parseDex } from './dex.js';
import { readSigningBlockCert, certFromPkcs7, describeCert, sha256Hex, sha1Hex } from './cert.js';
import { collectApple, findAppleBundle } from './ios.js';
import { isMachO, parseMachO, machoStrings, parseCodeSignature } from './macho.js';
import { signerCertFromPkcs7 } from './cert.js';
import { isPE } from './pe.js';
import { isCFB } from './cfb.js';
import { isXar, collectPkg } from './pkg.js';
import { isPcap, analyzePcap, hostsFromFlows } from './pcap.js';
import {
  collectPE, collectMsix, collectMsi, collectELF, collectDeb, collectRpm, collectAsar, collectHarmony,
  collectExtension, crxZipOffset, isWxapkg, collectWxapkg, collectGeneric, collectNestedZip, offsetSource, scanBinary,
} from './formats.js';

export const ANALYZER_VERSION = '0.3.0';

// Hard-coded credentials. Values are masked before they leave this module.
const SECRET_PREFILTER = /AKIA|ASIA|AIza|LTAI|AKID|-----BEGIN|xox[baprs]-|gh[pousr]_|sk-|sk_live_|APA91b/;
const SECRET_RES = [
  { type: 'aws_access_key', label: 'AWS access key ID', level: 'high', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { type: 'alibaba_access_key', label: 'Alibaba Cloud AccessKey ID', level: 'high', re: /\bLTAI[0-9A-Za-z]{12,20}\b/g },
  { type: 'tencent_secret_id', label: 'Tencent Cloud SecretId', level: 'high', re: /\bAKID[0-9A-Za-z]{32}\b/g },
  { type: 'private_key', label: 'Private key (PEM)', level: 'high', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g },
  { type: 'slack_token', label: 'Slack token', level: 'high', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { type: 'github_token', label: 'GitHub token', level: 'high', re: /\bgh[pousr]_[0-9A-Za-z]{36}\b/g },
  { type: 'openai_key', label: 'OpenAI-style API secret key', level: 'high', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b/g },
  { type: 'stripe_live_key', label: 'Stripe live secret key', level: 'high', re: /\bsk_live_[0-9a-zA-Z]{24,}\b/g },
  { type: 'fcm_server_key', label: 'Firebase Cloud Messaging server key', level: 'high', re: /\bAAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{100,}/g },
  { type: 'google_api_key', label: 'Google API key (often meant to be embedded; check its restrictions)', level: 'low', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
];
const mask = (v) => (v.startsWith('-----') ? v : `${v.slice(0, 6)}…${v.slice(-2)} (${v.length} chars)`);

// No leading \b: in binary formats (protobuf, native code) a length byte that happens to be a
// letter often sits directly before "https".
const URL_RE = /(?:https?|wss?):\/\/([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(?::\d{1,5})?(?:\/[^\s"'<>\\^`{|}\u0000-\u001f]*)?/g;
const TEXT_FILE_RE = /\.(json|xml|txt|properties|js|html?|cfg|ini|conf|ya?ml|plist|csv)$/i;
const CONFIG_KEY_RE = /^[A-Z][A-Z0-9_.]*(APPKEY|APP_KEY|APPID|APP_ID|API_KEY|APPSECRET|APP_SECRET|CHANNEL)[A-Z0-9_]*$/;
const MAX_TEXT_FILE = 4 * 1024 * 1024;
const MAX_TEXT_FILES = 400;
const MAX_NATIVE_SCAN = 48 * 1024 * 1024;

function emptyFacts() {
  return {
    platform: null,
    app: null,
    manifest: null, // android
    ios: null,
    classes: new Set(), // android (Java/Kotlin)
    objcClasses: new Set(), // iOS
    frameworkNames: new Set(),
    bundleNames: new Set(),
    frameworkBundleIds: [],
    urls: new Map(), // url -> Set(source)
    configKeys: new Set(),
    nativeLibs: new Map(), // lib -> Set(abi)
    dexFiles: [],
    cert: null,
    signatureSchemes: [],
    fileCount: 0,
    splits: [],
    errors: [],
    // cross-platform
    fileNames: new Set(), // basenames of libraries/executables/files (for "files" signatures)
    npm: new Set(), // npm / ohpm package names
    permissionList: [], // platforms other than Android/iOS fill this directly
    details: [], // generic { title, rows, lists } sections for the UI
    limits: [], // format-specific limits { en, zh }
    flags: {},
    electron: false,
    secrets: new Map(), // masked -> { type, label, level, sources:Set }
  };
}

function scanTextTo(facts) {
  return (text, source) => {
    if (!text || text.length < 16 || !SECRET_PREFILTER.test(text)) return;
    for (const s of SECRET_RES) {
      s.re.lastIndex = 0;
      let m;
      while ((m = s.re.exec(text)) !== null) {
        const key = `${s.type}:${mask(m[0])}`;
        if (!facts.secrets.has(key)) facts.secrets.set(key, { type: s.type, label: s.label, level: s.level, value: mask(m[0]), sources: new Set() });
        if (facts.secrets.get(key).sources.size < 6) facts.secrets.get(key).sources.add(source);
        if (facts.secrets.size > 200) return;
      }
    }
  };
}

function addUrlsTo(facts) {
  return (text, source) => {
    URL_RE.lastIndex = 0;
    let m;
    while ((m = URL_RE.exec(text)) !== null) {
      let url = m[0].replace(/[.,;:)\]]+$/, '');
      if (url.length > 300) url = url.slice(0, 300);
      if (!facts.urls.has(url)) facts.urls.set(url, new Set());
      facts.urls.get(url).add(source);
    }
  };
}

function latin1(bytes) {
  let out = '';
  const CH = 0x8000;
  for (let i = 0; i < bytes.length; i += CH) out += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
  return out;
}

// ---------------------------------------------------------------- Android
// layout: where a module keeps its manifest, dex, libs, assets and resource table.
function apkLayout() {
  return { manifest: 'AndroidManifest.xml', proto: false, dex: /^classes\d*\.dex$/, lib: /^lib\/([^/]+)\/([^/]+\.so)$/, assets: ['assets/', 'res/raw/'], arsc: 'resources.arsc' };
}
function aabLayout(module) {
  const m = module.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return {
    manifest: `${module}/manifest/AndroidManifest.xml`, proto: true,
    dex: new RegExp(`^${m}/dex/classes\\d*\\.dex$`), lib: new RegExp(`^${m}/lib/([^/]+)/([^/]+\\.so)$`),
    assets: [`${module}/assets/`, `${module}/res/raw/`, `${module}/root/`], arsc: `${module}/resources.pb`,
  };
}

async function collectAndroid(zip, facts, label, layout, progress) {
  const addUrls = addUrlsTo(facts);
  const scanText = scanTextTo(facts);
  facts.platform = 'android';
  facts.fileCount += zip.entries.length;
  const prefix = label ? `${label}!` : '';

  const manifestBytes = await zip.readEntry(layout.manifest);
  if (manifestBytes) {
    try {
      const tree = layout.proto ? parseProtoXml(manifestBytes) : parseAXML(manifestBytes);
      const m = summarizeManifest(tree);
      if (!facts.manifest) facts.manifest = m;
      else facts.splits.push(label || m.package);
      for (const c of m.components) if (c.name) facts.classes.add(c.name);
    } catch (e) {
      facts.errors.push(`${prefix}${layout.manifest}: ${e.message}`);
    }
  }

  const dexEntries = zip.entries.filter((e) => layout.dex.test(e.name));
  for (let i = 0; i < dexEntries.length; i++) {
    const e = dexEntries[i];
    progress({ step: 'dex', detail: `${prefix}${e.name}`, i: i + 1, n: dexEntries.length });
    try {
      const dex = parseDex(await zip.readEntry(e));
      facts.dexFiles.push({ name: prefix + e.name, classes: dex.classes.length, strings: dex.strings.length, version: dex.version });
      for (const c of dex.classes) facts.classes.add(c);
      for (const s of dex.strings) {
        if (s.length > 7 && s.length < 2048 && s.includes('://')) addUrls(s, prefix + e.name);
        else if (s.length >= 5 && s.length <= 64 && CONFIG_KEY_RE.test(s)) facts.configKeys.add(s);
        if (s.length >= 16 && s.length < 8192) scanText(s, prefix + e.name);
        if (s.length < 80 && /^(?:Ldalvik\/system\/(?:Dex|InMemoryDex|Path)ClassLoader;|dalvik\.system\.(?:Dex|InMemoryDex)ClassLoader)$/.test(s)) facts.flags.dynamicCodeLoading = true;
      }
    } catch (err) {
      facts.errors.push(`${prefix}${e.name}: ${err.message}`);
    }
  }

  progress({ step: 'resources' });
  try {
    const arsc = await zip.readEntry(layout.arsc);
    if (arsc) {
      if (layout.proto) { const t = latin1(arsc); addUrls(t, prefix + layout.arsc); scanText(t, prefix + layout.arsc); }
      else for (const s of parseArscStrings(arsc)) { if (s.includes('://')) addUrls(s, prefix + layout.arsc); scanText(s, prefix + layout.arsc); }
    }
  } catch (err) {
    facts.errors.push(`${prefix}${layout.arsc}: ${err.message}`);
  }

  const td = new TextDecoder('utf-8');
  const textEntries = zip.entries
    .filter((e) => layout.assets.some((a) => e.name.startsWith(a)) && TEXT_FILE_RE.test(e.name) && e.size <= MAX_TEXT_FILE)
    .slice(0, MAX_TEXT_FILES);
  for (const e of textEntries) {
    try {
      const text = td.decode(await zip.readEntry(e));
      if (text.includes('://')) addUrls(text, prefix + e.name);
      scanText(text, prefix + e.name);
    } catch { /* ignore */ }
  }

  const libEntries = [];
  for (const e of zip.entries) {
    const m = layout.lib.exec(e.name);
    if (!m) continue;
    libEntries.push({ e, abi: m[1], lib: m[2] });
    if (!facts.nativeLibs.has(m[2])) facts.nativeLibs.set(m[2], new Set());
    facts.nativeLibs.get(m[2]).add(m[1]);
  }
  const seen = new Set();
  libEntries.sort((a, b) => (b.abi === 'arm64-v8a' ? 1 : 0) - (a.abi === 'arm64-v8a' ? 1 : 0));
  for (const { e, lib } of libEntries) {
    if (seen.has(lib) || e.size > MAX_NATIVE_SCAN) continue;
    seen.add(lib);
    progress({ step: 'native', detail: prefix + e.name });
    try {
      const text = latin1(await zip.readEntry(e));
      if (text.includes('://')) addUrls(text, prefix + e.name);
      scanText(text, prefix + e.name);
    } catch { /* ignore */ }
  }
  for (const lib of facts.nativeLibs.keys()) facts.fileNames.add(lib);

  if (!facts.cert) {
    try {
      const v2 = await readSigningBlockCert(zip);
      if (v2) {
        facts.cert = { scheme: v2.scheme, der: v2.der };
        facts.signatureSchemes.push(...v2.schemes);
      }
    } catch (err) {
      facts.errors.push(`${prefix}signing block: ${err.message}`);
    }
    const v1 = zip.entries.find((e) => /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(e.name));
    if (v1) {
      facts.signatureSchemes.unshift('v1');
      if (!facts.cert) {
        try {
          const der = certFromPkcs7(await zip.readEntry(v1));
          if (der) facts.cert = { scheme: 'v1', der };
        } catch (err) {
          facts.errors.push(`${prefix}${v1.name}: ${err.message}`);
        }
      }
    }
  }
}

// ---------------------------------------------------------------- detection
function classMatches(cls, prefix) {
  return cls === prefix || cls.startsWith(prefix + '.') || cls.startsWith(prefix + '$');
}
function hostOf(url) {
  const m = /^[a-z]+:\/\/([^/:?#]+)/i.exec(url);
  return m ? m[1].toLowerCase() : null;
}
// Binary scans produce junk such as "ocsp.digicert.com0" (DER bytes after the host) or
// "www.css". Accept 2-letter country TLDs and a list of common generic TLDs; trim trailing junk.
const GTLDS = new Set(('com net org edu gov mil int info biz name pro app dev page io ai gg me tv cc ly so sh to co xyz top vip fun ink site online club live games game '
  + 'cloud store shop tech link work world life plus space website press group studio network zone video news wiki mobi asia moe one icu art '
  + 'blog chat email global media social systems team tools agency digital design center company services solutions software today '
  + 'example test local internal').split(' '));
function normalizeHost(host) {
  const labels = host.split('.');
  if (labels.length < 2 || labels.some((l) => !l || l.length > 63)) return null;
  if (/^\d+$/.test(labels[labels.length - 1])) return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ? host : null;
  let tld = labels[labels.length - 1];
  if (!(GTLDS.has(tld) || /^[a-z]{2}$/.test(tld))) {
    const cut = [...GTLDS].filter((g) => tld.startsWith(g) && /^[^a-z]/.test(tld.slice(g.length))).sort((a, b) => b.length - a.length)[0]
      ?? (/^[a-z]{2}[^a-z]/.test(tld) ? tld.slice(0, 2) : null);
    if (!cut) return null;
    tld = cut;
    labels[labels.length - 1] = tld;
  }
  if (labels.length === 2 && labels[0].length < 2) return null;
  return labels.join('.');
}
function hostMatches(host, suffix) {
  return host === suffix || host.endsWith('.' + suffix);
}
function bundleMatches(bundle, fw) {
  return bundle === fw || bundle.startsWith(fw + '_') || bundle === fw + 'Resources' || bundle === fw + 'Bundle';
}

function detectSdks(facts, kb, hosts) {
  const classes = [...facts.classes];
  const metaNames = new Set((facts.manifest?.metaData ?? []).map((m) => m.name));
  const ios = facts.ios;
  const plistKeys = new Set(ios?.plistKeys ?? []);
  const detections = [];
  for (const sdk of kb.sdks) {
    const evidence = [];
    let codeHits = 0;
    if (facts.platform === 'android') {
      for (const prefix of sdk.code ?? []) {
        const hits = classes.filter((c) => classMatches(c, prefix) && !(sdk.exclude ?? []).some((x) => classMatches(c, x)));
        if (hits.length) {
          codeHits += hits.length;
          evidence.push({ type: 'code', signature: prefix, count: hits.length, samples: hits.slice(0, 5) });
        }
      }
      for (const lib of sdk.native ?? []) {
        if (facts.nativeLibs.has(lib)) evidence.push({ type: 'native', signature: lib, samples: [...facts.nativeLibs.get(lib)].map((abi) => `lib/${abi}/${lib}`) });
      }
      for (const key of sdk.manifest ?? []) {
        if (metaNames.has(key)) evidence.push({ type: 'manifest', signature: key, samples: [`<meta-data android:name="${key}">`] });
        else if (facts.configKeys.has(key)) evidence.push({ type: 'config_key', signature: key, samples: [key] });
      }
    } else if (ios && sdk.ios) {
      const sig = sdk.ios;
      for (const fw of sig.frameworks ?? []) {
        const where = [];
        if (facts.frameworkNames.has(fw)) where.push(`Frameworks/${fw}.framework`);
        for (const b of facts.bundleNames) if (bundleMatches(b, fw)) where.push(`${b}.bundle`);
        if (where.length) evidence.push({ type: 'framework', signature: fw, samples: where.slice(0, 4) });
      }
      for (const key of sig.plist_keys ?? []) if (plistKeys.has(key)) evidence.push({ type: 'plist_key', signature: key, samples: [`Info.plist → ${key}`] });
      for (const re of sig.url_schemes ?? []) {
        const rx = new RegExp(re);
        const hit = ios.urlSchemes.filter((s) => rx.test(s));
        if (hit.length) evidence.push({ type: 'url_scheme', signature: re, samples: hit.slice(0, 3) });
      }
      const qs = (sig.query_schemes ?? []).filter((s) => ios.queriesSchemes.includes(s));
      if (qs.length) evidence.push({ type: 'query_scheme', signature: qs.join(', '), samples: qs });
      for (const cls of sig.classes ?? []) {
        if (facts.objcClasses.has(cls)) { codeHits += 1; evidence.push({ type: 'ios_class', signature: cls, samples: [cls] }); }
      }
      for (const fw of sig.system_frameworks ?? []) if (ios.linkedSystem.includes(fw)) evidence.push({ type: 'framework', signature: fw, samples: [`links ${fw}.framework`] });
      for (const ent of sig.entitlements ?? []) if ((ios.entitlementKeys ?? []).includes(ent)) evidence.push({ type: 'entitlement', signature: ent, samples: [ent] });
    }
    // cross-platform: library/executable file names and npm / ohpm packages
    if (facts.platform !== 'android') {
      for (const lib of sdk.native ?? []) if (facts.fileNamesLower.has(lib.toLowerCase())) evidence.push({ type: 'native', signature: lib, samples: [lib] });
    }
    for (const f of sdk.files ?? []) if (facts.fileNamesLower.has(f.toLowerCase())) evidence.push({ type: 'file', signature: f, samples: [f] });
    for (const p of [...(sdk.npm ?? []), ...(sdk.harmony ?? [])]) {
      const hit = [...facts.npm].filter((n) => n === p || (p.endsWith('/') && n.startsWith(p)));
      if (hit.length) evidence.push({ type: 'package', signature: p, samples: hit.slice(0, 3) });
    }
    for (const suffix of sdk.domains ?? []) {
      const matched = hosts.filter((h) => hostMatches(h, suffix));
      // In a network capture the host was actually contacted, which is stronger than a string in the file.
      if (matched.length) evidence.push({ type: facts.platform === 'traffic' ? 'traffic' : 'domain', signature: suffix, samples: facts.platform === 'traffic' ? matched : matched.slice(0, 5) });
    }
    if (!evidence.length) continue;
    const kinds = new Set(evidence.map((e) => e.type));
    const strong = kinds.has('framework') || kinds.has('file') || kinds.has('package') || kinds.has('traffic') || codeHits >= 3;
    const medium = ['code', 'ios_class', 'native', 'manifest', 'plist_key', 'url_scheme', 'config_key', 'entitlement'].some((k) => kinds.has(k));
    let confidence = 'low';
    if (strong || (medium && kinds.size >= 2)) confidence = 'high';
    else if (medium) confidence = 'medium';
    // A model-API endpoint is the integration itself (apps call these hosts directly).
    else if (sdk.category === 'ai' && kinds.has('domain')) confidence = 'medium';
    detections.push({
      id: sdk.id, name: sdk.name, vendor: sdk.vendor, category: sdk.category,
      cnNexus: sdk.cn_nexus ?? null, aliases: sdk.aliases ?? [], confidence, activity: 'code_present', evidence,
    });
  }
  const order = { high: 0, medium: 1, low: 2 };
  detections.sort((a, b) => (b.cnNexus ? 1 : 0) - (a.cnNexus ? 1 : 0) || order[a.confidence] - order[b.confidence] || a.name.en.localeCompare(b.name.en));
  return detections;
}

function classifyEndpoints(facts, infra, sdkKb) {
  const ignore = new Set(infra.ignore_hosts);
  const sdkDomains = [];
  for (const s of sdkKb.sdks) for (const d of s.domains ?? []) sdkDomains.push({ suffix: d, sdk: s });
  const byHost = new Map();
  for (const [url, sources] of facts.urls) {
    const host = normalizeHost(hostOf(url) ?? '');
    if (!host || ignore.has(host)) continue;
    if (!byHost.has(host)) byHost.set(host, { host, urls: new Set(), sources: new Set() });
    const h = byHost.get(host);
    if (h.urls.size < 10) h.urls.add(url);
    for (const s of sources) h.sources.add(s);
  }
  const out = [];
  for (const h of byHost.values()) {
    const op = infra.operators.find((o) => hostMatches(h.host, o.suffix));
    const indicators = [];
    if (op) indicators.push({ type: 'operator', operator: op.operator, text: op.cn_nexus });
    const sdkDomain = sdkDomains.find((d) => hostMatches(h.host, d.suffix));
    if (sdkDomain?.sdk.cn_nexus && !op) {
      indicators.push({ type: 'sdk_domain', operator: sdkDomain.sdk.vendor, text: `Domain listed for ${sdkDomain.sdk.name.en}; ${sdkDomain.sdk.cn_nexus}` });
    }
    if (/\.cn$/.test(h.host)) indicators.push({ type: 'cctld', text: '.cn country-code domain' });
    out.push({
      host: h.host,
      isIp: /^\d{1,3}(\.\d{1,3}){3}$/.test(h.host),
      cleartext: [...h.urls].some((u) => u.startsWith('http://') || u.startsWith('ws://')),
      operator: op?.operator ?? sdkDomain?.sdk.vendor ?? null,
      cnIndicators: indicators,
      urls: [...h.urls],
      sources: [...h.sources].slice(0, 8),
    });
  }
  out.sort((a, b) => b.cnIndicators.length - a.cnIndicators.length || a.host.localeCompare(b.host));
  return out;
}

function buildPermissions(facts, permKb) {
  if (facts.platform === 'android') {
    return facts.manifest.permissions.map((p) => ({ name: p, kind: 'permission', ...(permKb.permissions[p] ?? { category: null, level: null }) }));
  }
  if (!facts.ios) return facts.permissionList;
  const ios = facts.ios;
  const out = ios.usage.map((u) => ({ name: u.key, kind: 'usage', description: u.text, ...(permKb.ios_usage[u.key] ?? { category: 'other', level: 'low' }) }));
  for (const fw of ios.linkedSystem) {
    const def = permKb.ios_frameworks[fw];
    if (def) out.push({ name: `${fw}.framework`, kind: 'framework', description: def.note, category: def.category, level: def.level });
  }
  return out;
}

// ---------------------------------------------------------------- entry point
const MAX_WHOLE_FILE = 1024 * 1024 * 1024;

async function collectMachOFile(source, facts, ctx) {
  facts.platform = 'macos';
  const bytes = await source.read(0, source.size);
  const m = parseMachO(bytes);
  const { cstrings, classNames } = machoStrings(m);
  for (const c of classNames) facts.objcClasses.add(c);
  for (const s of cstrings) { if (s.includes('://')) ctx.addUrls(s, 'executable'); ctx.scanText(s, 'executable'); }
  if (!cstrings.length) scanBinary(bytes, 'executable', ctx);
  const cs = parseCodeSignature(m);
  if (cs?.cms) { const der = signerCertFromPkcs7(cs.cms); if (der) { facts.cert = { scheme: 'macos-codesign', der }; facts.signatureSchemes.push('Mach-O code signature (CMS)'); } }
  if (!cs) facts.flags.unsigned = true;
  for (const d of m.dylibs) facts.fileNames.add(d.split('/').pop());
  facts.app = { id: cs?.identifier ?? null, name: cs?.identifier ?? null, versionName: null, versionCode: null, minSdk: m.minOS, targetSdk: m.sdk };
  facts.details.push({ title: { en: 'Mach-O executable', zh: 'Mach-O 可执行文件' }, rows: [['Architecture', m.arch], ['Universal slices', String(m.fatArchs?.length ?? 1)], ['Team ID', cs?.teamId ?? '—'], ['Encrypted', m.encrypted ? 'yes' : 'no']], lists: [{ title: 'Linked libraries', items: m.dylibs }, { title: 'Entitlements', items: Object.keys(cs?.entitlements ?? {}) }] });
}

async function collectZip(zip, facts, ctx) {
  const has = (n) => zip.byName.has(n);
  const names = zip.entries.map((e) => e.name);
  if (has('AndroidManifest.xml')) { await collectAndroid(zip, facts, '', apkLayout(), ctx.progress); return 'apk'; }
  const apple = findAppleBundle(zip);
  if (apple) { await collectApple(zip, facts, { ...ctx, bundle: apple, collectAsar: (b, l) => collectAsar(b, facts, ctx, l) }); return apple.kind === 'ios' ? 'ipa' : 'app (zip)'; }
  if (has('base/manifest/AndroidManifest.xml')) {
    const modules = names.map((n) => /^([^/]+)\/manifest\/AndroidManifest\.xml$/.exec(n)?.[1]).filter(Boolean);
    modules.sort((a, b) => (a === 'base' ? -1 : b === 'base' ? 1 : a.localeCompare(b)));
    for (const mod of modules) await collectAndroid(zip, facts, mod === 'base' ? '' : mod, aabLayout(mod), ctx.progress);
    return 'aab';
  }
  if (has('AppxManifest.xml') || has('AppxMetadata/AppxBundleManifest.xml')) { await collectMsix(zip, facts, ctx); return has('AppxManifest.xml') ? 'msix' : 'msixbundle'; }
  if (has('module.json') || (has('config.json') && names.some((n) => /\.abc$/.test(n))) || (has('pack.info') && names.some((n) => /\.(hap|hsp)$/.test(n)))) { await collectHarmony(zip, facts, ctx); return has('pack.info') ? 'app (HarmonyOS)' : 'hap'; }
  if (has('manifest.json')) {
    try {
      const mf = JSON.parse(new TextDecoder().decode(await zip.readEntry('manifest.json')).replace(/^﻿/, ''));
      if (mf.manifest_version) { await collectExtension(zip, facts, ctx, names.some((n) => n.startsWith('META-INF/mozilla')) ? 'xpi' : 'zip'); return 'extension'; }
    } catch { /* not an extension manifest */ }
  }
  const apks = zip.entries.filter((e) => /\.(apk)$/i.test(e.name));
  if (apks.length) {
    const rank = (n) => (/(^|\/)base(-master)?\.apk$/i.test(n) ? 0 : /(^|\/)(config\.|split_)/i.test(n) ? 2 : 1);
    apks.sort((a, b) => rank(a.name) - rank(b.name));
    for (const e of apks) {
      ctx.progress({ step: 'split', detail: e.name });
      const inner = await openZip(bytesSource(await zip.readEntry(e)));
      await collectAndroid(inner, facts, e.name, apkLayout(), ctx.progress);
    }
    return 'bundle';
  }
  if (names.some((n) => /^Payload\//.test(n))) throw new Error('NO_IPA_APP');
  facts.platform = 'archive';
  facts.app = { id: null, name: null, versionName: null, versionCode: null, minSdk: null, targetSdk: null };
  await collectNestedZip(zip, facts, ctx, 'archive');
  facts.limits.push({ en: 'This ZIP did not contain a recognized app package; its files were inventoried and text/executable files scanned.', zh: '该 ZIP 中没有可识别的应用包；已列出其文件并扫描文本和可执行文件。' });
  return 'zip';
}

export async function analyzeSource(source, kb, { onProgress } = {}) {
  const progress = onProgress ?? (() => {});
  const started = Date.now();
  progress({ step: 'open' });
  const facts = emptyFacts();
  const ctx = { addUrls: addUrlsTo(facts), scanText: scanTextTo(facts), progress };
  if (source.size < 4) throw new Error('NOT_A_ZIP');
  const head = await source.read(0, Math.min(64, source.size));
  const ascii = new TextDecoder('latin1').decode(head);
  const tail = source.size > 512 ? new TextDecoder('latin1').decode(await source.read(source.size - 512, 4)) : '';
  let container;
  const big = source.size > MAX_WHOLE_FILE;

  if (isPcap(head) && !big) {
    const t = analyzePcap(await source.read(0, source.size));
    facts.platform = 'traffic';
    facts.app = { id: null, name: null, versionName: null, versionCode: null, minSdk: null, targetSdk: null };
    const hostsT = hostsFromFlows(t.flows, t.dns);
    for (const h of hostsT) if (/[a-z]/i.test(h.host)) ctx.addUrls(`https://${h.host}/`, 'network capture');
    for (const f of t.flows) for (const r of f.http) {
      ctx.addUrls(`http://${r.host || f.ip}${r.path}`, 'cleartext HTTP');
      ctx.scanText(`${r.path}\n${r.body}`, `HTTP ${r.method} ${r.host}`);
    }
    facts.traffic = { ...t, hosts: hostsT };
    container = new DataView(head.buffer, head.byteOffset, 4).getUint32(0, true) === 0x0a0d0d0a ? 'pcapng' : 'pcap';
  } else if (isPE(head) && !big) { await collectPE(source, facts, ctx); container = 'exe'; }
  else if (isCFB(head) && !big) { await collectMsi(source, facts, ctx); container = 'msi'; }
  else if (ascii.startsWith('\x7fELF') && !big) { await collectELF(source, facts, ctx, 'executable'); facts.app.id = null; facts.app.name = null; container = 'elf'; }
  else if (ascii.startsWith('!<arch>\n') && !big) { await collectDeb(source, facts, ctx); container = 'deb'; }
  else if (head[0] === 0xed && head[1] === 0xab && head[2] === 0xee && head[3] === 0xdb) { await collectRpm(source, facts, ctx); container = 'rpm'; }
  else if (isXar(head)) { await collectPkg(source, facts, ctx); container = 'pkg'; }
  else if (ascii.startsWith('Cr24')) {
    const off = crxZipOffset(head);
    const zip = await openZip(offsetSource(source, off, source.size - off));
    await collectExtension(zip, facts, ctx, 'crx');
    container = 'crx';
  } else if (isWxapkg(head)) { await collectWxapkg(source, facts, ctx); container = 'wxapkg'; }
  else if (isMachO(head) && !big) { await collectMachOFile(source, facts, ctx); container = 'mach-o'; }
  else if (head[0] === 4 && head[1] === 0 && head[2] === 0 && head[3] === 0 && ascii.slice(16).startsWith('{"files"')) {
    await collectAsar(await source.read(0, source.size), facts, ctx);
    facts.platform = 'electron';
    container = 'asar';
  } else if (tail === 'koly') {
    await collectGeneric(source, facts, ctx, { en: 'This is a macOS disk image (.dmg). Its contents are compressed in a format k1d does not unpack in the browser. Open the DMG, zip the .app inside, and analyze that zip.', zh: '这是 macOS 磁盘映像（.dmg），其内容采用 k1d 无法在浏览器中解压的压缩格式。请打开 DMG，将其中的 .app 压缩为 zip 后再分析。' });
    facts.platform = 'macos';
    container = 'dmg';
  } else {
    let zip = null;
    try { zip = await openZip(source); } catch { /* not a zip */ }
    if (zip) container = await collectZip(zip, facts, ctx);
    else {
      await collectGeneric(source, facts, ctx, { en: 'k1d did not recognize this file format. Only a generic scan for URLs and credentials was done.', zh: 'k1d 未能识别此文件格式，仅对 URL 和凭据进行了通用扫描。' });
      container = 'unknown';
    }
  }

  if (facts.platform === 'android' && !facts.manifest) throw new Error('NO_MANIFEST');
  if (facts.platform === 'ios' && !facts.ios?.bundleId) throw new Error('NO_IPA_APP');
  facts.fileNamesLower = new Set([...facts.fileNames].map((n) => n.toLowerCase()));

  progress({ step: 'detect' });
  const endpoints = classifyEndpoints(facts, kb.infra, kb.sdks);
  let traffic = null;
  if (facts.traffic) {
    const t = facts.traffic;
    const ep = new Map(endpoints.map((e) => [e.host, e]));
    const hostsOut = t.hosts.map((h) => {
      const e = ep.get(h.host);
      return { ...h, relFirst: t.start ? +(h.first - t.start).toFixed(1) : null, cnIndicators: e?.cnIndicators ?? [], operator: e?.operator ?? null };
    });
    for (const e of endpoints) {
      const h = hostsOut.find((x) => x.host === e.host);
      if (h) e.traffic = { up: h.up, down: h.down, relFirst: h.relFirst, protocols: h.protocols };
    }
    traffic = {
      packets: t.packets, parsedPackets: t.parsedPackets, links: t.links, start: t.start, end: t.end,
      duration: t.start && t.end ? +(t.end - t.start).toFixed(1) : null, device: t.device,
      flows: t.flows.length, hosts: hostsOut, dnsQueries: t.dns.length,
      http: t.flows.flatMap((f) => f.http.map((r) => ({ ...r, ip: f.ip, relTs: t.start ? +(r.ts - t.start).toFixed(1) : null }))),
      upTotal: t.flows.reduce((n, f) => n + f.up, 0), downTotal: t.flows.reduce((n, f) => n + f.down, 0),
    };
    if (!t.parsedPackets) facts.limits.push({ en: 'No IP packets could be decoded from this capture (unsupported link type or encrypted Wi-Fi frames).', zh: '无法从该抓包中解码 IP 数据包（不支持的链路类型或加密的 Wi-Fi 帧）。' });
  }
  const sdks = detectSdks(facts, kb.sdks, endpoints.map((e) => e.host));
  const permissions = [...buildPermissions(facts, kb.permissions), ...(facts.ios ? facts.permissionList : [])];

  let cert = null;
  if (facts.cert) cert = { scheme: facts.cert.scheme, sha256: await sha256Hex(facts.cert.der), sha1: await sha1Hex(facts.cert.der), ...(describeCert(facts.cert.der) ?? {}) };

  const has = (n) => permissions.some((p) => p.name === n);
  const ios = facts.ios;
  const m = facts.manifest;
  const capabilities = {
    billing: has('com.android.vending.BILLING') || sdks.some((s) => s.id === 'google_play_billing') || Boolean(ios?.linkedSystem.includes('StoreKit')) || has('wx.requestPayment'),
    advertisingId: has('com.google.android.gms.permission.AD_ID') || Boolean(ios?.linkedSystem.includes('AdSupport')) || has('ohos.permission.APP_TRACKING_CONSENT'),
    trackingPrompt: has('NSUserTrackingUsageDescription'),
    declaresTracking: Boolean(ios?.privacyManifests.some((p) => p.tracking)),
    cleartext: facts.platform === 'android'
      ? m.application.usesCleartextTraffic === true
      : Boolean(ios?.ats?.allowsArbitraryLoads || ios?.ats?.exceptionDomains.some((d) => d.insecureHttp)),
    unsigned: Boolean(facts.flags.unsigned),
    dynamicCodeLoading: Boolean(facts.flags.dynamicCodeLoading),
    electron: Boolean(facts.electron || ios?.electron),
    sandboxed: ios?.sandboxed ?? null,
  };

  let app;
  let android = null;
  if (facts.platform === 'android') {
    app = { id: m.package, name: null, versionName: m.versionName, versionCode: m.versionCode, minSdk: m.minSdk, targetSdk: m.targetSdk, splits: facts.splits };
    const packageNames = new Set();
    for (const c of facts.classes) {
      const parts = c.split('.');
      if (parts.length > 2) packageNames.add(parts.slice(0, Math.min(3, parts.length - 1)).join('.'));
    }
    android = {
      application: m.application,
      exportedComponents: m.components.filter((c) => c.exported),
      componentCount: m.components.length,
      components: m.components,
      metaData: m.metaData,
      queriedPackages: m.queriedPackages,
      nativeLibs: [...facts.nativeLibs].map(([name, abis]) => ({ name, abis: [...abis] })).sort((a, b) => a.name.localeCompare(b.name)),
      dex: facts.dexFiles,
      classes: facts.classes.size,
      topPackages: [...packageNames].sort().slice(0, 2000),
    };
  } else {
    app = { ...(facts.app ?? {}), splits: [] };
    if (ios) {
      const declared = new Map();
      for (const pm of ios.privacyManifests) {
        for (const c of pm.collected) {
          if (!declared.has(c.type)) declared.set(c.type, { type: c.type, category: kb.permissions.privacy_manifest_types[c.type] ?? 'other', linked: false, tracking: false, owners: [] });
          const d = declared.get(c.type);
          d.linked ||= c.linked;
          d.tracking ||= c.tracking;
          d.owners.push(pm.owner);
        }
      }
      ios.declaredData = [...declared.values()];
      ios.objcClasses = facts.objcClasses.size;
    }
  }

  // Store launchers / web installers: the file is not the app and contains none of its code.
  let notice = null;
  if (app?.name === 'Google Play Games' && /^Google/.test(app.publisher ?? '')) {
    notice = {
      en: 'This file is Google\'s Play Games installer, not the game. It contains none of the game\'s code: the game is downloaded after installation and runs as an Android app. To scan the game, scan its Android file (APK) instead.',
      zh: '该文件是 Google Play 游戏的安装程序，而不是游戏本身，其中不包含任何游戏代码：游戏在安装后下载并以 Android 应用形式运行。如需扫描该游戏，请改为扫描其 Android 文件（APK）。',
    };
  }

  return {
    analyzer: { name: 'k1d static analyzer', version: ANALYZER_VERSION, kbVersion: kb.sdks.version },
    platform: facts.platform,
    container,
    durationMs: Date.now() - started,
    app,
    cert,
    signatureSchemes: [...new Set(facts.signatureSchemes)],
    capabilities,
    permissions,
    sdks,
    endpoints,
    secrets: [...facts.secrets.values()].map((s) => ({ ...s, sources: [...s.sources] })).sort((a, b) => (a.level === 'high' ? 0 : 1) - (b.level === 'high' ? 0 : 1)),
    configKeys: [...facts.configKeys].sort(),
    npmPackages: [...facts.npm].sort(),
    android,
    ios,
    traffic,
    notice,
    details: facts.details,
    limits: facts.limits,
    files: facts.fileCount,
    errors: facts.errors,
  };
}
