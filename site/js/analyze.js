// Orchestrates static analysis of Android (APK, AAB, XAPK/APKS/APKM) and iOS (IPA) apps.
import { openZip, bytesSource } from './zip.js';
import { parseAXML, parseProtoXml, summarizeManifest, parseArscStrings } from './axml.js';
import { parseDex } from './dex.js';
import { readSigningBlockCert, certFromPkcs7, describeCert, sha256Hex } from './cert.js';
import { collectIos, findIpaApp } from './ios.js';

export const ANALYZER_VERSION = '0.2.0';

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
      }
    } catch (err) {
      facts.errors.push(`${prefix}${e.name}: ${err.message}`);
    }
  }

  progress({ step: 'resources' });
  try {
    const arsc = await zip.readEntry(layout.arsc);
    if (arsc) {
      if (layout.proto) addUrls(latin1(arsc), prefix + layout.arsc);
      else for (const s of parseArscStrings(arsc)) if (s.includes('://')) addUrls(s, prefix + layout.arsc);
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
    } catch { /* ignore */ }
  }

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
    }
    for (const suffix of sdk.domains ?? []) {
      const matched = hosts.filter((h) => hostMatches(h, suffix));
      if (matched.length) evidence.push({ type: 'domain', signature: suffix, samples: matched.slice(0, 5) });
    }
    if (!evidence.length) continue;
    const kinds = new Set(evidence.map((e) => e.type));
    const strong = kinds.has('framework') || codeHits >= 3;
    const medium = kinds.has('code') || kinds.has('ios_class') || kinds.has('native') || kinds.has('manifest') || kinds.has('plist_key') || kinds.has('url_scheme') || kinds.has('config_key');
    let confidence = 'low';
    if (strong || (medium && kinds.size >= 2)) confidence = 'high';
    else if (medium) confidence = 'medium';
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
    const host = hostOf(url);
    if (!host || ignore.has(host) || !host.includes('.')) continue;
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
  const ios = facts.ios;
  const out = ios.usage.map((u) => ({ name: u.key, kind: 'usage', description: u.text, ...(permKb.ios_usage[u.key] ?? { category: 'other', level: 'low' }) }));
  for (const fw of ios.linkedSystem) {
    const def = permKb.ios_frameworks[fw];
    if (def) out.push({ name: `${fw}.framework`, kind: 'framework', description: def.note, category: def.category, level: def.level });
  }
  return out;
}

// ---------------------------------------------------------------- entry point
export async function analyzeSource(source, kb, { onProgress } = {}) {
  const progress = onProgress ?? (() => {});
  const started = Date.now();
  progress({ step: 'open' });
  const zip = await openZip(source);
  const facts = emptyFacts();
  let container;

  if (zip.byName.has('AndroidManifest.xml')) {
    container = 'apk';
    await collectAndroid(zip, facts, '', apkLayout(), progress);
  } else if (findIpaApp(zip)) {
    container = 'ipa';
    await collectIos(zip, facts, { addUrls: addUrlsTo(facts), progress });
  } else if (zip.byName.has('base/manifest/AndroidManifest.xml')) {
    container = 'aab';
    const modules = zip.entries.map((e) => /^([^/]+)\/manifest\/AndroidManifest\.xml$/.exec(e.name)?.[1]).filter(Boolean);
    modules.sort((a, b) => (a === 'base' ? -1 : b === 'base' ? 1 : a.localeCompare(b)));
    for (const mod of modules) await collectAndroid(zip, facts, mod === 'base' ? '' : mod, aabLayout(mod), progress);
  } else {
    const apks = zip.entries.filter((e) => /\.apk$/i.test(e.name));
    if (!apks.length) {
      if (zip.entries.some((e) => /^Payload\//.test(e.name))) throw new Error('NO_IPA_APP');
      throw new Error('NO_MANIFEST');
    }
    container = 'bundle';
    const rank = (n) => (/(^|\/)base(-master)?\.apk$/i.test(n) ? 0 : /(^|\/)(config\.|split_)/i.test(n) ? 2 : 1);
    apks.sort((a, b) => rank(a.name) - rank(b.name));
    for (const e of apks) {
      progress({ step: 'split', detail: e.name });
      const inner = await openZip(bytesSource(await zip.readEntry(e)));
      await collectAndroid(inner, facts, e.name, apkLayout(), progress);
    }
  }

  if (facts.platform === 'android' && !facts.manifest) throw new Error('NO_MANIFEST');
  if (facts.platform === 'ios' && !facts.ios?.bundleId) throw new Error('NO_IPA_APP');

  progress({ step: 'detect' });
  const endpoints = classifyEndpoints(facts, kb.infra, kb.sdks);
  const sdks = detectSdks(facts, kb.sdks, endpoints.map((e) => e.host));
  const permissions = buildPermissions(facts, kb.permissions);

  let cert = null;
  if (facts.cert) cert = { scheme: facts.cert.scheme, sha256: await sha256Hex(facts.cert.der), ...(describeCert(facts.cert.der) ?? {}) };

  const has = (n) => permissions.some((p) => p.name === n);
  const ios = facts.ios;
  const capabilities = {
    billing: has('com.android.vending.BILLING') || sdks.some((s) => s.id === 'google_play_billing') || Boolean(ios?.linkedSystem.includes('StoreKit')),
    advertisingId: has('com.google.android.gms.permission.AD_ID') || Boolean(ios?.linkedSystem.includes('AdSupport')),
    trackingPrompt: has('NSUserTrackingUsageDescription'),
    declaresTracking: Boolean(ios?.privacyManifests.some((p) => p.tracking)),
    cleartext: facts.platform === 'android'
      ? facts.manifest.application.usesCleartextTraffic === true
      : Boolean(ios?.ats?.allowsArbitraryLoads || ios?.ats?.exceptionDomains.some((d) => d.insecureHttp)),
  };

  let app;
  let android = null;
  if (facts.platform === 'android') {
    const m = facts.manifest;
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
      metaData: m.metaData,
      queriedPackages: m.queriedPackages,
      nativeLibs: [...facts.nativeLibs].map(([name, abis]) => ({ name, abis: [...abis] })).sort((a, b) => a.name.localeCompare(b.name)),
      dex: facts.dexFiles,
      classes: facts.classes.size,
      topPackages: [...packageNames].sort().slice(0, 2000),
    };
  } else {
    app = { ...facts.app, splits: [] };
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
    configKeys: [...facts.configKeys].sort(),
    android,
    ios,
    files: facts.fileCount,
    errors: facts.errors,
  };
}
