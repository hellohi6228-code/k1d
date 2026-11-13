// Orchestrates static analysis of an APK / XAPK / APKS and produces a report object.
import { openZip, bytesSource } from './zip.js';
import { parseAXML, summarizeManifest, parseArscStrings } from './axml.js';
import { parseDex } from './dex.js';
import { readSigningBlockCert, certFromPkcs7, describeCert, sha256Hex } from './cert.js';

export const ANALYZER_VERSION = '0.1.0';

const URL_RE = /\b(?:https?|wss?):\/\/([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(?::\d{1,5})?(?:\/[^\s"'<>\\^`{|}\u0000-\u001f]*)?/g;
const TEXT_FILE_RE = /\.(json|xml|txt|properties|js|html?|cfg|ini|conf|ya?ml|plist|csv)$/i;
const CONFIG_KEY_RE = /^[A-Z][A-Z0-9_.]*(APPKEY|APP_KEY|APPID|APP_ID|API_KEY|APPSECRET|APP_SECRET|CHANNEL)[A-Z0-9_]*$/;
const MAX_TEXT_FILE = 4 * 1024 * 1024;
const MAX_TEXT_FILES = 400;
const MAX_NATIVE_SCAN = 48 * 1024 * 1024;

function emptyFacts() {
  return {
    manifest: null,
    classes: new Set(),
    urls: new Map(), // url -> Set(source)
    configKeys: new Set(),
    nativeLibs: new Map(), // lib name -> Set(abi)
    dexFiles: [],
    cert: null,
    signatureSchemes: [],
    fileCount: 0,
    splits: [],
    errors: [],
  };
}

function addUrls(facts, text, source) {
  URL_RE.lastIndex = 0;
  let m;
  while ((m = URL_RE.exec(text)) !== null) {
    let url = m[0].replace(/[.,;:)\]]+$/, '');
    if (url.length > 300) url = url.slice(0, 300);
    if (!facts.urls.has(url)) facts.urls.set(url, new Set());
    facts.urls.get(url).add(source);
  }
}

function latin1(bytes) {
  // Fast enough for tens of MB; non-ASCII bytes become harmless characters.
  let out = '';
  const CH = 0x8000;
  for (let i = 0; i < bytes.length; i += CH) out += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
  return out;
}

async function collect(zip, facts, label, progress) {
  facts.fileCount += zip.entries.length;
  const prefix = label ? `${label}!` : '';

  // Manifest
  const manifestBytes = await zip.readEntry('AndroidManifest.xml');
  if (manifestBytes) {
    try {
      const m = summarizeManifest(parseAXML(manifestBytes));
      if (!facts.manifest) facts.manifest = m;
      else facts.splits.push(label || m.package);
      for (const c of m.components) if (c.name) facts.classes.add(c.name);
    } catch (e) {
      facts.errors.push(`${prefix}AndroidManifest.xml: ${e.message}`);
    }
  }

  // DEX
  const dexEntries = zip.entries.filter((e) => /^classes\d*\.dex$/.test(e.name));
  for (let i = 0; i < dexEntries.length; i++) {
    const e = dexEntries[i];
    progress({ step: 'dex', detail: `${prefix}${e.name}`, i: i + 1, n: dexEntries.length });
    try {
      const dex = parseDex(await zip.readEntry(e));
      facts.dexFiles.push({ name: prefix + e.name, classes: dex.classes.length, strings: dex.strings.length, version: dex.version });
      for (const c of dex.classes) facts.classes.add(c);
      for (const s of dex.strings) {
        if (s.length > 7 && s.length < 2048 && s.includes('://')) addUrls(facts, s, prefix + e.name);
        else if (s.length >= 5 && s.length <= 64 && CONFIG_KEY_RE.test(s)) facts.configKeys.add(s);
      }
    } catch (err) {
      facts.errors.push(`${prefix}${e.name}: ${err.message}`);
    }
  }

  // resources.arsc string pool
  progress({ step: 'resources' });
  try {
    const arsc = await zip.readEntry('resources.arsc');
    if (arsc) for (const s of parseArscStrings(arsc)) if (s.includes('://')) addUrls(facts, s, prefix + 'resources.arsc');
  } catch (err) {
    facts.errors.push(`${prefix}resources.arsc: ${err.message}`);
  }

  // Text assets
  const td = new TextDecoder('utf-8');
  const textEntries = zip.entries
    .filter((e) => (e.name.startsWith('assets/') || e.name.startsWith('res/raw/')) && TEXT_FILE_RE.test(e.name) && e.size <= MAX_TEXT_FILE)
    .slice(0, MAX_TEXT_FILES);
  for (const e of textEntries) {
    try {
      const text = td.decode(await zip.readEntry(e));
      if (text.includes('://')) addUrls(facts, text, prefix + e.name);
    } catch { /* ignore unreadable asset */ }
  }

  // Native libraries
  const libEntries = zip.entries.filter((e) => /^lib\/[^/]+\/[^/]+\.so$/.test(e.name));
  for (let i = 0; i < libEntries.length; i++) {
    const e = libEntries[i];
    const [, abi, lib] = e.name.split('/');
    if (!facts.nativeLibs.has(lib)) facts.nativeLibs.set(lib, new Set());
    facts.nativeLibs.get(lib).add(abi);
  }
  // Scan each distinct library once (prefer arm64), for embedded URLs.
  const seen = new Set();
  const ordered = [...libEntries].sort((a, b) => (b.name.includes('arm64') ? 1 : 0) - (a.name.includes('arm64') ? 1 : 0));
  for (const e of ordered) {
    const lib = e.name.split('/')[2];
    if (seen.has(lib) || e.size > MAX_NATIVE_SCAN) continue;
    seen.add(lib);
    progress({ step: 'native', detail: prefix + e.name });
    try {
      const text = latin1(await zip.readEntry(e));
      if (text.includes('://')) addUrls(facts, text, prefix + e.name);
    } catch { /* ignore */ }
  }

  // Signing certificate (only from the base APK / first package seen)
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

function detectSdks(facts, kb, hosts) {
  const classes = [...facts.classes];
  const metaNames = new Set((facts.manifest?.metaData ?? []).map((m) => m.name));
  const detections = [];
  for (const sdk of kb.sdks) {
    const evidence = [];
    let codeHits = 0;
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
    for (const suffix of sdk.domains ?? []) {
      const matched = hosts.filter((h) => hostMatches(h, suffix));
      if (matched.length) evidence.push({ type: 'domain', signature: suffix, samples: matched.slice(0, 5) });
    }
    if (!evidence.length) continue;
    const kinds = new Set(evidence.map((e) => e.type));
    let confidence = 'low';
    if ((codeHits >= 3 && kinds.size >= 1) || (codeHits > 0 && kinds.size >= 2)) confidence = 'high';
    else if (codeHits > 0 || kinds.has('native') || kinds.has('manifest')) confidence = 'medium';
    detections.push({
      id: sdk.id,
      name: sdk.name,
      vendor: sdk.vendor,
      category: sdk.category,
      cnNexus: sdk.cn_nexus ?? null,
      aliases: sdk.aliases ?? [],
      confidence,
      activity: 'code_present',
      evidence,
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
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(h.host);
    out.push({
      host: h.host,
      isIp,
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

export async function analyzeSource(source, kb, { onProgress } = {}) {
  const progress = onProgress ?? (() => {});
  const started = Date.now();
  progress({ step: 'open' });
  const zip = await openZip(source);
  const facts = emptyFacts();
  let container = 'apk';

  if (zip.byName.has('AndroidManifest.xml')) {
    await collect(zip, facts, '', progress);
  } else if (zip.byName.has('base/manifest/AndroidManifest.xml')) {
    throw new Error('AAB_UNSUPPORTED');
  } else {
    const apks = zip.entries.filter((e) => /\.apk$/i.test(e.name));
    if (!apks.length) throw new Error('NO_MANIFEST');
    container = 'bundle';
    // Base APK first so its manifest and certificate win.
    const rank = (n) => (/(^|\/)base(-master)?\.apk$/i.test(n) ? 0 : /(^|\/)(config\.|split_)/i.test(n) ? 2 : 1);
    apks.sort((a, b) => rank(a.name) - rank(b.name));
    for (const e of apks) {
      progress({ step: 'split', detail: e.name });
      const inner = await openZip(bytesSource(await zip.readEntry(e)));
      await collect(inner, facts, e.name, progress);
    }
  }
  if (!facts.manifest) throw new Error('NO_MANIFEST');

  progress({ step: 'detect' });
  const endpoints = classifyEndpoints(facts, kb.infra, kb.sdks);
  const hosts = endpoints.map((e) => e.host);
  const sdks = detectSdks(facts, kb.sdks, hosts);

  const permissions = facts.manifest.permissions.map((p) => ({
    name: p,
    ...(kb.permissions.permissions[p] ?? { category: null, level: null }),
  }));

  let cert = null;
  if (facts.cert) {
    cert = {
      scheme: facts.cert.scheme,
      sha256: await sha256Hex(facts.cert.der),
      ...(describeCert(facts.cert.der) ?? {}),
    };
  }

  const packageNames = new Set();
  for (const c of facts.classes) {
    const parts = c.split('.');
    if (parts.length > 2) packageNames.add(parts.slice(0, Math.min(3, parts.length - 1)).join('.'));
  }

  return {
    analyzer: { name: 'k1d static analyzer', version: ANALYZER_VERSION, kbVersion: kb.sdks.version },
    container,
    durationMs: Date.now() - started,
    app: {
      package: facts.manifest.package,
      versionName: facts.manifest.versionName,
      versionCode: facts.manifest.versionCode,
      minSdk: facts.manifest.minSdk,
      targetSdk: facts.manifest.targetSdk,
      splits: facts.splits,
    },
    cert,
    signatureSchemes: [...new Set(facts.signatureSchemes)],
    manifest: {
      application: facts.manifest.application,
      exportedComponents: facts.manifest.components.filter((c) => c.exported),
      componentCount: facts.manifest.components.length,
      metaData: facts.manifest.metaData,
      queriedPackages: facts.manifest.queriedPackages,
    },
    permissions,
    sdks,
    endpoints,
    configKeys: [...facts.configKeys].sort(),
    nativeLibs: [...facts.nativeLibs].map(([name, abis]) => ({ name, abis: [...abis] })).sort((a, b) => a.name.localeCompare(b.name)),
    inventory: {
      files: facts.fileCount,
      dex: facts.dexFiles,
      classes: facts.classes.size,
      topPackages: [...packageNames].sort().slice(0, 2000),
    },
    errors: facts.errors,
  };
}
