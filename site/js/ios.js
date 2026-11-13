// iOS (.ipa) collector: Info.plist, executables (Mach-O), frameworks, resource bundles,
// privacy manifests, entitlements, code-signing certificate, provisioning profile, store metadata.
import { parsePlist, plistFromCms } from './plist.js';
import { isMachO, parseMachO, machoStrings, parseCodeSignature } from './macho.js';
import { leafCertFromCms } from './cert.js';

const TEXT_RE = /\.(json|js|html?|txt|xml|cfg|conf|ini|ya?ml|csv|properties|strings)$/i;
const MAX_TEXT = 4 * 1024 * 1024;
const MAX_TEXT_FILES = 400;
const MAX_BINARY = 512 * 1024 * 1024;

export function findIpaApp(zip) {
  const e = zip.entries.find((x) => /^Payload\/[^/]+\.app\/Info\.plist$/.test(x.name));
  return e ? e.name.slice(0, -'Info.plist'.length) : null;
}

function walkStrings(v, fn, depth = 0) {
  if (depth > 20 || v == null) return;
  if (typeof v === 'string') fn(v);
  else if (Array.isArray(v)) for (const x of v) walkStrings(x, fn, depth + 1);
  else if (typeof v === 'object' && !(v instanceof Uint8Array)) for (const x of Object.values(v)) walkStrings(x, fn, depth + 1);
}

// "Payload/X.app/Frameworks/Foo.framework/Bar.bundle/PrivacyInfo.xcprivacy" -> "Bar.bundle"
function ownerOf(path, appDir) {
  const rel = path.slice(appDir.length).split('/').slice(0, -1);
  for (let i = rel.length - 1; i >= 0; i--) if (/\.(framework|bundle|appex)$/.test(rel[i])) return rel[i];
  return appDir.split('/').filter(Boolean).pop();
}

const stripExt = (n) => n.replace(/\.(framework|bundle|appex|dylib)$/, '');

export async function collectIos(zip, facts, { addUrls, progress }) {
  const appDir = findIpaApp(zip);
  const appName = appDir.split('/').filter(Boolean).pop();
  const inApp = zip.entries.filter((e) => e.name.startsWith(appDir));
  facts.fileCount += zip.entries.length;
  facts.platform = 'ios';

  const readPlist = async (name) => {
    try { return parsePlist(await zip.readEntry(name)); } catch (err) { facts.errors.push(`${name}: ${err.message}`); return null; }
  };

  // ---------------------------------------------------------------- Info.plist
  progress({ step: 'plist' });
  const info = (await readPlist(appDir + 'Info.plist')) ?? {};
  const ats = info.NSAppTransportSecurity ?? null;
  const ios = {
    bundleId: info.CFBundleIdentifier ?? null,
    displayName: info.CFBundleDisplayName ?? info.CFBundleName ?? null,
    executable: info.CFBundleExecutable ?? null,
    minimumOS: info.MinimumOSVersion ?? null,
    sdk: info.DTSDKName ?? null,
    xcode: info.DTXcode ?? null,
    deviceFamily: info.UIDeviceFamily ?? [],
    usage: Object.keys(info).filter((k) => /UsageDescription$/.test(k)).map((k) => ({ key: k, text: String(info[k] ?? '') })),
    ats: ats ? {
      allowsArbitraryLoads: ats.NSAllowsArbitraryLoads === true,
      allowsArbitraryLoadsInWebContent: ats.NSAllowsArbitraryLoadsInWebContent === true,
      exceptionDomains: Object.entries(ats.NSExceptionDomains ?? {}).map(([domain, v]) => ({
        domain,
        insecureHttp: Boolean(v?.NSExceptionAllowsInsecureHTTPLoads || v?.NSTemporaryExceptionAllowsInsecureHTTPLoads),
        includesSubdomains: Boolean(v?.NSIncludesSubdomains),
      })),
    } : null,
    urlSchemes: (info.CFBundleURLTypes ?? []).flatMap((t) => t?.CFBundleURLSchemes ?? []).map(String),
    queriesSchemes: (info.LSApplicationQueriesSchemes ?? []).map(String),
    backgroundModes: (info.UIBackgroundModes ?? []).map(String),
    associatedDomains: [],
    plistKeys: Object.keys(info),
    frameworks: [],
    dylibs: [],
    bundles: [],
    extensions: [],
    linkedSystem: [],
    linkedEmbedded: [],
    privacyManifests: [],
    binary: null,
    entitlements: null,
    teamId: null,
    signingIdentifier: null,
    provisioning: null,
    storeMetadata: null,
  };
  facts.ios = ios;
  facts.app = {
    id: ios.bundleId,
    name: ios.displayName,
    versionName: info.CFBundleShortVersionString ?? null,
    versionCode: info.CFBundleVersion ?? null,
    minSdk: ios.minimumOS,
    targetSdk: info.DTPlatformVersion ?? null,
  };
  walkStrings(info, (s) => { if (s.includes('://')) addUrls(s, `${appName}/Info.plist`); });
  for (const d of ios.ats?.exceptionDomains ?? []) addUrls(`${d.insecureHttp ? 'http' : 'https'}://${d.domain.replace(/^\*\./, '')}/`, `${appName}/Info.plist (ATS exception)`);

  // ---------------------------------------------------------------- executables
  const linked = new Set();
  const analyzeBinary = async (path, label, isMain) => {
    const entry = zip.byName.get(path);
    if (!entry || entry.size > MAX_BINARY) return null;
    progress({ step: 'binary', detail: label });
    try {
      const bytes = await zip.readEntry(entry);
      if (!isMachO(bytes)) return null;
      const m = parseMachO(bytes);
      for (const d of m.dylibs) linked.add(d);
      const { cstrings, classNames } = machoStrings(m);
      for (const c of classNames) facts.objcClasses.add(c);
      for (const s of cstrings) {
        if (s.includes('://') && s.length < 2048) addUrls(s, label);
      }
      const summary = { path: path.slice(appDir.length), arch: m.arch, fat: m.fatArchs ? m.fatArchs.length : 0, encrypted: m.encrypted, minOS: m.minOS, sdk: m.sdk, classNames: classNames.length, strings: cstrings.length };
      if (isMain) {
        const cs = parseCodeSignature(m);
        if (cs) {
          ios.signingIdentifier = cs.identifier;
          ios.teamId = cs.teamId;
          ios.entitlements = cs.entitlements;
          if (cs.cms) {
            try {
              const der = leafCertFromCms(cs.cms);
              if (der) { facts.cert = { scheme: 'ios-codesign', der }; facts.signatureSchemes.push('iOS code signature (CMS)'); }
            } catch (err) { facts.errors.push(`${label} signature: ${err.message}`); }
          }
        }
      }
      return summary;
    } catch (err) {
      facts.errors.push(`${label}: ${err.message}`);
      return null;
    }
  };

  if (ios.executable) ios.binary = await analyzeBinary(appDir + ios.executable, `${appName}/${ios.executable}`, true);
  if (!ios.binary) facts.errors.push('Main executable not found or not a Mach-O file.');

  // ---------------------------------------------------------------- frameworks, dylibs, extensions, bundles
  const fwNames = new Set();
  const bundleNames = new Set();
  const appexNames = new Set();
  for (const e of inApp) {
    const rel = e.name.slice(appDir.length);
    let m = /^Frameworks\/([^/]+\.framework)\//.exec(rel);
    if (m) fwNames.add(m[1]);
    m = /^Frameworks\/([^/]+\.dylib)$/.exec(rel);
    if (m) ios.dylibs.push(m[1]);
    m = /^PlugIns\/([^/]+\.appex)\//.exec(rel);
    if (m) appexNames.add(m[1]);
    for (const seg of rel.split('/').slice(0, -1)) if (seg.endsWith('.bundle')) bundleNames.add(seg);
  }
  for (const fw of [...fwNames].sort()) {
    const base = `${appDir}Frameworks/${fw}/`;
    const fInfo = zip.byName.has(base + 'Info.plist') ? await readPlist(base + 'Info.plist') : null;
    const exe = fInfo?.CFBundleExecutable ?? stripExt(fw);
    const bin = await analyzeBinary(base + exe, `Frameworks/${fw}/${exe}`, false);
    ios.frameworks.push({
      name: stripExt(fw),
      bundleId: fInfo?.CFBundleIdentifier ?? null,
      version: fInfo?.CFBundleShortVersionString ?? null,
      encrypted: bin?.encrypted ?? null,
    });
    if (fInfo) walkStrings(fInfo, (s) => { if (s.includes('://')) addUrls(s, `Frameworks/${fw}/Info.plist`); });
  }
  for (const ax of [...appexNames].sort()) {
    const base = `${appDir}PlugIns/${ax}/`;
    const aInfo = zip.byName.has(base + 'Info.plist') ? await readPlist(base + 'Info.plist') : null;
    const exe = aInfo?.CFBundleExecutable ?? stripExt(ax);
    await analyzeBinary(base + exe, `PlugIns/${ax}/${exe}`, false);
    ios.extensions.push({ name: stripExt(ax), bundleId: aInfo?.CFBundleIdentifier ?? null, type: aInfo?.NSExtension?.NSExtensionPointIdentifier ?? null });
  }
  ios.bundles = [...bundleNames].map(stripExt).sort();
  for (const d of [...linked].sort()) {
    const sys = /^\/System\/Library\/(?:Frameworks|PrivateFrameworks)\/([^/]+)\.framework\//.exec(d);
    if (sys) { ios.linkedSystem.push(sys[1]); continue; }
    const emb = /^@(?:rpath|executable_path|loader_path)\/.*?([^/]+)\.framework\//.exec(d);
    if (emb) ios.linkedEmbedded.push(emb[1]);
  }
  ios.linkedSystem = [...new Set(ios.linkedSystem)].sort();
  ios.linkedEmbedded = [...new Set(ios.linkedEmbedded)].sort();
  facts.frameworkNames = new Set([...ios.frameworks.map((f) => f.name), ...ios.linkedEmbedded, ...ios.dylibs.map(stripExt)]);
  facts.bundleNames = new Set(ios.bundles);
  facts.frameworkBundleIds = ios.frameworks.map((f) => f.bundleId).filter(Boolean);

  // ---------------------------------------------------------------- privacy manifests
  progress({ step: 'privacy' });
  for (const e of inApp.filter((x) => x.name.endsWith('PrivacyInfo.xcprivacy'))) {
    const pm = await readPlist(e.name);
    if (!pm) continue;
    const domains = (pm.NSPrivacyTrackingDomains ?? []).map(String);
    for (const d of domains) addUrls(`https://${d}/`, `${ownerOf(e.name, appDir)}/PrivacyInfo.xcprivacy (tracking domain)`);
    ios.privacyManifests.push({
      owner: ownerOf(e.name, appDir),
      tracking: pm.NSPrivacyTracking === true,
      trackingDomains: domains,
      collected: (pm.NSPrivacyCollectedDataTypes ?? []).map((c) => ({
        type: String(c?.NSPrivacyCollectedDataType ?? ''),
        linked: c?.NSPrivacyCollectedDataTypeLinked === true,
        tracking: c?.NSPrivacyCollectedDataTypeTracking === true,
        purposes: (c?.NSPrivacyCollectedDataTypePurposes ?? []).map((x) => String(x).replace(/^NSPrivacyCollectedDataTypePurpose/, '')),
      })),
      accessedApis: (pm.NSPrivacyAccessedAPITypes ?? []).map((a) => ({
        type: String(a?.NSPrivacyAccessedAPIType ?? '').replace(/^NSPrivacyAccessedAPICategory/, ''),
        reasons: (a?.NSPrivacyAccessedAPITypeReasons ?? []).map(String),
      })),
    });
  }

  // ---------------------------------------------------------------- provisioning, store metadata, entitlements
  if (zip.byName.has(appDir + 'embedded.mobileprovision')) {
    try {
      const prof = plistFromCms(await zip.readEntry(appDir + 'embedded.mobileprovision'));
      if (prof) {
        ios.provisioning = {
          name: prof.Name ?? null,
          teamName: prof.TeamName ?? null,
          teamIds: prof.TeamIdentifier ?? [],
          appIdName: prof.AppIDName ?? null,
          created: prof.CreationDate ?? null,
          expires: prof.ExpirationDate ?? null,
          provisionedDevices: Array.isArray(prof.ProvisionedDevices) ? prof.ProvisionedDevices.length : 0,
          provisionsAllDevices: prof.ProvisionsAllDevices === true,
          type: prof.ProvisionsAllDevices ? 'enterprise' : Array.isArray(prof.ProvisionedDevices) ? 'development / ad hoc' : 'app store / unknown',
        };
      }
    } catch (err) { facts.errors.push(`embedded.mobileprovision: ${err.message}`); }
  }
  const metaEntry = zip.byName.get('iTunesMetadata.plist');
  if (metaEntry) {
    const md = await readPlist(metaEntry.name);
    if (md) ios.storeMetadata = { artistName: md.artistName ?? null, itemName: md.itemName ?? md.playlistName ?? null, itemId: md.itemId ?? null, genre: md.genre ?? null, releaseDate: md.releaseDate ?? null, bundleId: md.softwareVersionBundleId ?? null };
  }
  if (ios.entitlements) {
    const ent = ios.entitlements;
    ios.teamId = ios.teamId ?? ent['com.apple.developer.team-identifier'] ?? null;
    ios.associatedDomains = (ent['com.apple.developer.associated-domains'] ?? []).map(String);
    for (const d of ios.associatedDomains) {
      const host = d.replace(/^[a-z]+:/, '').replace(/\?.*$/, '');
      if (host && !host.includes('*')) addUrls(`https://${host}/`, 'entitlements (associated domains)');
    }
  }

  // ---------------------------------------------------------------- other plists and text resources
  progress({ step: 'resources' });
  const otherPlists = inApp.filter((e) => /\.plist$/.test(e.name) && e.name !== appDir + 'Info.plist' && !/\/Info\.plist$/.test(e.name) && e.size <= MAX_TEXT).slice(0, 200);
  for (const e of otherPlists) {
    try {
      const v = parsePlist(await zip.readEntry(e));
      walkStrings(v, (s) => { if (s.includes('://')) addUrls(s, e.name.slice(appDir.length)); });
      if (v && typeof v === 'object' && !Array.isArray(v)) for (const k of Object.keys(v)) if (/^[A-Z][A-Z0-9_]{4,}$/.test(k)) facts.configKeys.add(k);
    } catch { /* not a plist */ }
  }
  const td = new TextDecoder('utf-8');
  for (const e of inApp.filter((x) => TEXT_RE.test(x.name) && x.size <= MAX_TEXT).slice(0, MAX_TEXT_FILES)) {
    try {
      const text = td.decode(await zip.readEntry(e));
      if (text.includes('://')) addUrls(text, e.name.slice(appDir.length));
    } catch { /* ignore */ }
  }

  // ---------------------------------------------------------------- permissions (usage descriptions + capability frameworks)
  return { info };
}
