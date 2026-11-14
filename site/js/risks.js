// Risk-area scan: maps static observations to the US legal areas where China-linked apps have
// faced lawsuits or enforcement. Draft, not expert-reviewed. Observations and context only —
// never a verdict. Each area lists the signals found, why the area may matter, public references,
// and what to verify next (usually at runtime).

import { inferProfile } from './profile.js';

const TRACKING = new Set(['ads', 'analytics', 'attribution']);
const S = (en, zh) => ({ en, zh });
const names = (list, lang = 'en') => list.map((s) => s.name[lang]).join(lang === 'zh' ? '、' : ', ');

export const CONTEXT_CATEGORIES = ['game', 'casino', 'video', 'ai', 'social', 'utility', 'ecommerce', 'health', 'education', 'other'];

// ctxIn may override the automatic profile (tests use this); the app passes nothing.
export function buildRisks(r, ctxIn = {}, policy = null) {
  const prof = inferProfile(r);
  const ctx = { category: prof.category, audience: prof.audience, consentAt: prof.consent?.at ?? null, ...ctxIn };
  if (ctxIn.childDirected === true) ctx.audience = 'child';
  const consentWhen = ctxIn.consentAt != null || !prof.consent?.service
    ? S(`before the consent time (${ctx.consentAt}s)`, `在同意时间（${ctx.consentAt} 秒）之前`)
    : S(`before the consent service (${prof.consent.service}) was first contacted at ${ctx.consentAt}s`, `在同意管理服务（${prof.consent.service}）于第 ${ctx.consentAt} 秒首次连接之前`);
  const ga = prof.gaDefaults;
  // Wording found in the app's resources and text files (analyze.js UI_PATTERNS), and how much was readable.
  const ui = r.uiText;
  const cov = r.coverage;
  const quote = (h) => `“${h.text.length > 160 ? `${h.text.slice(0, 157)}…` : h.text}” (${h.source.split('!').pop()})`;
  const readNote = cov ? S(` in the ${cov.textFiles} text files k1d read${cov.encrypted.length ? ` (${cov.encrypted.length} encrypted script file(s) could not be read)` : ''}`, `（共读取 ${cov.textFiles} 个文本文件${cov.encrypted.length ? `，${cov.encrypted.length} 个加密脚本文件无法读取` : ''}）`) : S('', '');
  const areas = [];
  const sdk = (cat) => r.sdks.filter((s) => s.category === cat && s.confidence !== 'low');
  const tracking = r.sdks.filter((s) => TRACKING.has(s.category) && s.confidence !== 'low');
  const cnSdks = r.sdks.filter((s) => s.cnNexus);
  const cnHosts = r.endpoints.filter((e) => e.cnIndicators.length);
  const perm = (n) => r.permissions.find((p) => p.name === n);
  const permCat = (...cats) => r.permissions.filter((p) => cats.includes(p.category) && (p.level === 'high' || p.level === 'medium'));
  const listed = r.sdks.filter((s) => s.lists?.length);
  const ios = r.ios;
  const android = r.android;
  const highSecrets = (r.secrets ?? []).filter((s) => s.level === 'high');
  // Network capture helpers (r.traffic exists only for .pcap/.pcapng input)
  const tHosts = r.traffic?.hosts ?? [];
  const kb = (n) => `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`;
  const before = (h) => ctx.consentAt != null && h.relFirst != null && h.relFirst < ctx.consentAt;
  const sdkHost = (h, list) => list.some((s) => s.evidence.some((e) => e.type === 'traffic' && e.samples.includes(h.host)));

  // 1 ── Foreign-adversary data transfers
  {
    const signals = [];
    if (cnSdks.length) signals.push(S(`${cnSdks.length} SDK(s) with China-nexus indicators: ${names(cnSdks)}.`, `${cnSdks.length} 个带中国关联指标的 SDK：${names(cnSdks, 'zh')}。`));
    if (cnHosts.length) signals.push(S(`${cnHosts.length} endpoint host(s) on PRC-headquartered infrastructure or .cn domains (e.g. ${cnHosts.slice(0, 3).map((e) => e.host).join(', ')}).`, `${cnHosts.length} 个接口主机位于总部在中国的基础设施或 .cn 域名上（如 ${cnHosts.slice(0, 3).map((e) => e.host).join('、')}）。`));
    if (r.cert?.subject?.C === 'CN') signals.push(S('The signing certificate subject country field is CN.', '签名证书主体的国家字段为 CN。'));
    if (listed.length) signals.push(S(`SDK vendor(s) noted on U.S. government lists in the knowledge base: ${names(listed)} (verify current status).`, `知识库标注列入美国政府名单的 SDK 提供方：${names(listed, 'zh')}（需核实当前状态）。`));
    const prcAi = r.sdks.filter((s) => s.category === 'ai' && s.cnNexus);
    if (prcAi.length) signals.push(S(`AI model endpoints operated by PRC-headquartered companies: ${names(prcAi)}. User prompts may be sent there.`, `由总部在中国的公司运营的 AI 模型接口：${names(prcAi, 'zh')}。用户输入可能被发送至这些接口。`));
    const cnLive = tHosts.filter((h) => h.cnIndicators.length && h.flows > 0);
    if (cnLive.length) {
      const up = cnLive.reduce((n, h) => n + h.up, 0);
      signals.push(S(`At runtime the device connected to ${cnLive.length} host(s) with China-nexus indicators and sent ${kb(up)} to them (${cnLive.slice(0, 4).map((h) => h.host).join(', ')}).`, `运行时设备连接了 ${cnLive.length} 个带中国关联指标的主机，并向其发送了 ${kb(up)}（${cnLive.slice(0, 4).map((h) => h.host).join('、')}）。`));
      const pre = cnLive.filter(before);
      if (pre.length) signals.push(S(`${pre.length} of them were contacted ${consentWhen.en}: ${pre.slice(0, 4).map((h) => h.host).join(', ')}.`, `其中 ${pre.length} 个${consentWhen.zh}即被连接：${pre.slice(0, 4).map((h) => h.host).join('、')}。`));
    }
    areas.push({
      id: 'foreign_data', title: S('Data transfers to countries of concern', '向受关注国家传输数据'), signals,
      why: S('The DOJ Data Security Program restricts giving covered persons or countries of concern access to bulk U.S. sensitive data (deadline Oct 6, 2025). PADFA bars data brokers from selling or providing sensitive data to foreign-adversary-controlled entities; the FTC sent warning letters in Feb 2026. Several state AGs (KY, AZ, TX, OK, IA, MO) have sued Temu over data practices; the Texas settlement requires U.S. storage and disclosure of offshore sharing.',
        '美国司法部《数据安全计划》限制向受关注国家或受管辖主体提供大批量美国敏感数据（截止日期 2025 年 10 月 6 日）。PADFA 禁止数据经纪商向受外国对手控制的实体出售或提供敏感数据；FTC 于 2026 年 2 月发出警告信。多个州检察长（KY、AZ、TX、OK、IA、MO）就数据做法起诉 Temu；德州和解要求数据存储在美国并披露境外共享。'),
      refs: [
        ['28 C.F.R. Part 202 — DOJ Data Security Program (Greenberg Traurig summary)', 'https://www.gtlaw.com/en/insights/2025/10/incoming-deadlines-and-requirements-for-dojs-data-security-program-on-oct-6-2025'],
        ['PADFA — FTC warning letters to data brokers (Feb 2026)', 'https://www.alstonprivacy.com/ftc-sends-letters-reminding-data-brokers-of-their-obligations-under-padfaa/'],
        ['Texas AG settlement with Temu (Oct 2026)', 'https://www.texasattorneygeneral.gov/news/releases/attorney-general-paxton-secures-first-its-kind-settlement-temu-protect-texans-data-ccp-and-protect'],
      ],
      unseen: S("What data actually reaches these companies and where it is stored. A file shows what is built in, not what is sent.", "实际有哪些数据到达这些公司、存储在哪里。文件只能显示内置了什么，不能显示发送了什么。"),
    });
  }

  // 2 ── Children and teens (audience inferred automatically, see profile.js)
  {
    const signals = [];
    const ageSignals = r.sdks.filter((s) => s.category === 'age-assurance');
    const kidsAudience = ctx.audience === 'child' || ctx.audience === 'mixed';
    const basis = [...prof.audienceBasis, ...prof.categoryBasis].slice(0, 3);
    if (ctx.audience === 'child') signals.push(S(`Likely directed to children. ${basis.map((b) => b.en).join(' ')}`.trim(), `可能面向儿童。${basis.map((b) => b.zh).join('')}`));
    else if (ctx.audience === 'mixed') signals.push(S(`Likely mixed audience including children and teens. ${basis.map((b) => b.en).join(' ')}`.trim(), `受众可能包含儿童和青少年。${basis.map((b) => b.zh).join('')}`));
    if (kidsAudience) {
      if (tracking.length) signals.push(S(`${tracking.length} advertising/analytics/attribution SDK(s): ${names(tracking)}.`, `${tracking.length} 个广告/统计/归因 SDK：${names(tracking, 'zh')}。`));
      if (r.capabilities.advertisingId) signals.push(S('Can access the advertising identifier (a persistent identifier under COPPA).', '可访问广告标识符（COPPA 下的持久标识符）。'));
      if (ga.granted.length) signals.push(S(`Ad consent defaults are set to granted in the manifest (${ga.granted.join(', ')}), so ad data can be collected before any age or consent check.`, `清单将广告同意默认值设为“已授予”（${ga.granted.join('、')}），在任何年龄或同意确认之前即可收集广告数据。`));
      const liveTracking = tHosts.filter((h) => h.flows > 0 && sdkHost(h, tracking));
      if (liveTracking.length) signals.push(S(`At runtime the app contacted ${liveTracking.length} tracking host(s), e.g. ${liveTracking.slice(0, 4).map((h) => h.host).join(', ')}.`, `运行时应用连接了 ${liveTracking.length} 个跟踪主机，如 ${liveTracking.slice(0, 4).map((h) => h.host).join('、')}。`));
      if (['game', 'casino'].includes(ctx.category) && r.capabilities.billing) signals.push(S('Game with in-app purchases: the FTC order against HoYoverse requires parental consent for loot-box purchases by users under 16.', '含应用内购买的游戏：FTC 对 HoYoverse 的命令要求 16 岁以下用户购买抽奖箱须经家长同意。'));
    }
    if (ui) {
      if (ui.age.length) for (const h of ui.age.slice(0, 3)) signals.push(S(`Age-question wording in the app: ${quote(h)}.`, `应用中的年龄询问文字：${quote(h)}。`));
      else signals.push(S(`No age-question wording found${readNote.en}.`, `未发现年龄询问文字${readNote.zh}。`));
    }
    if (!r.traffic || ageSignals.length) signals.push(ageSignals.length
      ? S(`Platform age-signal API present: ${names(ageSignals)}.`, `存在平台年龄信号 API：${names(ageSignals, 'zh')}。`)
      : S('No platform age-signal API found (Google Play Age Signals / Apple Declared Age Range).', '未发现平台年龄信号 API（Google Play Age Signals / Apple Declared Age Range）。'));
    areas.push({
      id: 'children', title: S('Children and teens', '儿童与青少年'), signals, attention: kidsAudience,
      why: S('The amended COPPA Rule (deadline Apr 22, 2026) covers persistent identifiers collected by operators and integrated third parties. The FTC settled with HoYoverse (Genshin Impact) for $20M in Jan 2025 over COPPA and loot boxes. Texas sued TikTok under the SCOPE Act (Oct 2024) and won a DTPA ruling in Sep 2026. Texas\'s app-store age law was preliminarily enjoined in Dec 2025; similar laws exist in Utah, Louisiana and Alabama.',
        '修订后的 COPPA 规则（截止日期 2026 年 4 月 22 日）涵盖运营者及其集成的第三方收集的持久标识符。FTC 于 2025 年 1 月就 COPPA 和抽奖箱问题与 HoYoverse（原神）以 2000 万美元和解。德州依据 SCOPE 法案起诉 TikTok（2024 年 10 月），并于 2026 年 9 月获得 DTPA 裁决。德州应用商店年龄法于 2025 年 12 月被初步禁止执行；犹他、路易斯安那和阿拉巴马有类似法律。'),
      refs: [
        ['FTC: lessons from the HoYoverse (Genshin Impact) settlement', 'https://ftc.gov/business-guidance/blog/2025/01/level-tips-businesses-ftcs-settlement-genshin-impact-developer-hoyoverse'],
        ['Texas AG v. TikTok under the SCOPE Act', 'https://www.kelleydrye.com/viewpoints/blogs/ad-law-access/texas-ag-sues-tiktok-in-first-lawsuit-brought-under-scope-act'],
        ['Texas app-store age law enjoined (Dec 2025)', 'https://techcrunch.com/2025/12/24/apple-pauses-app-store-changes-in-texas-after-court-blocks-age-assurance-law/'],
        ['Google Play Age Signals API', 'https://developer.android.com/google/play/age-signals/use-age-signals-api'],
        ['Apple Declared Age Range', 'https://developer.apple.com/documentation/declaredagerange'],
      ],
      unseen: S("What the SDKs send before an age question or consent (that needs a recording: see the Android recording guide), and text inside encrypted scripts, images or loaded from servers.", "年龄询问或同意之前各 SDK 发送了什么（需要录制流量：见 Android 录制指南），以及加密脚本、图片或从服务器加载的文字。"),
    });
  }

  // 3 ── Biometrics
  {
    const signals = [];
    const bio = sdk('biometrics');
    if (bio.length) signals.push(S(`Face / voice / biometric SDK(s): ${names(bio)}.`, `人脸/语音/生物识别 SDK：${names(bio, 'zh')}。`));
    const camMic = permCat('camera', 'microphone');
    if (bio.length && camMic.length) signals.push(S(`Combined with camera/microphone access (${camMic.map((p) => p.name).join(', ')}).`, `同时具有相机/麦克风访问权限（${camMic.map((p) => p.name).join('、')}）。`));
    const declaredBio = (ios?.declaredData ?? []).filter((d) => d.category === 'biometrics');
    if (declaredBio.length) signals.push(S(`Privacy manifests declare biometric-type data: ${declaredBio.map((d) => d.type.replace('NSPrivacyCollectedDataType', '')).join(', ')}.`, `隐私清单声明了生物特征类数据：${declaredBio.map((d) => d.type.replace('NSPrivacyCollectedDataType', '')).join('、')}。`));
    areas.push({
      id: 'biometrics', title: S('Biometric data (face, voice)', '生物识别数据（人脸、声纹）'), signals,
      why: S('Illinois BIPA gives a private right of action for collecting face geometry or voiceprints without written notice and consent. TikTok paid $92M (2022) over face filters; a BIPA class action over CapCut has partly survived dismissal. Texas and Washington also regulate biometric identifiers.',
        '伊利诺伊州 BIPA 允许个人就未经书面告知和同意收集面部几何特征或声纹提起诉讼。TikTok 因人脸滤镜支付 9200 万美元（2022 年）；针对 CapCut 的 BIPA 集体诉讼部分驳回动议被拒。德州和华盛顿州也规范生物识别信息。'),
      refs: [
        ['Judge approves $92M TikTok settlement (Hunton)', 'https://www.hunton.com/privacy-and-information-security-law/judge-approves-92-million-tiktok-settlement'],
        ['CapCut BIPA lawsuit (The Record)', 'https://therecord.media/capcut-privacy-lawsuit-illinois-bipa-bytedance-china'],
      ],
      unseen: S("Whether face or voice data is actually captured, stored, or sent off the phone.", "是否真的采集、存储或向手机外发送了人脸或声音数据。"),
    });
  }

  // 4 ── Wiretap / pen-register (tracking SDKs and session replay)
  {
    const signals = [];
    const replay = sdk('session-replay');
    if (replay.length) signals.push(S(`Session-replay SDK(s) that can record screens and inputs: ${names(replay)}.`, `可录制屏幕和输入的会话回放 SDK：${names(replay, 'zh')}。`));
    if (tracking.length) signals.push(S(`${tracking.length} advertising/analytics/attribution SDK(s): ${names(tracking)}.`, `${tracking.length} 个广告/统计/归因 SDK：${names(tracking, 'zh')}。`));
    if (r.capabilities.declaresTracking) signals.push(S('Privacy manifests declare tracking.', '隐私清单声明了跟踪。'));
    if (ga.granted.length) signals.push(S(`The manifest sets Google Analytics consent defaults to granted (${ga.granted.join(', ')}); these apply until the app records a user's choice.`, `清单将 Google Analytics 同意默认值设为“已授予”（${ga.granted.join('、')}），在应用记录用户选择前一直适用。`));
    if (ga.collection.length) signals.push(S(`The manifest turns on ${ga.collection.join(', ')}.`, `清单开启了 ${ga.collection.join('、')}。`));
    if (tHosts.length) {
      const live = tHosts.filter((h) => h.flows > 0 && sdkHost(h, tracking));
      if (live.length) signals.push(S(`Tracking SDK hosts contacted at runtime: ${live.slice(0, 6).map((h) => h.host).join(', ')}.`, `运行时连接的跟踪 SDK 主机：${live.slice(0, 6).map((h) => h.host).join('、')}。`));
      const start = prof.consent?.appStart;
      const firstMin = start == null ? [] : live.filter((h) => h.relFirst != null && h.relFirst - start <= 60);
      if (firstMin.length) signals.push(S(`${firstMin.length} tracking host(s) were contacted in the app's first 60 seconds, before any tap if the recording followed the k1d guide: ${firstMin.slice(0, 6).map((h) => h.host).join(', ')}.`, `${firstMin.length} 个跟踪主机在应用启动后 60 秒内即被连接（如按 k1d 指南录制，此时尚未点击任何内容）：${firstMin.slice(0, 6).map((h) => h.host).join('、')}。`));
      const pre = live.filter(before);
      if (pre.length) signals.push(S(`${pre.length} tracking host(s) were contacted ${consentWhen.en}: ${pre.slice(0, 6).map((h) => h.host).join(', ')}.`, `${pre.length} 个跟踪主机${consentWhen.zh}即被连接：${pre.slice(0, 6).map((h) => h.host).join('、')}。`));
      if (live.length && ctx.consentAt == null && prof.consent) {
        const first = Math.min(...live.map((h) => h.relFirst ?? Infinity));
        const after = prof.consent.appStart != null && Number.isFinite(first) ? Math.max(0, +(first - prof.consent.appStart).toFixed(1)) : null;
        signals.push(S(`No consent-management service was contacted during the capture${after != null ? `; the first tracking host was contacted ${after}s after the app's first connection` : ''}.`, `抓包期间未连接任何同意管理服务${after != null ? `；首个跟踪主机在应用首次联网后 ${after} 秒即被连接` : ''}。`));
      }
    }
    areas.push({
      id: 'wiretap', title: S('Wiretap and pen-register claims (tracking SDKs)', '窃听与“笔式记录器”诉讼（跟踪 SDK）'), signals,
      why: S('Plaintiffs use California\'s Invasion of Privacy Act (CIPA §§ 631, 638.51; statutory damages of $5,000 per claim) and the federal Wiretap Act against embedded SDKs. A federal court let a claim that InMobi\'s ad SDK is a "pen register" proceed; a Los Angeles court ruled the other way in May 2026, so the law is unsettled. Washington\'s first My Health My Data class action (Feb 2025) also targets an ad SDK.',
        '原告援引加州《隐私侵犯法》（CIPA 第 631、638.51 条；每项主张法定赔偿 5000 美元）及联邦《窃听法》起诉嵌入式 SDK。联邦法院允许“InMobi 广告 SDK 属于笔式记录器”的主张继续审理；洛杉矶法院于 2026 年 5 月作出相反裁决，法律尚未定论。华盛顿州首起《我的健康我的数据法》集体诉讼（2025 年 2 月）同样针对广告 SDK。'),
      refs: [
        ['"The SDK in your app may be your next class action" (InMobi ruling)', 'https://www.mondaq.com/unitedstates/class-actions/1789130/the-sdk-in-your-app-may-be-your-next-class-action-lawsuit'],
        ['Blaker v. NetScout — CIPA pen-register claim dismissed (May 2026)', 'https://natlawreview.com/article/cipa-win-california-superior-court-sustains-dismissal-website-tracking-claims'],
        ['First Washington MHMDA class action (Amazon ad SDK)', 'https://www.wilmerhale.com/en/insights/blogs/wilmerhale-privacy-and-cybersecurity-law/20250220-first-lawsuit-filed-under-washingtons-my-health-my-data-act'],
      ],
      unseen: S("What each tracking SDK sends, and whether it sends it before the user agrees.", "各跟踪 SDK 发送了什么，以及是否在用户同意之前发送。"),
    });
  }

  // 5 ── Location and health data
  {
    const signals = [];
    const loc = permCat('precise_location', 'location');
    const health = permCat('health');
    if (loc.length) signals.push(S(`Location access: ${loc.map((p) => p.name).join(', ')}.`, `位置访问：${loc.map((p) => p.name).join('、')}。`));
    if (perm('android.permission.ACCESS_BACKGROUND_LOCATION') || ios?.backgroundModes?.includes('location')) signals.push(S('Background location is requested.', '请求后台定位。'));
    if (health.length) signals.push(S(`Health / fitness / motion access: ${health.map((p) => p.name).join(', ')}.`, `健康/运动/传感器访问：${health.map((p) => p.name).join('、')}。`));
    const locSdks = r.sdks.filter((s) => ['amap', 'baidu_location'].includes(s.id));
    if (locSdks.length) signals.push(S(`Location SDK(s): ${names(locSdks)}.`, `定位 SDK：${names(locSdks, 'zh')}。`));
    if (loc.length && tracking.length) signals.push(S('Location access in an app that also embeds ad/analytics SDKs.', '应用具有位置访问权限，同时嵌入广告/统计 SDK。'));
    areas.push({
      id: 'location_health', title: S('Precise location and health data', '精确位置与健康数据'), signals,
      why: S('Washington\'s My Health My Data Act (private right of action) treats some location data as consumer health data and restricts geofencing. Precise geolocation is a sensitive-data category under state privacy laws and under the DOJ Data Security Program. Missouri\'s Oct 2026 suit against Temu centers on location, camera and microphone access.',
        '华盛顿州《我的健康我的数据法》（允许私人诉讼）将部分位置数据视为消费者健康数据并限制地理围栏。精确地理位置在各州隐私法和司法部《数据安全计划》中均属敏感数据。密苏里州 2026 年 10 月起诉 Temu 的核心即为位置、相机和麦克风访问。'),
      refs: [
        ['First Washington MHMDA class action', 'https://www.wilmerhale.com/en/insights/blogs/wilmerhale-privacy-and-cybersecurity-law/20250220-first-lawsuit-filed-under-washingtons-my-health-my-data-act'],
        ['Missouri sues Temu over location, camera and microphone access', 'https://www.stlpr.org/government-politics-issues/2026-10-13/missouri-sues-temu-says-shopping-app-can-access-phone-location-camera-and-microphone'],
      ],
      unseen: S("How precise the location is, how often it is sent, and to whom.", "位置精度如何、多久发送一次、发给谁。"),
    });
  }

  // 6 ── Video viewing (VPPA)
  {
    const signals = [];
    const players = sdk('video-player');
    // A generic player (e.g., ExoPlayer) in a game usually plays video ads, not content the user
    // chooses to watch. Dedicated VOD players, or a video/social app, make this area relevant.
    const VOD = new Set(['tencent_liteav', 'aliyun_player', 'bytedance_ttvideo', 'ijkplayer']);
    const vodPlayers = players.filter((p) => VOD.has(p.id));
    const videoApp = ['video', 'social'].includes(ctx.category);
    const relevant = videoApp || vodPlayers.length > 0;
    if (players.length && relevant) signals.push(S(`Video player SDK(s): ${names(players)}.`, `视频播放 SDK：${names(players, 'zh')}。`));
    if (relevant && tracking.length) signals.push(S(`Video playback plus ${tracking.length} tracking SDK(s) (${names(tracking)}).`, `视频播放同时包含 ${tracking.length} 个跟踪 SDK（${names(tracking, 'zh')}）。`));
    areas.push({
      id: 'vppa', title: S('Video viewing data (VPPA)', '视频观看数据（VPPA）'), signals,
      why: S('The Video Privacy Protection Act (18 U.S.C. § 2710; $2,500 liquidated damages per person) has been used against apps that send what a user watched together with a persistent identifier to ad or analytics partners. Short-drama and video apps fit this pattern.',
        '《视频隐私保护法》（18 U.S.C. § 2710；每人 2500 美元约定赔偿）曾被用于起诉将用户观看内容与持久标识符一并发送给广告或统计合作方的应用。短剧和视频应用符合这一模式。'),
      refs: [['18 U.S.C. § 2710 (Cornell LII)', 'https://www.law.cornell.edu/uscode/text/18/2710']],
      unseen: S("Whether what users watch is sent to ad or analytics companies together with an identifier.", "用户观看的内容是否连同标识符一起发送给广告或统计公司。"),
    });
  }

  // 7 ── Subscriptions / auto-renewal
  {
    const signals = [];
    const subs = ui?.subscription ?? [];
    if (r.capabilities.billing) signals.push(S('In-app purchases are built in (Google Play Billing / StoreKit).', '内置应用内购买（Google Play Billing / StoreKit）。'));
    for (const h of subs.slice(0, 4)) signals.push(S(`Subscription wording in the app: ${quote(h)}.`, `应用中的订阅文字：${quote(h)}。`));
    if (ui && r.capabilities.billing && !subs.length) signals.push(S(`No subscription or auto-renewal wording found${readNote.en}.`, `未发现订阅或自动续费文字${readNote.zh}。`));
    areas.push({
      id: 'subscriptions', title: S('Subscriptions and auto-renewal', '订阅与自动续费'), signals, attention: ui ? subs.length > 0 : signals.length > 0,
      why: S('California\'s Automatic Renewal Law (Cal. Bus. & Prof. Code § 17600 et seq.) and the federal ROSCA (15 U.S.C. §§ 8401–8405) require clear terms and consent before charging and an easy way to cancel. Short-drama coin and VIP paywalls are a frequent subject.',
        '加州《自动续费法》（Cal. Bus. & Prof. Code § 17600 起）及联邦 ROSCA（15 U.S.C. §§ 8401–8405）要求扣费前清楚披露条款并取得同意，并提供简便的取消方式。短剧金币和 VIP 付费墙是常见关注对象。'),
      refs: [['ROSCA, 15 U.S.C. ch. 110 (Cornell LII)', 'https://www.law.cornell.edu/uscode/text/15/chapter-110']],
      unseen: S("Product prices and paywall screens: they come from the store and the app's servers at runtime, not from the file. Text inside encrypted scripts or images.", "商品价格和付费页面：运行时来自商店和应用服务器，不在文件中。以及加密脚本或图片中的文字。"),
    });
  }

  // 8 ── Gambling-like mechanics
  {
    const signals = [];
    const gameish = ['game', 'casino'].includes(ctx.category);
    if (gameish && r.capabilities.billing) signals.push(S(`${ctx.category === 'casino' ? 'Social-casino' : 'Game'} app with in-app purchases (virtual currency / loot boxes possible).`, `${ctx.category === 'casino' ? '社交博彩' : '游戏'}应用含应用内购买（可能涉及虚拟货币/抽奖箱）。`));
    for (const h of (ui?.odds ?? []).slice(0, 4)) signals.push(S(`Odds / loot-box wording in the app: ${quote(h)}.`, `应用中的概率/抽奖文字：${quote(h)}。`));
    if (ui && gameish && r.capabilities.billing && !ui.odds.length) signals.push(S(`No odds, drop-rate or loot-box wording found${readNote.en}.`, `未发现概率、掉落率或抽奖箱文字${readNote.zh}。`));
    areas.push({
      id: 'gambling', title: S('Loot boxes, virtual currency, social casino', '抽奖箱、虚拟货币与社交博彩'), signals,
      why: S('Washington\'s gambling-loss recovery law drives class actions against social-casino apps: a $24.9M jury verdict against High 5 Games (Feb 2025) and a proposed $201M judgment in Horn v. Amazon (Jul 2026). The FTC\'s HoYoverse order covers loot-box odds disclosure and virtual-currency practices.',
        '华盛顿州赌博损失追偿法推动了针对社交博彩应用的集体诉讼：High 5 Games 案陪审团裁定 2490 万美元（2025 年 2 月），Horn v. Amazon 案拟议判决 2.01 亿美元（2026 年 7 月）。FTC 对 HoYoverse 的命令涉及抽奖箱概率披露和虚拟货币做法。'),
      refs: [
        ['Social casino litigation in Washington (National Law Review)', 'https://natlawreview.com/article/operating-social-casino-style-applications-continues-be-costly-washington-state'],
        ['Amazon social casino settlement (Covers)', 'https://www.covers.com/industry/amazon-agrees-to-settlement-over-social-casino-apps-lawsuit-july-14-2026'],
      ],
      unseen: S("Odds shown in images or loaded from servers, and whether prizes can be cashed out or transferred.", "图片中或从服务器加载的概率，以及奖励能否兑现或转让。"),
    });
  }

  // 9 ── AI chatbots
  {
    const signals = [];
    const ai = sdk('ai');
    if (ai.length) signals.push(S(`AI model API(s) referenced: ${names(ai)}.`, `引用的 AI 模型 API：${names(ai, 'zh')}。`));
    areas.push({
      id: 'ai', title: S('AI companions and chatbots', 'AI 陪伴与聊天机器人'), signals,
      why: S('California SB 243 (in force Jan 1, 2026) requires companion chatbots to disclose they are AI, give minors break reminders, and allows private lawsuits. The FTC opened a 6(b) study of AI companions and minors (Sep 2025), and the Texas AG sent civil investigative demands to AI chatbot companies (Aug 2025).',
        '加州 SB 243（2026 年 1 月 1 日生效）要求陪伴型聊天机器人披露其为 AI、向未成年人发出休息提醒，并允许私人诉讼。FTC 于 2025 年 9 月启动针对 AI 陪伴与未成年人的 6(b) 研究，德州检察长于 2025 年 8 月向 AI 聊天公司发出民事调查要求。'),
      refs: [
        ['California SB 243 (TechCrunch)', 'https://techcrunch.com/2025/09/10/a-california-bill-that-would-regulate-ai-companion-chatbots-is-close-to-becoming-law'],
        ['FTC 6(b) orders on AI companion chatbots (DLA Piper)', 'https://www.dlapiper.com/en/insights/publications/2025/09/ftc-ai-chatbots'],
      ],
      unseen: S("What the chatbot tells users about being an AI, and where conversations are sent and stored.", "聊天机器人如何告知用户其为 AI，以及对话发送和存储到哪里。"),
    });
  }

  // 10 ── Security of the app itself
  {
    const signals = [];
    for (const s of highSecrets.slice(0, 6)) signals.push(S(`Hard-coded credential: ${s.label} ${s.value} (in ${s.sources[0]}).`, `硬编码凭据：${s.label} ${s.value}（位于 ${s.sources[0]}）。`));
    if (r.capabilities.cleartext) signals.push(S('Cleartext (unencrypted) connections are allowed.', '允许明文（未加密）连接。'));
    const http = r.endpoints.filter((e) => e.cleartext);
    if (http.length) signals.push(S(`${http.length} host(s) referenced over http:// or ws://.`, `${http.length} 个主机以 http:// 或 ws:// 引用。`));
    if (android?.application.debuggable) signals.push(S('The Android app is debuggable.', 'Android 应用处于可调试状态。'));
    if (android?.application.allowBackup) signals.push(S('Android backup of app data is allowed.', '允许 Android 备份应用数据。'));
    if (r.capabilities.unsigned) signals.push(S('The executable/package is not code-signed.', '可执行文件/安装包未进行代码签名。'));
    if (r.capabilities.dynamicCodeLoading) signals.push(S('Code can load additional code at runtime (DexClassLoader), so behavior can change after review.', '代码可在运行时加载额外代码（DexClassLoader），审核后行为可能改变。'));
    if (r.capabilities.sandboxed === false && r.platform === 'macos') signals.push(S('The macOS app is not sandboxed.', 'macOS 应用未启用沙盒。'));
    areas.push({
      id: 'security', title: S('Security of collected data', '所收集数据的安全'), signals,
      why: S('The FTC treats unreasonable data security as an unfair practice (FTC Act § 5), and state breach and data-security laws apply when personal data is exposed. Hard-coded cloud keys can expose every user\'s stored data.',
        'FTC 将不合理的数据安全措施视为不公平行为（FTC 法第 5 条），个人数据泄露时还适用各州泄露通知和数据安全法。硬编码的云服务密钥可能导致全部用户存储数据外泄。'),
      refs: [['FTC Act § 5, 15 U.S.C. § 45 (Cornell LII)', 'https://www.law.cornell.edu/uscode/text/15/45']],
      unseen: S("What each exposed key can access, and whether all traffic is encrypted when the app runs.", "每个暴露的密钥能访问什么，以及应用运行时是否所有流量都已加密。"),
    });
  }

  // 11 ── Intrusive device access (the "spyware" allegations in state AG suits)
  {
    const signals = [];
    for (const n of ['android.permission.QUERY_ALL_PACKAGES', 'android.permission.REQUEST_INSTALL_PACKAGES', 'android.permission.SYSTEM_ALERT_WINDOW', 'android.permission.READ_SMS', 'android.permission.READ_CALL_LOG', 'android.permission.READ_CONTACTS', 'android.permission.READ_PHONE_STATE']) {
      if (perm(n)) signals.push(S(`Requests ${n.split('.').pop()}.`, `请求 ${n.split('.').pop()}。`));
    }
    const queried = android?.queriedPackages ?? [];
    if (queried.length >= 10) {
      const seen = new Set();
      const sample = queried.filter((q) => {
        const k = q.split('.').slice(0, 2).join('.');
        if (/^com\.(google|android)$/.test(k) || seen.has(k)) return false;
        seen.add(k);
        return true;
      }).slice(0, 8).join(', ');
      signals.push(S(`Declares checks for whether ${queried.length} other apps are installed (e.g. ${sample}). Lists of installed apps can reveal interests and identity.`, `声明检测 ${queried.length} 个其他应用是否已安装（如 ${sample}）。已安装应用列表可能透露用户兴趣和身份。`));
    }
    if ((r.ios?.queriesSchemes?.length ?? 0) >= 10) signals.push(S(`Checks for ${r.ios.queriesSchemes.length} other apps via URL schemes.`, `通过 URL Scheme 检测 ${r.ios.queriesSchemes.length} 个其他应用。`));
    const comps = android?.components ?? [];
    if (comps.some((c) => c.permission === 'android.permission.BIND_ACCESSIBILITY_SERVICE')) signals.push(S('Declares an accessibility service (can read screen content and act on other apps).', '声明了无障碍服务（可读取屏幕内容并操作其他应用）。'));
    if (comps.some((c) => c.permission === 'android.permission.BIND_DEVICE_ADMIN')) signals.push(S('Declares a device-administrator receiver.', '声明了设备管理器接收器。'));
    for (const p of r.permissions.filter((x) => x.kind === 'capability' && x.level === 'high' && !['requireAdministrator'].includes(x.name))) {
      const ev = p.evidence ? p.evidence.join(', ') : p.name;
      signals.push(S(`${p.description} (${ev}).`, `${p.description}（${ev}）。`));
    }
    if (perm('requireAdministrator')) signals.push(S('Requires administrator rights on Windows.', '在 Windows 上需要管理员权限。'));
    if (r.platform === 'browser-extension') for (const p of r.permissions.filter((x) => x.level === 'high')) signals.push(S(`Extension permission: ${p.name}.`, `扩展权限：${p.name}。`));
    areas.push({
      id: 'intrusive', title: S('Intrusive device access', '侵入性设备访问'), signals,
      why: S('State AG complaints against China-linked apps (e.g., Temu) allege access beyond what the app needs — installed apps, other apps\' data, camera, microphone, location — and the ability to change behavior after installation, framed as deceptive or unfair practices.',
        '各州检察长对中国关联应用（如 Temu）的起诉指控其访问超出所需的数据——已安装应用、其他应用数据、相机、麦克风、位置——以及安装后改变行为的能力，并据此认定为欺骗性或不公平行为。'),
      refs: [['Missouri v. Temu (St. Louis Public Radio)', 'https://www.stlpr.org/government-politics-issues/2026-10-13/missouri-sues-temu-says-shopping-app-can-access-phone-location-camera-and-microphone']],
      unseen: S("Which app features use each access, and whether the app explains this to users.", "哪些功能使用了这些访问权限，以及应用是否向用户说明。"),
    });
  }

  // 12 ── Disclosures vs behavior
  {
    const signals = [];
    if (policy) {
      const missS = policy.sdkChecks.filter((c) => !c.match);
      const missC = policy.categoryChecks.filter((c) => !c.match);
      if (missS.length) signals.push(S(`Policy text does not name: ${missS.map((c) => c.name.en).join(', ')}.`, `隐私政策未提及：${missS.map((c) => c.name.zh).join('、')}。`));
      if (missC.length) signals.push(S(`Policy text does not mention: ${missC.map((c) => c.label.en).join(', ')}.`, `隐私政策未提及：${missC.map((c) => c.label.zh).join('、')}。`));
      const us = policy.statements.filter((s) => s.kind === 'us_storage');
      if (us.length && (cnSdks.length || cnHosts.length)) signals.push(S(`Policy says “${us[0].text.slice(0, 160)}” while the app contains China-nexus SDKs or endpoints.`, `政策称“${us[0].text.slice(0, 160)}”，而应用包含中国关联 SDK 或接口。`));
    }
    if (r.capabilities.declaresTracking && !r.capabilities.trackingPrompt && r.platform === 'ios') signals.push(S('Privacy manifests declare tracking but the app has no App Tracking Transparency prompt text.', '隐私清单声明了跟踪，但应用没有 App Tracking Transparency 提示文字。'));
    areas.push({
      id: 'disclosures', title: S('Disclosures vs. what the app contains', '披露内容与应用实际包含内容'), signals, attention: signals.length > 0,
      why: S('Most state AG cases against China-linked apps are UDAP claims built on gaps between what the app does and what its policy or store labels say (FTC Act § 5 and state consumer-protection acts).',
        '各州检察长针对中国关联应用的案件大多为 UDAP 主张，依据是应用实际行为与隐私政策或商店标签之间的差异（FTC 法第 5 条及各州消费者保护法）。'),
      refs: [['Texas AG settlement with Temu', 'https://www.texasattorneygeneral.gov/news/releases/attorney-general-paxton-secures-first-its-kind-settlement-temu-protect-texans-data-ccp-and-protect']],
      unseen: S("The full text of the privacy policy and the store privacy labels: they are online, not inside the app file.", "隐私政策全文和商店隐私标签：它们在网上，不在应用文件中。"),
    });
  }

  // 13 ── Foreign-adversary-controlled applications
  if (cnSdks.length || cnHosts.length || r.cert?.subject?.C === 'CN') {
    const signals = [];
    if (['social', 'video'].includes(ctx.category)) signals.push(S('Social / video app with China-nexus indicators.', '带有中国关联指标的社交/视频应用。'));
    areas.push({
      id: 'pafaca', title: S('Foreign-adversary-controlled apps law', '外国对手控制应用法'), signals,
      why: S('The Protecting Americans from Foreign Adversary Controlled Applications Act (2024) names ByteDance/TikTok and lets the President designate other social apps controlled by a foreign adversary that meet user thresholds. Ownership structure, not the code, decides coverage.',
        '《保护美国人免受外国对手控制应用法》（2024）点名字节跳动/TikTok，并允许总统指定其他符合用户规模门槛、受外国对手控制的社交应用。是否适用取决于股权结构，而非代码。'),
      refs: [['PAFACA text (Congress.gov, H.R. 7521)', 'https://www.congress.gov/bill/118th-congress/house-bill/7521']],
      unseen: S("Who ultimately owns the publisher and how many US users it has.", "发行商的最终所有者是谁，以及其美国用户数量。"),
    });
  }

  for (const a of areas) a.status = (a.attention ?? a.signals.length > 0) ? 'signals' : 'none';
  // Informational lines that don't change a status.
  const disc = areas.find((a) => a.id === 'disclosures');
  if (disc && ui?.consent.length) disc.signals.push(S(`Consent / policy wording in the app: ${ui.consent.slice(0, 4).map((h) => `“${h.text.length > 60 ? `${h.text.slice(0, 57)}…` : h.text}”`).join(', ')}.`, `应用中的同意/政策文字：${ui.consent.slice(0, 4).map((h) => `“${h.text.length > 60 ? `${h.text.slice(0, 57)}…` : h.text}”`).join('、')}。`));
  // Links on SDK vendors' domains are the vendors' own policies, not the app's.
  const policyUrls = [...new Set(r.endpoints.filter((e) => !e.operator).flatMap((e) => e.urls).filter((u) => /privacy|policy|terms|agreement/i.test(u)))].slice(0, 4);
  if (disc && policyUrls.length) disc.signals.push(S(`Policy links in the app: ${policyUrls.join(', ')}.`, `应用中的政策链接：${policyUrls.join('、')}。`));
  const order = { signals: 0, context: 1, none: 2 };
  areas.sort((a, b) => order[a.status] - order[b.status]);
  return areas;
}

export const LIMITATIONS = {
  en: [
    'Static analysis shows what code and strings are in the file, not what runs. An SDK can be present but inactive.',
    'Obfuscated or encrypted code can hide SDKs. Detection depends on the knowledge base, which is an unverified starter seed.',
    'Endpoint hosts are strings found in the file. No traffic was captured, so we cannot say which hosts the app contacts or what data it sends.',
    'A domain operator (for example a cloud provider) does not establish where data is stored or processed.',
    'Certificates are read but signatures are not verified.',
    'iOS apps from the App Store have encrypted executables (FairPlay); SDKs linked statically into them can be missed. Installers whose payload is compressed (NSIS, Inno, 7z, MSI cabinets, pkg payloads, DMG) are only string-scanned.',
    'Risk areas are draft, not expert-reviewed, and do not say whether any law applies. Ownership, user counts, contracts and runtime behavior decide that.',
  ],
  zh: [
    '静态分析显示文件中有哪些代码和字符串，而不是实际运行的内容。SDK 可能存在但未启用。',
    '经过混淆或加密的代码可能隐藏 SDK。检测依赖知识库，而知识库目前是未经核验的初始数据。',
    '接口主机是在文件中发现的字符串。本次未抓取流量，因此无法确定应用会访问哪些主机或发送哪些数据。',
    '域名运营方（例如云服务商）不能说明数据存储或处理的地点。',
    '本工具读取证书，但不校验签名。',
    'App Store 下载的 iOS 应用可执行文件经过加密（FairPlay），静态链接的 SDK 可能被遗漏。载荷经压缩的安装包（NSIS、Inno、7z、MSI CAB、pkg 载荷、DMG）仅做字符串扫描。',
    '风险领域为草稿，未经专家审核，也不判断任何法律是否适用；这取决于股权结构、用户规模、合同和运行时行为。',
  ],
};
