// Automatic app profile: what kind of app this is, who its likely audience is, and (for network
// captures) when the consent screen appeared. Everything here is inferred from the file; each
// conclusion carries the evidence it rests on so a reader can check it. No user input.

const S = (en, zh) => ({ en, zh });

// Operating-system traffic commonly seen in captures (not the app).
export const SYSTEM_HOSTS = /(^|\.)(gstatic\.com|android\.apis\.google\.com|play\.googleapis\.com|android\.clients\.google\.com|connectivitycheck\.[a-z.]+|mtalk\.google\.com|time\.android\.com|googleapis\.com|apple\.com|icloud\.com|mzstatic\.com|msftconnecttest\.com|windowsupdate\.com)$/;

// Android android:appCategory enum (R.attr.appCategory)
const ANDROID_APP_CATEGORY = ['game', 'audio', 'video', 'image', 'social', 'news', 'maps', 'productivity', 'accessibility'];
const ANDROID_TO_CTX = { game: 'game', video: 'video', social: 'social', audio: 'other', image: 'other', news: 'other', maps: 'utility', productivity: 'utility', accessibility: 'utility' };

// Words are matched at the start of identifier tokens (com.block.juggle → "block"), so "edu"
// does not match "schedule". CJK terms are matched anywhere.
const KEYWORDS = [
  ['casino', 'slot|casino|poker|bingo|jackpot|vegas|blackjack|roulette', /老虎机|棋牌/],
  ['video', 'drama|video|movie|reels|shorttv', /短剧|视频|影视/],
  ['social', 'chat|dating|social|meetup|livestream', /直播|交友/],
  ['health', 'fitness|health|workout|period|pregnan|diet', /健康|运动/],
  ['education', 'learn|school|edu|math|phonics|homework', /学习|教育/],
  ['ecommerce', 'shop|mall|deals', /购物|商城/],
  ['game', 'game|puzzle|block|match3|solitaire|mahjong|sudoku', /游戏/],
].map(([id, words, cjk]) => [id, new RegExp(`^(?:${words})`), cjk]);
const KIDS = [new RegExp('^(?:kid|baby|babies|toddler|preschool|kindergarten|nursery)'), /儿童|宝宝|幼儿|少儿/];
const keywordHit = (ident, [re, cjk]) => {
  for (const t of ident.toLowerCase().split(/[^a-z0-9]+/)) if (t && re.test(t)) return t;
  return ident.match(cjk)?.[0] ?? null;
};
const KIDS_SDKS = new Set(['superawesome', 'kidoz']);
const GAME_SDKS = new Set(['unity_engine', 'cocos_engine', 'steamworks', 'epic_eos', 'taptap', 'discord_game_sdk', 'easy_anticheat', 'battleye', 'tencent_anticheat']);
const VOD = new Set(['tencent_liteav', 'aliyun_player', 'bytedance_ttvideo', 'ijkplayer']);

// Google Analytics for Firebase consent-mode and collection defaults set in AndroidManifest.xml
const GA_DEFAULTS = {
  google_analytics_default_allow_ad_storage: 'ad storage',
  google_analytics_default_allow_ad_user_data: 'ad user data',
  google_analytics_default_allow_ad_personalization_signals: 'ad personalization',
  google_analytics_default_allow_analytics_storage: 'analytics storage',
};
const GA_COLLECTION = {
  firebase_analytics_collection_enabled: 'Analytics collection',
  google_analytics_adid_collection_enabled: 'advertising ID collection',
  google_analytics_ssaid_collection_enabled: 'Android ID (SSAID) collection',
};

export function inferProfile(r) {
  const sdkIds = new Set(r.sdks.map((s) => s.id));
  const sdkNames = (pred) => r.sdks.filter(pred).map((s) => s.name.en);
  const meta = new Map((r.android?.metaData ?? []).map((m) => [m.name, String(m.value)]));
  const ident = [r.app?.id, r.app?.name, r.ios?.storeMetadata?.itemName].filter(Boolean).join(' ');

  // ── Category
  const votes = [];
  const vote = (id, strength, en, zh) => votes.push({ id, strength, basis: S(en, zh) });
  const ac = r.android?.application?.appCategory;
  if (ac != null) {
    const name = typeof ac === 'number' ? ANDROID_APP_CATEGORY[ac] : String(ac);
    if (ANDROID_TO_CTX[name]) vote(ANDROID_TO_CTX[name], 3, `The manifest declares appCategory="${name}".`, `清单声明 appCategory="${name}"。`);
  }
  if (r.android?.application?.isGame) vote('game', 3, 'The manifest declares isGame="true".', '清单声明 isGame="true"。');
  const lsCat = r.ios?.appCategory;
  if (lsCat) {
    const c = /games/.test(lsCat) ? 'game' : /education/.test(lsCat) ? 'education' : /health|medical/.test(lsCat) ? 'health' : /social/.test(lsCat) ? 'social' : /video|entertainment/.test(lsCat) ? 'video' : /shopping/.test(lsCat) ? 'ecommerce' : null;
    if (c) vote(c, 3, `Info.plist declares ${lsCat}.`, `Info.plist 声明 ${lsCat}。`);
  }
  const genre = r.ios?.storeMetadata?.genre;
  if (genre && /game/i.test(genre)) vote('game', 3, `App Store genre: ${genre}.`, `App Store 类别：${genre}。`);
  const engines = sdkNames((s) => GAME_SDKS.has(s.id));
  if (engines.length) vote('game', 2, `Game engine / game services: ${engines.join(', ')}.`, `游戏引擎/游戏服务：${engines.join('、')}。`);
  if (meta.has('com.google.android.gms.games.APP_ID')) vote('game', 2, 'Registers with Google Play Games services.', '接入 Google Play 游戏服务。');
  const ai = sdkNames((s) => s.category === 'ai');
  if (ai.length) vote('ai', 2, `AI model APIs: ${ai.join(', ')}.`, `AI 模型 API：${ai.join('、')}。`);
  const vod = sdkNames((s) => VOD.has(s.id));
  if (vod.length) vote('video', 2, `Video-on-demand player: ${vod.join(', ')}.`, `点播播放器：${vod.join('、')}。`);
  if ((r.permissions ?? []).some((p) => p.category === 'health')) vote('health', 2, 'Requests health / fitness data access.', '请求健康/运动数据访问。');
  for (const [id, re, cjk] of KEYWORDS) {
    const m = keywordHit(ident, [re, cjk]);
    if (m) { vote(id, id === 'casino' ? 3 : 1, `The app identifier/name contains "${m}".`, `应用标识/名称包含“${m}”。`); break; }
  }
  if (r.traffic) {
    const gh = r.traffic.hosts.filter((h) => h.flows > 0 && !SYSTEM_HOSTS.test(h.host) && /(^|[.-])game/i.test(h.host)).map((h) => h.host);
    if (gh.length) vote('game', 1, `Contacted hosts named for games: ${gh.slice(0, 3).join(', ')}.`, `连接了以游戏命名的主机：${gh.slice(0, 3).join('、')}。`);
  }
  const score = {};
  for (const v of votes) score[v.id] = (score[v.id] ?? 0) + v.strength;
  // Social casino beats game: casino apps are games too.
  let category = 'other';
  let best = 0;
  for (const [id, n] of Object.entries(score)) if (n > best || (n === best && id === 'casino')) { category = id; best = n; }
  if (score.casino && score.game) category = 'casino';
  const categoryBasis = votes.filter((v) => v.id === category).map((v) => v.basis);

  // ── Audience
  const audienceBasis = [];
  let audience = 'general';
  const kidsSdks = sdkNames((s) => KIDS_SDKS.has(s.id) || s.category === 'kids-ads');
  if (kidsSdks.length) { audience = 'child'; audienceBasis.push(S(`Ad SDK built for children's apps: ${kidsSdks.join(', ')}.`, `面向儿童应用的广告 SDK：${kidsSdks.join('、')}。`)); }
  if (lsCat && /kids/.test(lsCat)) { audience = 'child'; audienceBasis.push(S(`Info.plist declares ${lsCat}.`, `Info.plist 声明 ${lsCat}。`)); }
  const km = keywordHit(ident, KIDS);
  if (km) { audience = 'child'; audienceBasis.push(S(`The app identifier/name contains "${km}".`, `应用标识/名称包含“${km}”。`)); }
  const rating = r.ios?.storeMetadata?.rating;
  if (rating) audienceBasis.push(S(`App Store age rating: ${rating}.`, `App Store 年龄分级：${rating}。`));
  if (audience === 'general' && ['game', 'education'].includes(category)) {
    audience = 'mixed';
    audienceBasis.push(S(`${category === 'game' ? 'Games' : 'Education apps'} commonly have child and teen users unless they gate by age.`, `${category === 'game' ? '游戏' : '教育应用'}通常有儿童和青少年用户，除非设置了年龄门槛。`));
  }

  // ── Consent defaults declared in the manifest
  const granted = Object.entries(GA_DEFAULTS).filter(([k]) => meta.get(k) === 'true').map(([, v]) => v);
  const denied = Object.entries(GA_DEFAULTS).filter(([k]) => meta.get(k) === 'false').map(([, v]) => v);
  const collection = Object.entries(GA_COLLECTION).filter(([k]) => meta.get(k) === 'true').map(([, v]) => v);

  // ── Consent moment in a capture: first contact with a consent-management service
  let consent = null;
  if (r.traffic) {
    const cmp = r.sdks.filter((s) => s.category === 'consent');
    const cmpHosts = new Set(cmp.flatMap((s) => s.evidence.filter((e) => e.type === 'traffic').flatMap((e) => e.samples)));
    const firstCmp = r.traffic.hosts.filter((h) => cmpHosts.has(h.host) && h.relFirst != null).sort((a, b) => a.relFirst - b.relFirst)[0];
    const appHosts = r.traffic.hosts.filter((h) => h.flows > 0 && h.relFirst != null && !SYSTEM_HOSTS.test(h.host));
    const appStart = appHosts.length ? Math.min(...appHosts.map((h) => h.relFirst)) : null;
    consent = {
      at: firstCmp?.relFirst ?? null,
      service: firstCmp ? cmp.find((s) => s.evidence.some((e) => e.samples.includes(firstCmp.host)))?.name.en ?? firstCmp.host : null,
      host: firstCmp?.host ?? null,
      appStart,
    };
  }

  return { category, categoryBasis, audience, audienceBasis, gaDefaults: { granted, denied, collection }, consent };
}
