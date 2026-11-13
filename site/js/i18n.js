// UI strings, English and Simplified Chinese.
// Never use verdict language here (see scripts/check-claims.mjs).

export const STRINGS = {
  en: {
    tagline: 'Static evidence about Android apps',
    heroTitle: "What's inside this Android app?",
    heroBody: 'Find embedded SDKs, sensitive permissions, hard-coded endpoints and China-nexus indicators in an APK, then compare them with the privacy policy. The analysis runs in your browser. The file is never uploaded.',
    dropTitle: 'Drop an APK, XAPK or APKS file here',
    dropOr: 'or',
    chooseFile: 'Choose file',
    tryDemo: 'Try the synthetic demo APK',
    demoNote: 'The demo is a small fake app built for testing. It is not a real product.',
    privacyNote: 'Nothing leaves this device. There is no server: this page is static and the file is read locally.',

    authTitle: 'Authorize analysis',
    authIntro: 'Before analysis, confirm you have the right to analyze this app.',
    scopeTitle: 'Scope of this authorization',
    scopeFile: 'File',
    scopeSize: 'Size',
    scopeTechniques: 'Techniques',
    scopeTechniquesValue: 'Static analysis of the file contents, in this browser only. No dynamic analysis, traffic interception or instrumentation.',
    scopeValidity: 'Validity',
    scopeValidityValue: 'This session only',
    termsTitle: 'Authorization & Testing Terms',
    yourName: 'Your name',
    yourRole: 'Your role / title',
    yourOrg: 'Organization',
    consentCheckbox: 'I confirm that I own this app, or that I am authorized by the organization that owns or controls it, to have it analyzed, and I accept the Authorization & Testing Terms (version {v}).',
    consentButton: 'I agree and authorize analysis of {file}',
    cancel: 'Cancel',
    fillFields: 'Enter your name, role and organization, and tick the box to continue.',

    analyzing: 'Analyzing…',
    step_open: 'Reading archive',
    step_dex: 'Reading code ({i}/{n})',
    step_resources: 'Reading resources',
    step_native: 'Scanning native libraries',
    step_split: 'Reading split APK',
    step_detect: 'Matching against knowledge base',
    step_hash: 'Computing file hash',

    err_NOT_A_ZIP: 'This file is not an APK (it is not a ZIP archive).',
    err_NO_MANIFEST: 'No AndroidManifest.xml was found. Is this an Android app?',
    err_AAB_UNSUPPORTED: 'Android App Bundles (.aab) are not supported yet. Export a universal APK (for example with bundletool) and try again.',
    err_generic: 'The analysis stopped with an error: {msg}',
    startOver: 'Analyze another file',

    summaryTitle: 'Summary',
    package: 'Package',
    version: 'Version',
    sdkCount: 'SDKs detected',
    cnCount: 'With China-nexus indicators',
    permCount: 'Sensitive permissions',
    endpointCount: 'Endpoint hosts',
    fileHash: 'File SHA-256',
    notComputed: 'not computed (file larger than 512 MB)',
    analyzedIn: 'Analyzed in {s} s · analyzer {v} · knowledge base {kb}',

    tab_sdks: 'SDKs',
    tab_permissions: 'Permissions',
    tab_endpoints: 'Endpoints',
    tab_manifest: 'Manifest & signing',
    tab_policy: 'Privacy policy check',
    tab_notes: 'Why this may matter',
    tab_export: 'Export',

    kbSeedBanner: 'Knowledge base: unverified starter seed. Signatures come from public package names and still need expert review.',
    colSdk: 'SDK',
    colVendor: 'Vendor',
    colCategory: 'Category',
    colConfidence: 'Confidence',
    colCnNexus: 'China-nexus indicator',
    colEvidence: 'Evidence',
    noSdks: 'No SDKs from the knowledge base were found. Code may be obfuscated, or the SDKs are not in the knowledge base yet.',
    codePresentNote: 'Detection means the code is in the file. It does not show that the SDK runs or sends data.',
    evidence_code: '{n} class(es) under {sig}',
    evidence_native: 'Native library {sig}',
    evidence_manifest: 'Manifest key {sig}',
    evidence_config_key: 'Config key string {sig}',
    evidence_domain: 'Endpoint domain {sig}',

    colPermission: 'Permission',
    colDataCategory: 'Data category',
    colLevel: 'Sensitivity',
    otherPermissions: 'Other permissions',

    colHost: 'Host',
    colOperator: 'Operator / indicator',
    colFoundIn: 'Found in',
    colExample: 'Example URL',
    endpointsNote: 'Hosts are hard-coded strings found in code, resources, assets and native libraries. Presence does not show that the app contacts them, and a domain operator does not show where data is stored.',
    cleartext: 'cleartext',
    ipLiteral: 'IP address',
    noEndpoints: 'No URLs were found in the file.',
    showAll: 'Show all {n}',

    signingTitle: 'Signing certificate',
    certScheme: 'Signature scheme',
    certSha: 'Certificate SHA-256',
    certSubject: 'Subject',
    certIssuer: 'Issuer',
    certValidity: 'Valid',
    certNote: 'k1d reads the certificate but does not verify the signature.',
    noCert: 'No signing certificate found.',
    appFlags: 'Application flags',
    flag_usesCleartextTraffic: 'Cleartext (HTTP) traffic allowed',
    flag_allowBackup: 'Backup allowed',
    flag_debuggable: 'Debuggable',
    flag_networkSecurityConfig: 'Network security config',
    exportedComponents: 'Exported components ({n} of {total})',
    metaData: 'Manifest meta-data',
    queries: 'Package visibility queries',
    configKeys: 'Config key names in code',
    nativeLibs: 'Native libraries',
    minTarget: 'min SDK {min} · target SDK {target}',
    yes: 'yes',
    no: 'no',
    notSet: 'not set',

    policyIntro: 'Paste the app\'s privacy policy (EN or ZH). k1d looks for each detected SDK/vendor and each permission data category in the text, and shows the matching excerpt so you can check it.',
    policyPlaceholder: 'Paste privacy policy text here…',
    policyCheck: 'Check policy',
    policyDemo: 'Load demo policy',
    policySdkTitle: 'Detected SDKs and vendors',
    policyCatTitle: 'Data categories from permissions',
    policyStatementsTitle: 'Statements about location of storage or transfers',
    found: 'Named in policy',
    notFound: 'Not found in policy text',
    excerpt: 'Excerpt',
    noStatements: 'No sentences about storage location or international transfers were found.',
    policyLimit: 'Text matching only. A name that does not appear may still be covered by general wording. Review each item yourself.',

    notesBanner: 'DRAFT – NOT EXPERT-REVIEWED. These notes link observations to rules for discussion with your own advisers. They are not legal advice and do not say whether any law applies.',
    contextTitle: 'App context (used for the notes below)',
    category: 'Category',
    cat_game: 'Game', cat_video: 'Video / short drama', cat_ai: 'AI assistant', cat_utility: 'Utility / VPN', cat_ecommerce: 'E-commerce', cat_other: 'Other',
    childDirected: 'The app is directed to children, or has a mixed audience that includes children',
    observation: 'Observation',
    whyMatters: 'Why this may matter',
    noNotes: 'No notes for the current observations and context.',
    limitationsTitle: 'Methodology and limits',

    exportIntro: 'Download the full result, including your authorization record, or print it to PDF.',
    downloadJson: 'Download JSON',
    print: 'Print / save as PDF',
    consentRecord: 'Authorization record',
    consentAt: 'Accepted at',

    disclaimer: 'k1d provides factual analysis, not legal advice, and no attorney-client relationship is created. Results show what is present in the file you provided; they do not establish what the app does at runtime or whether any law applies.',

    sev_high: 'high', sev_medium: 'medium', sev_low: 'low',
    conf_high: 'high', conf_medium: 'medium', conf_low: 'low',
    category_analytics: 'Analytics', category_ads: 'Advertising', category_attribution: 'Attribution', category_push: 'Push', category_crash: 'Crash reporting', category_payments: 'Payments', 'category_social-login': 'Social login', 'category_anti-fraud': 'Anti-fraud / anti-cheat', 'category_game-services': 'Game services', category_engine: 'Engine', category_other: 'Other',
  },

  zh: {
    tagline: 'Android 应用静态证据',
    heroTitle: '这个 Android 应用里有什么？',
    heroBody: '找出 APK 中嵌入的 SDK、敏感权限、硬编码的接口地址和中国关联指标，并与隐私政策进行对照。分析在浏览器中完成，文件不会被上传。',
    dropTitle: '将 APK、XAPK 或 APKS 文件拖到此处',
    dropOr: '或',
    chooseFile: '选择文件',
    tryDemo: '使用合成演示 APK',
    demoNote: '演示文件是为测试而构建的小型虚构应用，并非真实产品。',
    privacyNote: '数据不会离开本设备。本页面是静态页面，没有服务器，文件仅在本地读取。',

    authTitle: '授权分析',
    authIntro: '开始分析前，请确认您有权分析该应用。',
    scopeTitle: '本次授权范围',
    scopeFile: '文件',
    scopeSize: '大小',
    scopeTechniques: '分析方式',
    scopeTechniquesValue: '仅在本浏览器中对文件内容进行静态分析。不进行动态分析、流量拦截或插桩。',
    scopeValidity: '有效期',
    scopeValidityValue: '仅限本次会话',
    termsTitle: '授权与测试条款',
    yourName: '您的姓名',
    yourRole: '您的职务',
    yourOrg: '所属机构',
    consentCheckbox: '我确认本人拥有该应用，或已获得拥有或控制该应用的机构授权对其进行分析，并接受《授权与测试条款》（版本 {v}）。',
    consentButton: '我同意并授权分析 {file}',
    cancel: '取消',
    fillFields: '请填写姓名、职务和所属机构，并勾选确认框后继续。',

    analyzing: '正在分析…',
    step_open: '读取压缩包',
    step_dex: '读取代码（{i}/{n}）',
    step_resources: '读取资源',
    step_native: '扫描原生库',
    step_split: '读取拆分 APK',
    step_detect: '与知识库比对',
    step_hash: '计算文件哈希',

    err_NOT_A_ZIP: '该文件不是 APK（不是 ZIP 压缩包）。',
    err_NO_MANIFEST: '未找到 AndroidManifest.xml。这是 Android 应用吗？',
    err_AAB_UNSUPPORTED: '暂不支持 Android App Bundle（.aab）。请导出通用 APK（例如使用 bundletool）后重试。',
    err_generic: '分析因错误中止：{msg}',
    startOver: '分析其他文件',

    summaryTitle: '概要',
    package: '包名',
    version: '版本',
    sdkCount: '检测到的 SDK',
    cnCount: '带有中国关联指标',
    permCount: '敏感权限',
    endpointCount: '接口主机',
    fileHash: '文件 SHA-256',
    notComputed: '未计算（文件大于 512 MB）',
    analyzedIn: '用时 {s} 秒 · 分析器 {v} · 知识库 {kb}',

    tab_sdks: 'SDK',
    tab_permissions: '权限',
    tab_endpoints: '接口地址',
    tab_manifest: '清单与签名',
    tab_policy: '隐私政策对照',
    tab_notes: '可能的关注点',
    tab_export: '导出',

    kbSeedBanner: '知识库：未经核验的初始数据。特征来自公开包名，仍需专家审核。',
    colSdk: 'SDK',
    colVendor: '提供方',
    colCategory: '类别',
    colConfidence: '置信度',
    colCnNexus: '中国关联指标',
    colEvidence: '证据',
    noSdks: '未发现知识库中的 SDK。代码可能经过混淆，或这些 SDK 尚未收录。',
    codePresentNote: '检测到表示文件中存在该代码，不代表该 SDK 一定运行或发送数据。',
    evidence_code: '{sig} 下的 {n} 个类',
    evidence_native: '原生库 {sig}',
    evidence_manifest: '清单键 {sig}',
    evidence_config_key: '配置键字符串 {sig}',
    evidence_domain: '接口域名 {sig}',

    colPermission: '权限',
    colDataCategory: '数据类别',
    colLevel: '敏感度',
    otherPermissions: '其他权限',

    colHost: '主机',
    colOperator: '运营方 / 指标',
    colFoundIn: '出现位置',
    colExample: '示例 URL',
    endpointsNote: '主机来自代码、资源、assets 和原生库中的硬编码字符串。出现不代表应用会访问它们；域名运营方也不能说明数据存储在何处。',
    cleartext: '明文',
    ipLiteral: 'IP 地址',
    noEndpoints: '文件中未发现 URL。',
    showAll: '显示全部 {n} 项',

    signingTitle: '签名证书',
    certScheme: '签名方案',
    certSha: '证书 SHA-256',
    certSubject: '主体',
    certIssuer: '颁发者',
    certValidity: '有效期',
    certNote: 'k1d 读取证书，但不校验签名。',
    noCert: '未找到签名证书。',
    appFlags: '应用标志',
    flag_usesCleartextTraffic: '允许明文（HTTP）流量',
    flag_allowBackup: '允许备份',
    flag_debuggable: '可调试',
    flag_networkSecurityConfig: '网络安全配置',
    exportedComponents: '导出组件（{total} 个中的 {n} 个）',
    metaData: '清单 meta-data',
    queries: '软件包可见性查询',
    configKeys: '代码中的配置键名',
    nativeLibs: '原生库',
    minTarget: '最低 SDK {min} · 目标 SDK {target}',
    yes: '是',
    no: '否',
    notSet: '未设置',

    policyIntro: '粘贴该应用的隐私政策（中文或英文）。k1d 会在文本中查找每个检测到的 SDK/提供方以及权限对应的数据类别，并显示匹配片段供您核对。',
    policyPlaceholder: '在此粘贴隐私政策文本…',
    policyCheck: '对照政策',
    policyDemo: '载入演示政策',
    policySdkTitle: '检测到的 SDK 与提供方',
    policyCatTitle: '权限对应的数据类别',
    policyStatementsTitle: '关于存储地点或跨境传输的表述',
    found: '政策中已提及',
    notFound: '政策文本中未找到',
    excerpt: '摘录',
    noStatements: '未找到关于存储地点或跨境传输的语句。',
    policyLimit: '仅为文本匹配。未出现的名称仍可能被概括性表述覆盖，请逐项自行核对。',

    notesBanner: '草稿 – 未经专家审核。以下说明将观察结果与相关规则联系起来，供您与自己的顾问讨论。它们不是法律意见，也不判断任何法律是否适用。',
    contextTitle: '应用背景（用于下方说明）',
    category: '类别',
    cat_game: '游戏', cat_video: '视频 / 短剧', cat_ai: 'AI 助手', cat_utility: '工具 / VPN', cat_ecommerce: '电商', cat_other: '其他',
    childDirected: '该应用面向儿童，或受众中包含儿童',
    observation: '观察',
    whyMatters: '可能的关注点',
    noNotes: '根据当前观察结果和背景，暂无说明。',
    limitationsTitle: '方法与局限',

    exportIntro: '下载完整结果（含您的授权记录），或打印为 PDF。',
    downloadJson: '下载 JSON',
    print: '打印 / 另存为 PDF',
    consentRecord: '授权记录',
    consentAt: '接受时间',

    disclaimer: 'k1d 提供事实分析，不构成法律意见，也不建立律师与客户关系。结果仅说明您提供的文件中存在的内容，不能确定应用运行时的行为，也不判断任何法律是否适用。',

    sev_high: '高', sev_medium: '中', sev_low: '低',
    conf_high: '高', conf_medium: '中', conf_low: '低',
    category_analytics: '统计分析', category_ads: '广告', category_attribution: '归因', category_push: '推送', category_crash: '崩溃报告', category_payments: '支付', 'category_social-login': '社交登录', 'category_anti-fraud': '风控 / 反作弊', 'category_game-services': '游戏服务', category_engine: '引擎', category_other: '其他',
  },
};

export const TERMS_VERSION = '1-draft';

export const TERMS = {
  en: `k1d Authorization & Testing Terms — version 1 (draft)

1. Authority. You represent that you own the app contained in the selected file, or that you are authorized by the organization that owns or controls it to have it analyzed.

2. Scope. This authorization covers static analysis of the selected file only: reading its manifest, code identifiers, embedded strings, resource strings, native library names and signing certificate. No dynamic analysis, network interception or instrumentation is performed.

3. Local processing. The analysis runs in your browser. The file is not uploaded to k1d or to anyone else.

4. Nature of output. Output is factual analysis, not legal advice, and creates no attorney-client relationship. It reports what is present in the file. It does not determine what the app does at runtime or whether any law applies, and it promises no regulatory outcome.

5. Your responsibilities. Do not analyze apps you are not authorized to analyze. You are responsible for the accuracy of any facts you enter and for decisions you make based on the output.

6. Revocation. You can stop at any time by closing this page. Nothing is kept after you close it unless you export it.`,
  zh: `k1d 授权与测试条款 — 版本 1（草稿）

1. 授权。您声明您拥有所选文件中的应用，或已获得拥有或控制该应用的机构授权对其进行分析。

2. 范围。本授权仅涵盖对所选文件的静态分析：读取其清单、代码标识符、内嵌字符串、资源字符串、原生库名称和签名证书。不进行动态分析、网络拦截或插桩。

3. 本地处理。分析在您的浏览器中运行，文件不会上传给 k1d 或任何第三方。

4. 输出性质。输出为事实分析，不构成法律意见，也不建立律师与客户关系。它仅报告文件中存在的内容，不判断应用运行时的行为或任何法律是否适用，也不承诺任何监管结果。

5. 您的责任。请勿分析您未获授权分析的应用。您对所输入事实的准确性以及基于输出所作的决定负责。

6. 撤回。您可以随时关闭本页面以停止。除非您导出结果，关闭后不会保留任何内容。`,
};

export function t(lang, key, vars = {}) {
  const s = STRINGS[lang]?.[key] ?? STRINGS.en[key] ?? key;
  return s.replace(/\{(\w+)\}/g, (_, k) => (vars[k] ?? `{${k}}`));
}
