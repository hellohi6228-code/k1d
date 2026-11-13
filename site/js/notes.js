// "Why this may matter" notes. Each note pairs an observation (fact from the file)
// with the rule area it may relate to. Draft, not expert-reviewed. No verdicts and no
// legal thresholds: those require reviewed rule data (see docs/ARCHITECTURE.md §8).

const TRACKING = new Set(['ads', 'analytics', 'attribution']);

export function buildNotes(result, context, policy) {
  const notes = [];
  const cnSdks = result.sdks.filter((s) => s.cnNexus);
  const cnHosts = result.endpoints.filter((e) => e.cnIndicators.length);
  const certCn = result.cert?.subject?.C === 'CN';
  const tracking = result.sdks.filter((s) => TRACKING.has(s.category));
  const perm = (n) => result.permissions.some((p) => p.name === n);

  if (cnSdks.length || cnHosts.length || certCn) {
    notes.push({
      id: 'dsp',
      citation: '28 C.F.R. Part 202 (DOJ Data Security Program, implementing E.O. 14117)',
      observation: {
        en: `${cnSdks.length} SDK(s) and ${cnHosts.length} endpoint host(s) carry China-nexus indicators${certCn ? '; the signing certificate subject country field is CN' : ''}.`,
        zh: `${cnSdks.length} 个 SDK 和 ${cnHosts.length} 个接口主机带有中国关联指标${certCn ? '；签名证书主体的国家字段为 CN' : ''}。`,
      },
      why: {
        en: 'Transfers of certain categories of U.S. persons\' data to countries of concern or covered persons are the subject of the DOJ Data Security Program. Whether it is relevant depends on facts this scan does not establish: which data is actually sent, to whom, in what volume, and under what agreements.',
        zh: '美国司法部《数据安全计划》涉及将特定类别的美国人数据传输给受关注国家或受管辖主体的情形。是否相关取决于本次扫描无法确定的事实：实际发送了哪些数据、发送给谁、数量多少以及依据何种协议。',
      },
    });
  }

  if (context.childDirected && tracking.length) {
    notes.push({
      id: 'coppa',
      citation: '16 C.F.R. Part 312 (FTC COPPA Rule, as amended)',
      observation: {
        en: `The app is marked as child-directed or mixed-audience, and the file contains ${tracking.length} advertising, analytics or attribution SDK(s): ${tracking.map((s) => s.name.en).join(', ')}.`,
        zh: `该应用被标记为面向儿童或混合受众，且文件中包含 ${tracking.length} 个广告、统计或归因 SDK：${tracking.map((s) => s.name.zh).join('、')}。`,
      },
      why: {
        en: 'The COPPA Rule addresses collection of personal information, including persistent identifiers, from children by operators and by third parties integrated into their services. Runtime testing (for example, what is sent before an age gate or consent) is needed to know what these SDKs actually collect.',
        zh: 'COPPA 规则涉及运营者及其集成的第三方从儿童处收集个人信息（包括持久标识符）的情形。需要进行运行时测试（例如年龄门槛或同意之前发送了什么），才能了解这些 SDK 实际收集的内容。',
      },
    });
  }

  if (perm('com.android.vending.BILLING') || result.sdks.some((s) => s.id === 'google_play_billing')) {
    notes.push({
      id: 'arl',
      citation: 'Cal. Bus. & Prof. Code § 17600 et seq. (California Automatic Renewal Law) and similar state laws',
      observation: {
        en: 'The app includes Google Play Billing, so it can sell in-app purchases and possibly subscriptions.',
        zh: '该应用包含 Google Play 结算，可以销售应用内购买项目，并可能销售订阅。',
      },
      why: {
        en: 'If the app sells auto-renewing subscriptions, the paywall disclosures (price, billing period, renewal terms, cancellation) are a topic under automatic-renewal laws. This static scan does not look at paywall screens.',
        zh: '如果应用销售自动续订的订阅，付费墙披露（价格、计费周期、续订条款、取消方式）是自动续订相关法律关注的内容。本次静态扫描不检查付费墙页面。',
      },
    });
  }

  if (context.category === 'video' && tracking.length) {
    notes.push({
      id: 'vppa',
      citation: '18 U.S.C. § 2710 (Video Privacy Protection Act)',
      observation: {
        en: `This is a video/short-drama app with ${tracking.length} advertising, analytics or attribution SDK(s).`,
        zh: `这是一款视频/短剧应用，包含 ${tracking.length} 个广告、统计或归因 SDK。`,
      },
      why: {
        en: 'VPPA claims often concern sharing video-viewing information together with a persistent user or device identifier with third parties. Runtime capture is needed to see whether requests contain both.',
        zh: 'VPPA 相关主张通常涉及将视频观看信息与持久的用户或设备标识符一起分享给第三方。需要运行时抓包才能看到请求中是否同时包含两者。',
      },
    });
  }

  if (policy) {
    const missingSdks = policy.sdkChecks.filter((c) => !c.match);
    const missingCats = policy.categoryChecks.filter((c) => !c.match);
    const usStorage = policy.statements.filter((s) => s.kind === 'us_storage');
    if (missingSdks.length || missingCats.length) {
      notes.push({
        id: 'disclosure',
        citation: 'State consumer-protection (UDAP) and consumer-privacy statutes; FTC Act § 5 (15 U.S.C. § 45)',
        observation: {
          en: `The privacy policy text does not name ${missingSdks.length} detected SDK/vendor(s) (${missingSdks.map((s) => s.name.en).join(', ') || '—'}) and does not mention ${missingCats.length} permission data categor(ies) (${missingCats.map((c) => c.label.en).join(', ') || '—'}).`,
          zh: `隐私政策文本未提及 ${missingSdks.length} 个检测到的 SDK/提供方（${missingSdks.map((s) => s.name.zh).join('、') || '—'}），也未提及 ${missingCats.length} 个权限数据类别（${missingCats.map((c) => c.label.zh).join('、') || '—'}）。`,
        },
        why: {
          en: 'Differences between what an app contains or does and what its disclosures say are the kind of fact regulators and state attorneys general have relied on. A name missing from the text is not by itself a discrepancy: general wording may cover it, and the SDK may be inactive.',
          zh: '应用包含或实际执行的内容与其披露内容之间的差异，是监管机构和州检察长曾经援引的事实类型。文本中缺少某个名称本身并不构成差异：概括性表述可能已涵盖，且该 SDK 可能并未启用。',
        },
      });
    }
    if (usStorage.length && (cnSdks.length || cnHosts.length)) {
      notes.push({
        id: 'storage_statement',
        citation: 'State consumer-protection (UDAP) statutes; FTC Act § 5 (15 U.S.C. § 45)',
        observation: {
          en: `The policy says: “${usStorage[0].text}” The file also contains SDKs or endpoints with China-nexus indicators.`,
          zh: `政策称：“${usStorage[0].text}” 同时文件中包含带有中国关联指标的 SDK 或接口地址。`,
        },
        why: {
          en: 'Where data is stored and who can access it is a frequent subject of statements in policies of China-linked apps. Runtime capture with IP/ASN enrichment is needed to see where data is actually sent.',
          zh: '数据存储地点及谁可访问，是中国关联应用隐私政策中常见的表述内容。需要结合 IP/ASN 信息的运行时抓包，才能确认数据实际发送到何处。',
        },
      });
    }
  }

  if (result.manifest.application.usesCleartextTraffic || result.endpoints.some((e) => e.cleartext)) {
    notes.push({
      id: 'cleartext',
      citation: null,
      observation: {
        en: `Cleartext traffic is ${result.manifest.application.usesCleartextTraffic ? 'allowed in the manifest' : 'not enabled in the manifest'}; ${result.endpoints.filter((e) => e.cleartext).length} host(s) appear with http:// or ws:// URLs.`,
        zh: `清单中${result.manifest.application.usesCleartextTraffic ? '允许' : '未开启'}明文流量；有 ${result.endpoints.filter((e) => e.cleartext).length} 个主机以 http:// 或 ws:// URL 形式出现。`,
      },
      why: {
        en: 'Data sent over unencrypted connections can be read by anyone on the network path. This is a security observation, not tied to a specific rule.',
        zh: '通过未加密连接发送的数据可被网络路径上的任何人读取。这是安全方面的观察，并非针对特定规则。',
      },
    });
  }

  return notes;
}

export const LIMITATIONS = {
  en: [
    'Static analysis shows what code and strings are in the file, not what runs. An SDK can be present but inactive.',
    'Obfuscated or renamed code can hide SDKs. Detection depends on the knowledge base, which is an unverified starter seed.',
    'Endpoint hosts are strings found in the file. No traffic was captured, so we cannot say which hosts the app contacts or what data it sends.',
    'A domain operator (for example a cloud provider) does not establish where data is stored or processed.',
    'The signing certificate is read but its signature is not verified.',
    'Not assessed in this version: runtime behavior before and after consent or age gates, use of platform age-signal APIs, paywall screens, ownership chains beyond the vendor named in the knowledge base.',
  ],
  zh: [
    '静态分析显示文件中有哪些代码和字符串，而不是实际运行的内容。SDK 可能存在但未启用。',
    '经过混淆或重命名的代码可能隐藏 SDK。检测依赖知识库，而知识库目前是未经核验的初始数据。',
    '接口主机是在文件中发现的字符串。本次未抓取流量，因此无法确定应用会访问哪些主机或发送哪些数据。',
    '域名运营方（例如云服务商）不能说明数据存储或处理的地点。',
    '本工具读取签名证书，但不校验签名。',
    '本版本未评估：同意或年龄门槛前后的运行时行为、平台年龄信号 API 的使用、付费墙页面，以及知识库所列提供方之外的所有权链条。',
  ],
};
