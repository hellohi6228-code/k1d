// Publishers page: plans, what paid adds, how buying works, CI setup. EN / ZH.
import { CONFIG } from './config.js';

const C = {
  en: {
    tagline: 'For app publishers',
    title: 'Check every release before your users, regulators or plaintiffs do',
    lead: 'The free k1d tool shows anyone what your app contains. The paid plans make that a routine part of shipping: every build checked automatically, changes caught before release, runtime evidence from test devices, and reports your counsel can use, in English and Chinese.',
    ctaMail: 'Email us', ctaCall: 'Book a call', ctaFree: 'Try the free tool',
    noContact: 'Contact details are being added. Check back shortly.',
    plansTitle: 'Plans',
    plans: [
      { name: 'Free', price: '$0', unit: 'forever', who: 'Anyone', items: ['Every app format, every platform, in the browser', 'Risk areas, recordings, iPhone App Privacy Report', 'Command line: k1d scan and k1d diff'] },
      { name: 'Pro', price: '$299', unit: 'per month, or $2,990 per year · up to 5 apps', who: 'Publishers shipping regularly', items: ['Release check in your build pipeline (GitHub Action or any CI)', 'Blocks a release that adds China-linked SDKs or servers, credentials, tracking SDKs, high-risk permissions or consent defaults set to granted', 'Baseline per app, change table in every build summary', 'Bilingual evidence report for any build or build + recording (k1d report)', 'License key works offline; your builds never leave your servers'] },
      { name: 'Health Check', price: '$9,500', unit: 'per app · +$4,000 per extra platform', who: 'Before a launch, a deal, or after a demand letter', items: ['Automated Android runtime test on an emulator: first launch with no taps, consent declined, age answered as 12, consent accepted, then random play; every step time-stamped with screenshots', 'iPhone: the App Privacy Report from a test iPhone, combined with the IPA', 'Which servers each SDK contacts, when, and how much it sends, before and after consent (encrypted contents are not decrypted)', 'Server hosting from public registry records', 'Bilingual EN/ZH evidence report with file hashes, reviewed by a person before delivery', 'Delivered in about 2 weeks'], note: 'Design partners: the first 5 publishers pay $4,750 in exchange for feedback and an anonymized case study.' },
      { name: 'Monitoring', price: '$2,500', unit: 'per app per month', who: 'After a Health Check', items: ['Includes Pro and evidence reports for the app', 'Store watch: daily check of the Google Play and App Store versions; alert when a release ships without a k1d check', 'Automated runtime re-test of each new build', 'Quarterly review of the findings against new rules and lawsuits, in EN and ZH'] },
      { name: 'Enterprise', price: 'From $180,000', unit: 'per year', who: 'Portfolios of 10+ apps, groups, law firms', items: ['Portfolio dashboard across all titles (k1d portfolio)', 'White-label evidence reports under your firm\'s name', 'Everything runs in your own CI; command line and JSON output for your systems', 'Store watch and runtime tests for every title'] },
    ],
    bigNote: 'Apps with very large US audiences are quoted on a call.',
    paidTitle: 'What paid adds to the free tool',
    paid: [
      ['Automatic', 'Free scans one file when you remember to. Pro checks every build in your pipeline.'],
      ['Changes, not snapshots', 'Each release is compared with the last: "Mintegral added, new Alibaba Cloud bucket, new permission".'],
      ['Evidence', 'A dated record of every release checked, which is what counsel and order obligations ask for.'],
      ['Runtime depth', 'Scripted scenarios on an emulator, including a child user and ads, which a browser cannot run.'],
      ['Watching the stores', 'A daily check of what is live on Google Play and the App Store, and an alert when a release skipped the check.'],
    ],
    buyTitle: 'How buying works',
    buy: [
      'Email us or book a 20-minute call. We show your app in the free tool and agree the scope.',
      'We send a one-page order form with scope, price and dates. You sign it electronically.',
      'You receive an invoice from {company}. Pay by ACH, Zelle or wire in USD; we can invoice your US, Hong Kong or Singapore entity.',
      'Monthly plans: set up a recurring payment in your bank with your customer code as the reference. Each payment renews your license key automatically for the next month.',
      'Health Check: we start when the first half is paid and deliver in about 2 weeks; the second half is due on delivery. Pro and Monitoring: your license key is emailed when the first payment arrives.',
    ],
    companyFallback: 'k1d\'s US company (a New York LLC)',
    fraud: 'Bank details appear only on our invoices. We never change them by email: if you receive new bank details, call us to confirm before paying.',
    ciTitle: 'Release check in GitHub Actions',
    ciBody: 'Add your license key as a repository secret named K1D_LICENSE, then add this step after your build. The first run saves a baseline file; commit it.',
    ciOther: 'Other CI systems: run node cli/k1d.mjs check <app> --baseline k1d-baseline.json with K1D_LICENSE set. Exit code 0 = no blocking changes, 1 = blocking changes, 3 = license problem. Evidence report: node cli/k1d.mjs report <app> --recording <pcap> --out report.html.',
    faqTitle: 'Questions',
    faq: [
      ['Do you upload or keep our app?', 'The free tool and the release check run on your machine or your CI; nothing is sent to us. For a Health Check we analyze the builds you give us on our test devices; retention is set in the order form.'],
      ['Is this legal advice?', 'No. We provide factual technical evidence. Whether a law applies is for your counsel.'],
      ['Do you publish what you find?', 'No. Findings about your app go to you, privately.'],
      ['Can you invoice our Hong Kong or Singapore company?', 'Yes, in USD.'],
      ['Can we try before paying?', 'Yes: the free tool shows the same file analysis. For Pro, we can issue a 30-day trial key on request.'],
    ],
    footer: 'k1d provides factual technical observations, not legal advice.',
  },
  zh: {
    tagline: '面向应用发行商',
    title: '在用户、监管机构或原告律师之前，检查每一个版本',
    lead: '免费的 k1d 工具让任何人都能看到您的应用里有什么。付费方案把这件事变成发版流程的一部分：每个构建自动检查，发布前发现变化，在测试设备上获取运行时证据，并提供可供律师使用的中英双语报告。',
    ctaMail: '发邮件联系', ctaCall: '预约通话', ctaFree: '试用免费工具',
    noContact: '联系方式正在添加中，请稍后再来。',
    plansTitle: '方案',
    plans: [
      { name: '免费', price: '$0', unit: '永久', who: '所有人', items: ['所有平台、所有应用格式，在浏览器中分析', '风险领域、流量录制、iPhone App 隐私报告', '命令行：k1d scan 和 k1d diff'] },
      { name: 'Pro', price: '$299', unit: '每月，或每年 $2,990 · 最多 5 个应用', who: '定期发版的发行商', items: ['在构建流水线中检查每次发布（GitHub Action 或任何 CI）', '当新版本新增中国关联 SDK 或服务器、凭据、跟踪 SDK、高风险权限或“已授予”的同意默认值时阻止发布', '每个应用一个基线，每次构建摘要中都有变化表', '任一构建或“构建 + 录制”的中英双语证据报告（k1d report）', '许可证离线验证；您的构建不会离开您的服务器'] },
      { name: '健康检查', price: '$9,500', unit: '每个应用 · 每增加一个平台 +$4,000', who: '上线前、交易前或收到律师函后', items: ['在模拟器上自动运行 Android 测试：不点击的首次启动、拒绝同意、年龄填写为 12 岁、接受同意、随机操作；每一步都有时间戳和截图', 'iPhone：测试 iPhone 的 App 隐私报告，与 IPA 合并分析', '每个 SDK 在同意前后连接了哪些服务器、何时连接、发送了多少数据（不解密加密内容）', '依据公开注册记录确认服务器托管', '带文件哈希的中英双语证据报告，交付前经人工审核', '约 2 周交付'], note: '设计合作伙伴：前 5 家发行商仅需 $4,750，换取反馈和一份匿名案例。' },
      { name: '持续监测', price: '$2,500', unit: '每个应用每月', who: '健康检查之后', items: ['包含该应用的 Pro 和证据报告', '商店监测：每天检查 Google Play 和 App Store 上的版本；有版本未经 k1d 检查即上线时提醒', '对每个新构建自动进行运行时复测', '每季度对照新规则和诉讼复核发现，中英双语'] },
      { name: '企业版', price: '$180,000 起', unit: '每年', who: '10 个以上应用的组合、集团、律所', items: ['覆盖所有产品的组合看板（k1d portfolio）', '以贵所名义出具的白标证据报告', '全部在您自己的 CI 中运行；命令行和 JSON 输出可接入您的系统', '每个产品的商店监测和运行时测试'] },
    ],
    bigNote: '美国用户规模很大的应用，请通话报价。',
    paidTitle: '付费版比免费工具多什么',
    paid: [
      ['自动', '免费版在您想起来时扫描一个文件；Pro 在流水线中检查每个构建。'],
      ['看变化，而不是快照', '每次发布都与上一版对比：“新增 Mintegral、新的阿里云存储桶、新的权限”。'],
      ['证据', '每次发布检查都有带日期的记录，这正是律师和监管命令要求的。'],
      ['运行时深度', '在模拟器上按脚本运行场景，包括儿童用户和广告，这是浏览器做不到的。'],
      ['商店监测', '每天检查 Google Play 和 App Store 上线的版本，有版本跳过检查时提醒。'],
    ],
    buyTitle: '如何购买',
    buy: [
      '发邮件或预约 20 分钟通话。我们在免费工具中演示您的应用，并确定范围。',
      '我们发送一页订单表，写明范围、价格和日期，您电子签署。',
      '您会收到 {company} 开具的发票。可通过 ACH、Zelle 或电汇以美元付款；可向您的美国、香港或新加坡主体开票。',
      '月付方案：在您的银行设置定期付款，并以客户代码作为附言。每次付款到账后，许可证密钥自动续期一个月。',
      '健康检查：收到首期 50% 后开始，约 2 周交付，交付时支付其余 50%。Pro 和持续监测：首笔付款到账后通过邮件发送许可证密钥。',
    ],
    companyFallback: 'k1d 的美国公司（纽约州 LLC）',
    fraud: '银行信息只出现在我们的发票上。我们绝不会通过邮件更改银行信息：如收到新的银行信息，请先致电我们确认再付款。',
    ciTitle: '在 GitHub Actions 中检查发布',
    ciBody: '将许可证密钥添加为名为 K1D_LICENSE 的仓库机密，然后在构建之后加入此步骤。首次运行会保存一个基线文件，请提交它。',
    ciOther: '其他 CI 系统：设置 K1D_LICENSE 后运行 node cli/k1d.mjs check <app> --baseline k1d-baseline.json。退出码 0 = 无阻止性变化，1 = 有阻止性变化，3 = 许可证问题。证据报告：node cli/k1d.mjs report <app> --recording <pcap> --out report.html。',
    faqTitle: '常见问题',
    faq: [
      ['你们会上传或保留我们的应用吗？', '免费工具和发布检查都在您的电脑或 CI 上运行，不会发送给我们。健康检查时，我们在测试设备上分析您提供的构建；保留期限在订单表中约定。'],
      ['这是法律意见吗？', '不是。我们提供事实性的技术证据，法律是否适用由您的律师判断。'],
      ['你们会公开发现吗？', '不会。关于您应用的发现只私下发给您。'],
      ['可以向我们的香港或新加坡公司开票吗？', '可以，以美元开票。'],
      ['可以先试用吗？', '可以：免费工具提供同样的文件分析。Pro 可应要求提供 30 天试用密钥。'],
    ],
    footer: 'k1d 提供事实性技术观察，不构成法律意见。',
  },
};

const CI = `- name: k1d release check
  uses: hellohi6228-code/k1d@main
  with:
    file: app/build/outputs/bundle/release/app-release.aab
    baseline: k1d-baseline.json
    license: \${{ secrets.K1D_LICENSE }}`;

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
let lang = (() => { try { return localStorage.getItem('k1d.lang'); } catch { return null; } })() || ((navigator.language || '').toLowerCase().startsWith('zh') ? 'zh' : 'en');

function contactButtons(t) {
  const mail = CONFIG.contactEmail ? `<a class="btn btn-primary" href="mailto:${esc(CONFIG.contactEmail)}?subject=${encodeURIComponent('k1d for publishers')}">${esc(t.ctaMail)}</a>` : '';
  const call = CONFIG.bookingUrl ? `<a class="btn btn-secondary" href="${esc(CONFIG.bookingUrl)}" target="_blank" rel="noopener">${esc(t.ctaCall)}</a>` : '';
  const free = `<a class="btn btn-secondary" href="./">${esc(t.ctaFree)}</a>`;
  return `<div class="actions" style="margin-top:14px">${mail}${call}${free}</div>${mail || call ? '' : `<p class="muted small">${esc(t.noContact)}</p>`}`;
}

function render() {
  const t = C[lang];
  document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
  for (const b of document.querySelectorAll('[data-lang]')) b.setAttribute('aria-pressed', String(b.dataset.lang === lang));
  document.getElementById('tagline').textContent = t.tagline;
  document.getElementById('pub-footer').textContent = t.footer;
  const company = CONFIG.companyName || t.companyFallback;
  document.getElementById('pub').innerHTML = `
    <div class="hero"><h1>${esc(t.title)}</h1><p class="lead">${esc(t.lead)}</p>${contactButtons(t)}</div>
    <h2>${esc(t.plansTitle)}</h2>
    <div class="plans">${t.plans.map((p) => `<section class="card plan">
      <h3>${esc(p.name)}</h3><div class="price">${esc(p.price)}</div><div class="muted small">${esc(p.unit)}</div>
      <p class="small"><strong>${esc(p.who)}</strong></p>
      <ul class="small">${p.items.map((i) => `<li>${esc(i)}</li>`).join('')}</ul>
      ${p.note ? `<p class="small note-line">${esc(p.note)}</p>` : ''}
    </section>`).join('')}</div>
    <p class="muted small">${esc(t.bigNote)}</p>
    <h2>${esc(t.paidTitle)}</h2>
    <div class="card"><dl class="kv">${t.paid.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl></div>
    <h2>${esc(t.buyTitle)}</h2>
    <div class="card"><ol class="steps">${t.buy.map((s) => `<li>${esc(s.replace('{company}', company))}</li>`).join('')}</ol>
      <p class="banner small" style="margin-top:10px">${esc(t.fraud)}</p>${contactButtons(t)}</div>
    <h2>${esc(t.ciTitle)}</h2>
    <div class="card"><p class="small">${esc(t.ciBody)}</p><pre class="terms">${esc(CI)}</pre><p class="muted small">${esc(t.ciOther)}</p></div>
    <h2>${esc(t.faqTitle)}</h2>
    <div class="card">${t.faq.map(([q, a]) => `<details><summary>${esc(q)}</summary><p class="small">${esc(a)}</p></details>`).join('')}</div>`;
}

for (const b of document.querySelectorAll('[data-lang]')) b.addEventListener('click', () => { lang = b.dataset.lang; try { localStorage.setItem('k1d.lang', lang); } catch { /* private mode */ } render(); });
render();
