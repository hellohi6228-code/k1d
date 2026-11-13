// Privacy-policy cross-check: plain text matching with excerpts. No inference.

const CJK = /[㐀-鿿]/;

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function termRegex(term) {
  if (CJK.test(term)) return new RegExp(escapeRe(term), 'i');
  // Short names (QQ, XD, MSA) need a full word boundary; longer ones may take a suffix (purchase -> purchases).
  const tail = term.length < 4 ? '(?![A-Za-z0-9])' : '';
  return new RegExp(`(?<![A-Za-z0-9])${escapeRe(term)}${tail}`, 'i');
}

function excerptAt(text, index, length) {
  const start = Math.max(0, index - 90);
  const end = Math.min(text.length, index + length + 90);
  return {
    text: (start > 0 ? '…' : '') + text.slice(start, end).replace(/\s+/g, ' ').trim() + (end < text.length ? '…' : ''),
    offset: index,
  };
}

function findFirst(text, terms) {
  let best = null;
  for (const term of terms) {
    if (!term) continue;
    const m = termRegex(term).exec(text);
    if (m && (!best || m.index < best.index)) best = { term, index: m.index, length: m[0].length };
  }
  return best ? { term: best.term, ...excerptAt(text, best.index, best.length) } : null;
}

function sentences(text) {
  return text.split(/(?<=[.!?。！？；;\n])\s*/).map((s) => s.trim()).filter((s) => s.length > 10);
}

const US_STORAGE = [/(united states|\bu\.s\.|\bus\b|美国)/i, /(stor|server|host|process|retain|存储|储存|服务器|处理|保存)/i];
const TRANSFER = [/(china|people's republic|\bprc\b|hong kong|singapore|中国|中华人民共和国|境外|跨境|香港|新加坡|international transfer|cross-border|transfer.*(outside|abroad))/i];

export function checkPolicy(text, result, permissionsKb) {
  const sdkChecks = result.sdks
    .filter((s) => s.confidence !== 'low' && s.category !== 'engine')
    .map((s) => {
      const terms = [s.name.en, s.name.zh, s.vendor, ...s.aliases];
      return { id: s.id, name: s.name, vendor: s.vendor, cnNexus: s.cnNexus, match: findFirst(text, terms) };
    });

  // Categories come from Android permissions / iOS usage keys and, on iOS, from privacy-manifest declarations.
  const sources = new Map();
  const add = (cat, src) => {
    if (!cat || cat === 'other' || !permissionsKb.categories[cat]) return;
    if (!sources.has(cat)) sources.set(cat, []);
    sources.get(cat).push(src);
  };
  for (const p of result.permissions) add(p.category, p.name);
  for (const d of result.ios?.declaredData ?? []) add(d.category, `${d.type.replace(/^NSPrivacyCollectedDataType/, '')} (privacy manifest)`);
  const categoryChecks = [...sources].map(([c, srcs]) => {
    const def = permissionsKb.categories[c];
    return {
      category: c,
      label: { en: def.en, zh: def.zh },
      permissions: [...new Set(srcs)],
      match: findFirst(text, def.keywords),
    };
  });

  const statements = [];
  for (const s of sentences(text)) {
    if (US_STORAGE.every((re) => re.test(s))) statements.push({ kind: 'us_storage', text: s.slice(0, 400) });
    else if (TRANSFER.some((re) => re.test(s))) statements.push({ kind: 'transfer', text: s.slice(0, 400) });
    if (statements.length >= 12) break;
  }

  return {
    checkedAt: new Date().toISOString(),
    textLength: text.length,
    sdkChecks,
    categoryChecks,
    statements,
  };
}
