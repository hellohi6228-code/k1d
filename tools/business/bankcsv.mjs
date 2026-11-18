// Read a bank transactions CSV export (any US bank's "Download → CSV") into incoming payments.
// Column names differ by bank, so columns are found by name: date, description/memo, and either one
// signed amount column or separate credit/debit columns.

export function parseCsv(text) {
  const rows = [];
  let row = [];
  let cell = '';
  let q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; } else if (c === '"') q = false; else cell += c;
    } else if (c === '"') q = true;
    else if (c === ',') { row.push(cell); cell = ''; } else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(cell); cell = '';
      if (row.some((x) => x.trim() !== '')) rows.push(row);
      row = [];
    } else cell += c;
  }
  row.push(cell);
  if (row.some((x) => x.trim() !== '')) rows.push(row);
  return rows;
}

export function parseAmount(s) {
  if (s == null) return null;
  let t = String(s).trim();
  if (!t) return null;
  const neg = /^\(.*\)$/.test(t) || /^-/.test(t) || /\bDR\b/i.test(t);
  t = t.replace(/[()$,\sA-Za-z]/g, '').replace(/^-/, '');
  const n = Number(t);
  if (!Number.isFinite(n)) return null;
  return neg ? -n : n;
}

export function parseDate(s) {
  const t = String(s ?? '').trim();
  let m = t.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (m) return `${m[1]}-${m[2]}-${m[3]}`;
  m = t.match(/^(\d{1,2})\/(\d{1,2})\/(\d{2,4})/);
  if (m) return `${m[3].length === 2 ? `20${m[3]}` : m[3]}-${m[1].padStart(2, '0')}-${m[2].padStart(2, '0')}`;
  return null;
}

// First regex that matches any header wins, so more specific names are listed first.
const find = (headers, ...res) => { for (const re of res) { const i = headers.findIndex((h) => re.test(h)); if (i >= 0) return i; } return -1; };

// Returns { payments: [{ date, amount, description }], skipped }
export function incomingPayments(text) {
  const rows = parseCsv(text.replace(/^﻿/, ''));
  const hi = rows.findIndex((r) => r.some((c) => /date/i.test(c)) && r.some((c) => /amount|credit|deposit/i.test(c)));
  if (hi < 0) throw new Error('No header row with a date and an amount/credit column was found in the CSV.');
  const headers = rows[hi].map((h) => h.trim().toLowerCase());
  const iDate = find(headers, /^posting date$/, /^date$/, /transaction date/, /date/);
  const iDesc = find(headers, /description/, /payee/, /narrative/, /memo/, /reference/, /details/);
  const iMemo = find(headers, /^memo$/, /reference/, /addenda/);
  const iAmt = find(headers, /^amount$/, /amount/);
  const iCredit = find(headers, /credit/, /deposit/);
  const iDebit = find(headers, /debit/, /withdrawal/);
  const payments = [];
  let skipped = 0;
  for (const r of rows.slice(hi + 1)) {
    const date = parseDate(r[iDate]);
    let amount = null;
    if (iCredit >= 0 && iCredit !== iAmt) amount = parseAmount(r[iCredit]);
    if (amount == null && iAmt >= 0) amount = parseAmount(r[iAmt]);
    if (amount == null && iDebit >= 0 && parseAmount(r[iDebit])) amount = -Math.abs(parseAmount(r[iDebit]));
    if (!date || amount == null || amount <= 0) { skipped += 1; continue; }
    const description = [r[iDesc], iMemo >= 0 && iMemo !== iDesc ? r[iMemo] : ''].filter(Boolean).join(' · ').trim();
    payments.push({ date, amount, description });
  }
  return { payments, skipped };
}
