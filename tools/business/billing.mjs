#!/usr/bin/env node
// Bank-only subscription billing: invoices, bank-statement matching, license renewal, email drafts.
// No payment processor and no email service: invoices are paid by ACH, Zelle or wire to your own bank
// account; you download the bank's CSV, run `reconcile`, and send the drafts it writes.
//
//   node tools/business/billing.mjs run        [--date YYYY-MM-DD]   create due invoices + drafts
//   node tools/business/billing.mjs reconcile  <bank.csv>            match payments, renew license keys
//   node tools/business/billing.mjs status     [--date YYYY-MM-DD]   open/overdue invoices, key expiry, reminders
//   node tools/business/billing.mjs trial      <customerId> [--days 30]
//   options: --dir <folder> (default docs/business) — holds company.json, customers.json, ledger.json
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { renderInvoice, emlDraft, invoiceTotal, money, addDays } from './invoice.mjs';
import { incomingPayments } from './bankcsv.mjs';
import { signLicense } from '../../cli/license.mjs';

// ---------------------------------------------------------------- dates and periods
export const addMonths = (iso, n) => {
  const [y, m, d] = iso.split('-').map(Number);
  const t = new Date(Date.UTC(y, m - 1 + n, 1));
  const last = new Date(Date.UTC(t.getUTCFullYear(), t.getUTCMonth() + 1, 0)).getUTCDate();
  return new Date(Date.UTC(t.getUTCFullYear(), t.getUTCMonth(), Math.min(d, last))).toISOString().slice(0, 10);
};
const step = (interval) => ({ month: 1, quarter: 3, year: 12 })[interval];

// All billing periods of a subscription that have started on or before `date`.
export function periodsUpTo(sub, date) {
  if (sub.interval === 'once') return sub.start <= date ? [{ start: sub.start, end: sub.start }] : [];
  const out = [];
  for (let s = sub.start, i = 0; s <= date && i < 600; i++) {
    const next = addMonths(sub.start, step(sub.interval) * (i + 1));
    if (sub.end && s > sub.end) break;
    out.push({ start: s, end: addDays(next, -1) });
    s = next;
  }
  return out;
}

// ---------------------------------------------------------------- invoices
const PLAN_LABEL = { pro: 'k1d Pro (release check)', monitoring: 'k1d Monitoring', enterprise: 'k1d Enterprise', healthcheck: 'k1d Health Check', service: 'k1d services' };

export function nextInvoiceNumber(ledger, date, prefix = 'K1D') {
  const year = date.slice(0, 4);
  const n = ledger.invoices.filter((i) => i.number.startsWith(`${prefix}-${year}-`)).length + 1;
  return `${prefix}-${year}-${String(n).padStart(3, '0')}`;
}

// Invoices that should exist by `date` and don't yet.
export function dueInvoices(customers, ledger, date, company = {}) {
  const out = [];
  const shadow = { invoices: [...ledger.invoices] };
  for (const c of customers.customers) {
    (c.subscriptions ?? []).forEach((sub, si) => {
      if (sub.status === 'cancelled' && !sub.end) return;
      for (const p of periodsUpTo(sub, date)) {
        if (shadow.invoices.some((i) => i.customerId === c.id && i.sub === si && i.periodStart === p.start)) continue;
        const number = nextInvoiceNumber(shadow, date, company.invoicePrefix);
        const apps = (sub.apps ?? []).join(', ');
        const desc = sub.description ?? `${PLAN_LABEL[sub.plan] ?? sub.plan}${apps ? ` — ${apps}` : ''}${sub.interval === 'once' ? '' : ` — ${p.start} to ${p.end}`}`;
        const inv = {
          number, customerId: c.id, sub: si, plan: sub.plan, periodStart: p.start, periodEnd: p.end,
          date, due: addDays(date, company.paymentTermsDays ?? 15), currency: c.currency ?? 'USD', customerCode: c.code,
          billTo: c.billTo, reference: sub.reference ?? null,
          items: [{ description: desc, qty: sub.qty ?? 1, unitPrice: sub.price }],
          notes: sub.interval === 'once' ? sub.notes ?? null : 'Your license key is renewed automatically when this payment arrives.',
          paid: null,
        };
        inv.amount = invoiceTotal(inv);
        shadow.invoices.push(inv);
        out.push(inv);
      }
    });
  }
  return out;
}

// ---------------------------------------------------------------- payments
const norm = (s) => String(s ?? '').toLowerCase().replace(/[^a-z0-9一-鿿]+/g, ' ');

// Match bank credits to open invoices: invoice number in the reference first, then customer code,
// then exact amount + the customer's name. Returns { matched: [{payment, invoice, how}], unmatched }.
export function matchPayments(ledger, customers, payments) {
  const open = ledger.invoices.filter((i) => !i.paid);
  const used = new Set();
  const matched = [];
  const unmatched = [];
  const cust = Object.fromEntries(customers.customers.map((c) => [c.id, c]));
  const already = new Set(ledger.invoices.filter((i) => i.paid).map((i) => `${i.paid.date}|${i.paid.amount}|${i.paid.ref}`));
  for (const p of payments) {
    if (already.has(`${p.date}|${p.amount}|${p.description}`)) continue; // same CSV imported twice
    const d = norm(p.description);
    const take = (inv, how) => { used.add(inv.number); matched.push({ payment: p, invoice: inv, how }); };
    const byNumber = open.find((i) => !used.has(i.number) && d.includes(norm(i.number).trim()));
    if (byNumber) { take(byNumber, 'invoice number'); continue; }
    const byCode = open.filter((i) => !used.has(i.number) && cust[i.customerId]?.code && new RegExp(`\\b${norm(cust[i.customerId].code).trim()}\\b`).test(d))
      .sort((a, b) => a.date.localeCompare(b.date));
    const codeHit = byCode.find((i) => Math.abs(i.amount - p.amount) < 0.01) ?? byCode[0];
    if (codeHit) { take(codeHit, 'customer code'); continue; }
    const byName = open.filter((i) => !used.has(i.number) && Math.abs(i.amount - p.amount) < 0.01 && (cust[i.customerId]?.payerNames ?? [cust[i.customerId]?.billTo?.name, cust[i.customerId]?.org]).filter(Boolean).some((n) => norm(n).trim().split(' ').filter((w) => w.length > 2).every((w) => d.includes(w))))
      .sort((a, b) => a.date.localeCompare(b.date));
    if (byName[0]) { take(byName[0], 'amount and payer name'); continue; }
    unmatched.push(p);
  }
  return { matched, unmatched };
}

// License covering every paid period of the subscription, plus a grace period.
export function licensePayload(customer, sub, invoices, graceDays = 7) {
  const paid = invoices.filter((i) => i.customerId === customer.id && i.sub === customer.subscriptions.indexOf(sub) && i.paid).sort((a, b) => a.periodEnd.localeCompare(b.periodEnd));
  if (!paid.length || !['pro', 'monitoring', 'enterprise'].includes(sub.plan)) return null;
  return { v: 1, id: crypto.randomUUID(), org: customer.org, plan: sub.plan, apps: sub.apps?.length ? sub.apps : ['*'], exp: addDays(paid.at(-1).periodEnd, graceDays), issued: new Date().toISOString().slice(0, 10) };
}

// ---------------------------------------------------------------- files
function load(dir) {
  const read = (f, fallback) => (fs.existsSync(path.join(dir, f)) ? JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')) : fallback);
  const company = read('company.json', null);
  if (!company) throw new Error(`${dir}/company.json is missing (copy company.example.json and fill it in).`);
  const customers = read('customers.json', null);
  if (!customers) throw new Error(`${dir}/customers.json is missing (copy customers.example.json).`);
  const ledger = read('ledger.json', { invoices: [], licenses: [], payments: [] });
  return { company, customers, ledger };
}
const save = (dir, ledger) => fs.writeFileSync(path.join(dir, 'ledger.json'), `${JSON.stringify(ledger, null, 1)}\n`);
const signingKey = () => fs.readFileSync(process.env.K1D_SIGNING_KEY || path.join(os.homedir(), '.k1d', 'license-signing-key.pem'), 'utf8');

function writeDraft(dir, name, draft) {
  const out = path.join(dir, 'outbox');
  fs.mkdirSync(out, { recursive: true });
  const f = path.join(out, `${name}.eml`);
  fs.writeFileSync(f, emlDraft(draft));
  return f;
}
const from = (co) => `${co.legalName} <${co.email}>`;

function invoiceEmail(co, c, inv) {
  const recurring = inv.periodStart !== inv.periodEnd;
  const text = `Hello${c.billTo.attention ? ` ${c.billTo.attention.split(',')[0]}` : ''},

Please find invoice ${inv.number} for ${money(inv.amount, inv.currency)}, due ${inv.due}${recurring ? ` (period ${inv.periodStart} to ${inv.periodEnd})` : ''}.

Pay by ACH, Zelle or wire to the account on the invoice and put ${inv.number} in the payment reference${c.code ? ` (or your customer code ${c.code} for a recurring bank payment)` : ''}.
${recurring ? 'Your k1d license key is renewed automatically once the payment arrives.\n' : ''}
We never change bank details by email. If you receive different payment instructions, call us before paying.

Thank you,
${co.legalName}`;
  return { from: from(co), to: c.billTo.email, subject: `Invoice ${inv.number} — ${co.legalName}`, text, html: `${renderInvoice(co, inv)}` };
}

function licenseEmail(co, c, key, payload) {
  const text = `Hello,

Thank you, payment received. Your k1d ${payload.plan} license key (valid until ${payload.exp}, apps: ${payload.apps.join(', ')}):

${key}

Store it as a repository secret named K1D_LICENSE (GitHub: Settings → Secrets and variables → Actions). Replace the previous key; it stops working after its own expiry date.

${co.legalName}`;
  return { from: from(co), to: c.billTo.email, subject: `Your k1d license key (until ${payload.exp})`, text };
}

function reminderEmail(co, c, inv, days) {
  const text = `Hello,

A reminder that invoice ${inv.number} (${money(inv.amount, inv.currency)}) was due on ${inv.due}, ${days} day(s) ago. If you've already paid, thank you, and please ignore this; bank transfers can take a few days to arrive.

Pay by ACH, Zelle or wire with ${inv.number} in the reference. The account details are on the invoice. Your k1d license key keeps working until its expiry date and is renewed when the payment arrives.

${co.legalName}`;
  return { from: from(co), to: c.billTo.email, subject: `Reminder: invoice ${inv.number}`, text };
}

// ---------------------------------------------------------------- commands
export function cmdRun(dir, date) {
  const { company, customers, ledger } = load(dir);
  const cust = Object.fromEntries(customers.customers.map((c) => [c.id, c]));
  const created = dueInvoices(customers, ledger, date, company);
  fs.mkdirSync(path.join(dir, 'invoices'), { recursive: true });
  for (const inv of created) {
    fs.writeFileSync(path.join(dir, 'invoices', `${inv.number}.html`), renderInvoice(company, inv));
    writeDraft(dir, `${inv.number}-invoice`, invoiceEmail(company, cust[inv.customerId], inv));
    ledger.invoices.push(inv);
  }
  save(dir, ledger);
  return created;
}

export function cmdReconcile(dir, csvText, { graceDays = 7 } = {}) {
  const { company, customers, ledger } = load(dir);
  const cust = Object.fromEntries(customers.customers.map((c) => [c.id, c]));
  const { payments, skipped } = incomingPayments(csvText);
  const { matched, unmatched } = matchPayments(ledger, customers, payments);
  const keys = [];
  for (const m of matched) {
    m.invoice.paid = { date: m.payment.date, amount: m.payment.amount, ref: m.payment.description, how: m.how };
    if (Math.abs(m.payment.amount - m.invoice.amount) >= 0.01) m.invoice.paid.short = +(m.invoice.amount - m.payment.amount).toFixed(2);
  }
  // One renewed key per subscription that got a payment.
  const subs = new Map();
  for (const m of matched) subs.set(`${m.invoice.customerId}|${m.invoice.sub}`, m.invoice);
  for (const inv of subs.values()) {
    const c = cust[inv.customerId];
    const sub = c.subscriptions[inv.sub];
    const payload = licensePayload(c, sub, ledger.invoices, graceDays);
    if (!payload) continue;
    const key = signLicense(payload, signingKey());
    ledger.licenses.push({ customerId: c.id, sub: inv.sub, id: payload.id, plan: payload.plan, apps: payload.apps, exp: payload.exp, issued: payload.issued });
    writeDraft(dir, `${payload.issued}-${c.id}-license`, licenseEmail(company, c, key, payload));
    keys.push({ customer: c.org, exp: payload.exp });
  }
  ledger.payments.push(...unmatched.map((p) => ({ ...p, unmatched: true })));
  save(dir, ledger);
  return { matched, unmatched, skipped, keys };
}

export function cmdStatus(dir, date) {
  const { company, customers, ledger } = load(dir);
  const cust = Object.fromEntries(customers.customers.map((c) => [c.id, c]));
  const open = ledger.invoices.filter((i) => !i.paid);
  const overdue = open.filter((i) => i.due < date);
  for (const inv of overdue) {
    const days = Math.round((Date.parse(date) - Date.parse(inv.due)) / 864e5);
    if ([1, 7, 14, 30].includes(days) || days > 30) writeDraft(dir, `${date}-${inv.number}-reminder`, reminderEmail(company, cust[inv.customerId], inv, days));
  }
  const latest = new Map();
  for (const l of ledger.licenses) if (!latest.has(`${l.customerId}|${l.sub}`) || latest.get(`${l.customerId}|${l.sub}`).exp < l.exp) latest.set(`${l.customerId}|${l.sub}`, l);
  return { open, overdue, licenses: [...latest.values()].sort((a, b) => a.exp.localeCompare(b.exp)) };
}

export function cmdTrial(dir, customerId, days = 30) {
  const { company, customers, ledger } = load(dir);
  const c = customers.customers.find((x) => x.id === customerId);
  if (!c) throw new Error(`No customer ${customerId} in customers.json`);
  const today = new Date().toISOString().slice(0, 10);
  const payload = { v: 1, id: crypto.randomUUID(), org: c.org, plan: 'pro', apps: c.subscriptions?.[0]?.apps ?? ['*'], exp: addDays(today, days), issued: today, trial: true };
  const key = signLicense(payload, signingKey());
  ledger.licenses.push({ customerId: c.id, sub: null, id: payload.id, plan: 'pro', apps: payload.apps, exp: payload.exp, issued: today, trial: true });
  save(dir, ledger);
  writeDraft(dir, `${today}-${c.id}-trial`, licenseEmail(company, c, key, payload));
  return payload;
}

// ---------------------------------------------------------------- CLI
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const argv = process.argv.slice(2);
  const opt = (k, d) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : d; };
  const dir = path.resolve(opt('dir', 'docs/business'));
  const date = opt('date', new Date().toISOString().slice(0, 10));
  const [cmd, arg] = argv.filter((a, i) => !a.startsWith('--') && !argv[i - 1]?.startsWith('--'));
  try {
    if (cmd === 'run') {
      const created = cmdRun(dir, date);
      console.log(created.length ? created.map((i) => `${i.number}  ${i.customerId}  ${money(i.amount, i.currency)}  due ${i.due}`).join('\n') : 'No invoices due.');
      if (created.length) console.log(`\nInvoices: ${path.join(dir, 'invoices')}\nEmail drafts: ${path.join(dir, 'outbox')} (open each .eml, attach the invoice PDF if you like, send)`);
    } else if (cmd === 'reconcile') {
      if (!arg) throw new Error('usage: reconcile <bank.csv>');
      const r = cmdReconcile(dir, fs.readFileSync(arg, 'utf8'));
      for (const m of r.matched) console.log(`PAID  ${m.invoice.number}  ${money(m.payment.amount, m.invoice.currency)} on ${m.payment.date}  (matched by ${m.how})${m.invoice.paid.short ? `  SHORT by ${m.invoice.paid.short}` : ''}`);
      for (const k of r.keys) console.log(`KEY   ${k.customer} renewed until ${k.exp} (draft in outbox)`);
      for (const p of r.unmatched) console.log(`??    ${p.date}  ${p.amount}  "${p.description}" — not matched; check it by hand`);
      console.log(`${r.matched.length} matched, ${r.unmatched.length} unmatched, ${r.skipped} non-credit rows skipped.`);
    } else if (cmd === 'status') {
      const s = cmdStatus(dir, date);
      console.log(`Open invoices: ${s.open.length}${s.overdue.length ? ` (${s.overdue.length} overdue: ${s.overdue.map((i) => i.number).join(', ')}; reminder drafts written)` : ''}`);
      for (const l of s.licenses) console.log(`License ${l.customerId} ${l.plan}${l.trial ? ' (trial)' : ''} valid until ${l.exp}${l.exp < date ? '  EXPIRED' : ''}`);
    } else if (cmd === 'trial') {
      const p = cmdTrial(dir, arg, Number(opt('days', 30)));
      console.log(`Trial key for ${p.org} until ${p.exp}; draft in outbox.`);
    } else {
      console.log('usage: billing.mjs run | reconcile <bank.csv> | status | trial <customerId> [--days 30] [--dir docs/business] [--date YYYY-MM-DD]');
    }
  } catch (err) {
    console.error(`billing: ${err.message}`);
    process.exit(1);
  }
}
