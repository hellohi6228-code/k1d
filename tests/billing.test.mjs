// Bank-only billing: periods, invoices, CSV parsing (two bank layouts), payment matching, license renewal.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { addMonths, periodsUpTo, dueInvoices, matchPayments, cmdRun, cmdReconcile, cmdStatus, cmdTrial } from '../tools/business/billing.mjs';
import { incomingPayments, parseAmount } from '../tools/business/bankcsv.mjs';
import { verifyLicense } from '../cli/license.mjs';

const company = { legalName: 'Demo LLC', address: ['1 Main St', 'New York, NY'], email: 'billing@demo.example', paymentTermsDays: 15, bank: { accountName: 'Demo LLC', bankName: 'Demo Bank', accountNumber: '000', achRouting: '000', wireRouting: '000' } };
const customers = { customers: [{
  id: 'acme', code: 'K1D-AC01', org: 'Acme Games', billTo: { name: 'Acme Games Pte. Ltd.', email: 'ap@acme.example', address: ['Singapore'] },
  subscriptions: [
    { plan: 'healthcheck', interval: 'once', start: '2026-12-01', price: 4750 },
    { plan: 'monitoring', interval: 'month', start: '2026-12-15', price: 2500, apps: ['com.acme.puzzle'] },
  ],
}] };

function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'k1d-billing-'));
  fs.writeFileSync(path.join(dir, 'company.json'), JSON.stringify(company));
  fs.writeFileSync(path.join(dir, 'customers.json'), JSON.stringify(customers));
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const keyFile = path.join(dir, 'signing.pem');
  fs.writeFileSync(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }));
  process.env.K1D_SIGNING_KEY = keyFile;
  return { dir, pub: publicKey.export({ type: 'spki', format: 'pem' }) };
}

test('periods: month ends, Jan 31 start, once', () => {
  assert.equal(addMonths('2026-01-31', 1), '2026-02-28');
  assert.deepEqual(periodsUpTo({ interval: 'month', start: '2026-12-15' }, '2027-02-20').map((p) => `${p.start}..${p.end}`), ['2026-12-15..2027-01-14', '2027-01-15..2027-02-14', '2027-02-15..2027-03-14']);
  assert.equal(periodsUpTo({ interval: 'once', start: '2026-12-01' }, '2026-11-30').length, 0);
});

test('bank CSV: signed amount column and separate credit/debit columns', () => {
  const chase = 'Details,Posting Date,Description,Amount,Type,Balance,Check or Slip #\nCREDIT,12/03/2026,"WIRE IN ACME GAMES PTE LTD K1D-2026-001",4750.00,WIRE_INCOMING,9000.00,\nDEBIT,12/04/2026,"COFFEE",-4.50,DEBIT_CARD,8995.50,\n';
  const p1 = incomingPayments(chase);
  assert.deepEqual(p1.payments, [{ date: '2026-12-03', amount: 4750, description: 'WIRE IN ACME GAMES PTE LTD K1D-2026-001' }]);
  assert.equal(p1.skipped, 1);
  const other = '﻿Date,Description,Debit,Credit,Balance\n2027-01-16,ACH CREDIT ACME GAMES K1D-AC01,,"2,500.00",1\n2027-01-17,FEE,"(15.00)",,1\n';
  assert.deepEqual(incomingPayments(other).payments, [{ date: '2027-01-16', amount: 2500, description: 'ACH CREDIT ACME GAMES K1D-AC01' }]);
  assert.equal(parseAmount('(1,234.50)'), -1234.5);
});

test('run → reconcile → license renewal → status, end to end', () => {
  const { dir, pub } = setup();
  const first = cmdRun(dir, '2026-12-01');
  assert.deepEqual(first.map((i) => [i.number, i.amount]), [['K1D-2026-001', 4750]]);
  assert.ok(fs.existsSync(path.join(dir, 'invoices', 'K1D-2026-001.html')));
  assert.match(fs.readFileSync(path.join(dir, 'outbox', 'K1D-2026-001-invoice.eml'), 'utf8'), /X-Unsent: 1/);
  assert.equal(cmdRun(dir, '2026-12-01').length, 0, 'running twice creates nothing new');
  const second = cmdRun(dir, '2027-01-20');
  assert.deepEqual(second.map((i) => `${i.periodStart}..${i.periodEnd}`), ['2026-12-15..2027-01-14', '2027-01-15..2027-02-14']);

  const csv = 'Posting Date,Description,Amount\n12/03/2026,"WIRE ACME GAMES PTE LTD K1D-2026-001",4750.00\n12/20/2026,"ACH CREDIT ACME GAMES K1D-AC01",2500.00\n01/22/2027,"ZELLE FROM ACME GAMES PTE LTD",2500.00\n01/23/2027,"UNKNOWN SENDER",99.00\n';
  const r = cmdReconcile(dir, csv);
  assert.deepEqual(r.matched.map((m) => [m.invoice.number, m.how]), [['K1D-2026-001', 'invoice number'], ['K1D-2027-001', 'customer code'], ['K1D-2027-002', 'amount and payer name']]);
  assert.equal(r.unmatched.length, 1);
  assert.equal(r.keys.length, 1, 'one renewed key for the monitoring subscription; none for the one-off Health Check');
  assert.equal(r.keys[0].exp, '2027-02-21', 'paid through Feb 14 + 7 days grace');
  const draft = fs.readdirSync(path.join(dir, 'outbox')).find((f) => f.endsWith('-license.eml'));
  const body = Buffer.from(fs.readFileSync(path.join(dir, 'outbox', draft), 'utf8').split('\r\n\r\n')[2].split('\r\n--')[0].replace(/\r\n/g, ''), 'base64').toString('utf8');
  const key = body.match(/\n\n([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\n/)[1];
  const v = verifyLicense(key, { appId: 'com.acme.puzzle', publicKeyPem: pub, today: new Date('2027-02-20') });
  assert.equal(v.ok, true, v.reason);
  assert.equal(cmdReconcile(dir, csv).matched.length, 0, 'importing the same CSV again matches nothing twice');

  cmdRun(dir, '2027-02-15');
  const s = cmdStatus(dir, '2027-03-09');
  assert.deepEqual(s.overdue.map((i) => i.number), ['K1D-2027-003']);
  assert.ok(fs.readdirSync(path.join(dir, 'outbox')).some((f) => f.includes('K1D-2027-003-reminder')), 'reminder 7 days after due date');
  assert.equal(cmdTrial(dir, 'acme', 30).trial, true);
});

test('matching does not use the same payment or invoice twice', () => {
  const ledger = { invoices: [
    { number: 'K1D-2027-001', customerId: 'acme', amount: 2500, date: '2027-01-01', paid: null },
    { number: 'K1D-2027-002', customerId: 'acme', amount: 2500, date: '2027-02-01', paid: null },
  ] };
  const { matched } = matchPayments(ledger, customers, [
    { date: '2027-02-03', amount: 2500, description: 'ACME GAMES PTE LTD' },
    { date: '2027-02-04', amount: 2500, description: 'ACME GAMES PTE LTD' },
  ]);
  assert.deepEqual(matched.map((m) => m.invoice.number), ['K1D-2027-001', 'K1D-2027-002'], 'oldest open invoice first');
  assert.equal(dueInvoices(customers, { invoices: [] }, '2026-11-01').length, 0);
});
