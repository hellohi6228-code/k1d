// Printable invoice HTML (browser → Print → Save as PDF) and .eml drafts that open in Outlook,
// Apple Mail or Thunderbird as unsent messages. No payment processor, no email service.

const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
export const money = (n, cur = 'USD') => `${cur} ${Number(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
export const addDays = (iso, days) => new Date(new Date(`${iso}T00:00:00Z`).getTime() + days * 864e5).toISOString().slice(0, 10);

export function invoiceTotal(inv) {
  return inv.items.reduce((n, i) => n + i.qty * i.unitPrice, 0);
}

export function renderInvoice(co, inv) {
  const total = invoiceTotal(inv);
  const due = inv.due ?? addDays(inv.date, co.paymentTermsDays ?? 15);
  const b = co.bank ?? {};
  const cur = inv.currency ?? 'USD';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Invoice ${esc(inv.number)}</title>
<style>
body{font:14px/1.5 -apple-system,"Segoe UI",Roboto,Arial,sans-serif;color:#15201e;margin:0;background:#fff}
main{max-width:780px;margin:0 auto;padding:40px 24px}
.top{display:flex;justify-content:space-between;gap:24px;border-bottom:2px solid #0f766e;padding-bottom:16px}
h1{margin:0;font-size:28px;color:#0f766e}.muted{color:#5a6a66}
table{width:100%;border-collapse:collapse;margin:20px 0}th,td{border-bottom:1px solid #dde4e2;padding:8px;text-align:left}
td.n,th.n{text-align:right}.total td{font-weight:800;font-size:16px;border-bottom:2px solid #15201e}
.box{background:#f1f4f3;border-radius:8px;padding:12px 14px;margin-top:16px}.warn{background:#fff1e7}
@media print{main{padding:0}}
</style></head><body><main>
<div class="top"><div><strong>${esc(co.legalName)}</strong><br>${(co.address ?? []).map(esc).join('<br>')}<br>${esc(co.email)}${co.phone ? ` · ${esc(co.phone)}` : ''}</div>
<div style="text-align:right"><h1>INVOICE</h1>No. <strong>${esc(inv.number)}</strong><br>Date: ${esc(inv.date)}<br>Due: <strong>${esc(due)}</strong></div></div>
<p style="margin-top:20px"><span class="muted">Bill to</span><br><strong>${esc(inv.billTo.name)}</strong>${inv.billTo.attention ? `<br>Attn: ${esc(inv.billTo.attention)}` : ''}<br>${(inv.billTo.address ?? []).map(esc).join('<br>')}${inv.billTo.email ? `<br>${esc(inv.billTo.email)}` : ''}</p>
${inv.reference ? `<p class="muted">Reference: ${esc(inv.reference)}</p>` : ''}
<table><thead><tr><th>Description</th><th class="n">Qty</th><th class="n">Unit price</th><th class="n">Amount</th></tr></thead><tbody>
${inv.items.map((i) => `<tr><td>${esc(i.description)}</td><td class="n">${esc(i.qty)}</td><td class="n">${money(i.unitPrice, cur)}</td><td class="n">${money(i.qty * i.unitPrice, cur)}</td></tr>`).join('')}
<tr class="total"><td colspan="3">Total due</td><td class="n">${money(total, cur)}</td></tr></tbody></table>
${inv.notes ? `<p>${esc(inv.notes)}</p>` : ''}
<div class="box"><strong>Pay by ACH, Zelle or wire (${esc(cur)})</strong><br>
Account name: ${esc(b.accountName)}<br>Bank: ${esc(b.bankName)}${b.bankAddress ? `, ${esc(b.bankAddress)}` : ''}<br>
Account number: ${esc(b.accountNumber)}<br>ACH routing: ${esc(b.achRouting)} · Wire routing: ${esc(b.wireRouting)}${b.swift ? `<br>SWIFT (international wires): ${esc(b.swift)}` : ''}${b.zelle ? `<br>Zelle: ${esc(b.zelle)}` : ''}<br>
Put <strong>${esc(inv.number)}</strong> in the payment reference so the payment is matched automatically. For monthly plans you can set this up as a recurring payment in your bank (same amount, same reference each month: use your customer code <strong>${esc(inv.customerCode ?? '')}</strong> if your bank doesn't allow changing the reference).</div>
<div class="box warn">We never change bank details by email. If you receive different payment instructions, call us before paying.</div>
<p class="muted" style="margin-top:20px">${esc(co.taxNote ?? '')}</p>
</main></body></html>`;
}

// RFC 822 draft. X-Unsent makes Outlook open it as a new message ready to send.
export function emlDraft({ from, to, subject, html, text }) {
  const boundary = `k1d-${Math.random().toString(36).slice(2)}`;
  const b64 = (s) => Buffer.from(s, 'utf8').toString('base64').replace(/.{76}/g, '$&\r\n');
  const encSubject = `=?UTF-8?B?${Buffer.from(subject, 'utf8').toString('base64')}?=`;
  return [
    `From: ${from}`, `To: ${to}`, `Subject: ${encSubject}`, 'X-Unsent: 1', 'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`, '',
    `--${boundary}`, 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: base64', '', b64(text ?? ''),
    `--${boundary}`, 'Content-Type: text/html; charset=utf-8', 'Content-Transfer-Encoding: base64', '', b64(html ?? `<pre>${esc(text ?? '')}</pre>`),
    `--${boundary}--`, '',
  ].join('\r\n');
}
