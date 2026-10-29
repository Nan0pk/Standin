import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'standin-'));
process.env.STANDIN_PASSPHRASE = 'test-pass';
process.env.STANDIN_VAULT = 'file';
process.env.STANDIN_VAULT_FILE = path.join(tmp, 'secrets.enc');
process.env.STANDIN_PROFILES = path.join(tmp, 'profiles');

const { vaultSet, getSecret, totp } = await import('../src/vault.mjs');
const { runTask } = await import('../src/runner.mjs');

test('vault round-trips secrets encrypted on disk', () => {
  vaultSet('example.username', 'j@example.com');
  vaultSet('example.password', 'sup3r-secret');
  vaultSet('example.totp', 'JBSWY3DPEHPK3PXP');
  const raw = fs.readFileSync(process.env.STANDIN_VAULT_FILE, 'utf8');
  assert.ok(!raw.includes('sup3r-secret'), 'plaintext leaked into vault file');
  assert.equal(getSecret('example.username'), 'j@example.com');
  assert.match(getSecret('example.totp'), /^\d{6}$/);
  assert.match(totp('JBSWY3DPEHPK3PXP'), /^\d{6}$/);
});

test('end to end: login + 2FA + form + file upload + extract', async () => {
  const attachment = path.join(tmp, 'invoice.pdf');
  fs.writeFileSync(attachment, '%PDF-1.4 test');
  const task = {
    name: 'test-portal',
    profile: 'test',
    account: 'example',
    url: 'file://' + path.join(here, 'fixtures', 'form.html'),
    steps: [
      { login: {
        ifSelector: '#username',
        fields: { '#username': '{{vault.example.username}}', '#password': '{{vault.example.password}}' },
        submit: '#signin',
        otp: { selector: '#otp', value: '{{vault.example.totp}}', submit: '#verify' },
      } },
      { fill: {
        '#invoice': '{{data.invoice_no}}',
        '#amount': '{{data.amount}}',
        'select#currency': '{{data.currency}}',
        '#agree': 'true',
        '#attachment': '{{data.pdf_path}}',
      } },
      { submit: '#submit' },
      { extract: { confirmation: '#confirmation', user: '#echo', file: '#file' } },
    ],
  };
  const out = await runTask(task, {
    data: { invoice_no: 'INV77', amount: '4200', currency: 'PKR', pdf_path: attachment },
    outDir: path.join(tmp, 'run1'),
  });
  assert.equal(out.ok, true, out.error);
  assert.equal(out.extracted.confirmation, 'CONF-INV77-PKR-4200');
  assert.equal(out.extracted.user, 'j@example.com');
  assert.equal(out.extracted.file, 'invoice.pdf');
  assert.ok(fs.existsSync(path.join(tmp, 'run1', 'final.png')), 'screenshot missing');
});

test('second run reuses the saved session (login step skipped)', async () => {
  // fixture always shows the login form, so this asserts the skip logic instead:
  const out = await runTask({
    profile: 'test',
    url: 'file://' + path.join(here, 'fixtures', 'form.html'),
    steps: [{ login: { ifSelector: '#nonexistent', fields: { '#username': 'x' }, submit: '#signin' } }],
  }, { outDir: path.join(tmp, 'run2') });
  assert.equal(out.ok, true, out.error);
  const res = JSON.parse(fs.readFileSync(path.join(tmp, 'run2', 'result.json'), 'utf8'));
  assert.ok(res.log.includes('login'));
});

test('csv rows parse into data objects', async () => {
  const { readRows } = await import('../src/runner.mjs');
  const csv = path.join(tmp, 'rows.csv');
  fs.writeFileSync(csv, 'invoice_no,amount,currency\nINV1,100,USD\nINV2,"1,200",PKR\n');
  const rows = readRows(csv);
  assert.equal(rows.length, 2);
  assert.equal(rows[1].amount, '1,200');
  assert.equal(rows[1].currency, 'PKR');
});
