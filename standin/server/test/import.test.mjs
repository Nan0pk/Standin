import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'standin-import-'));
process.env.STANDIN_HOME = path.join(tmp, 'home');   // no passphrase set on purpose
delete process.env.STANDIN_PASSPHRASE;
process.env.STANDIN_VAULT = 'file';
delete process.env.STANDIN_VAULT_FILE;
process.env.STANDIN_PROFILES = path.join(tmp, 'profiles');

const { importDocument, getSecret, vaultList, vaultForget } = await import('../src/vault.mjs');
const { importChromeSession } = await import('../src/browser.mjs');

test('zero config: vault key is created on its own with 0600 perms', () => {
  importDocument(write('a.env', 'ACME_PASSWORD=hunter2\n'));
  const keyFile = path.join(process.env.STANDIN_HOME, 'key');
  assert.ok(fs.existsSync(keyFile));
  assert.equal(fs.statSync(keyFile).mode & 0o777, 0o600);
  assert.equal(getSecret('acme.password'), 'hunter2');
});

test('imports messy human notes', () => {
  const f = write('creds.md', `# My logins

## GitHub
username: j@example.com
password: gh-pass-123
2FA secret: JBSWY3DPEHPK3PXP

## Stripe
email = billing@example.com
secret key = sk_live_abc123
publishable key = pk_live_xyz

# ignore me
API_KEY_PLACEHOLDER: xxxxx
`);
  const summary = importDocument(f);
  assert.deepEqual(Object.keys(summary).sort(), ['github', 'stripe']);
  assert.equal(getSecret('github.username'), 'j@example.com');
  assert.equal(getSecret('github.password'), 'gh-pass-123');
  assert.match(getSecret('github.totp'), /^\d{6}$/);           // seed -> live code
  assert.equal(getSecret('stripe.api_key'), 'sk_live_abc123');
  assert.equal(getSecret('stripe.username'), 'billing@example.com');
  assert.ok(!vaultList().join().includes('xxxxx'));
});

test('imports a Chrome/1Password style CSV export', () => {
  const f = write('passwords.csv', 'name,url,username,password\nDigitalOcean,https://cloud.digitalocean.com,j@x.com,"do,pass"\nVercel,https://vercel.com,j@x.com,vc-pass\n');
  const summary = importDocument(f);
  assert.ok(summary.digitalocean && summary.vercel, JSON.stringify(summary));
  assert.equal(getSecret('digitalocean.password'), 'do,pass');
  assert.equal(getSecret('vercel.url'), 'https://vercel.com');
});

test('imports nested JSON', () => {
  const f = write('c.json', JSON.stringify({ twilio: { account_sid: 'AC123', auth_token: 'tok123' } }));
  importDocument(f);
  assert.equal(getSecret('twilio.auth_token'), 'tok123');
  assert.equal(getSecret('twilio.account_sid'), 'AC123');
});

test('vault_forget removes entries', () => {
  assert.equal(vaultForget('twilio'), true);
  assert.ok(!vaultList().join().includes('twilio'));
});

test('imports an existing browser session into a standin profile', () => {
  // fake a Chrome user-data dir
  const src = path.join(tmp, 'chrome');
  fs.mkdirSync(path.join(src, 'Default', 'Network'), { recursive: true });
  fs.writeFileSync(path.join(src, 'Default', 'Network', 'Cookies'), 'sqlite-ish');
  fs.writeFileSync(path.join(src, 'Local State'), '{"os_crypt":{}}');
  const r = importChromeSession('portal', { source: src });
  assert.ok(r.copied >= 2);
  const dest = path.join(process.env.STANDIN_PROFILES, 'portal');
  assert.ok(fs.existsSync(path.join(dest, 'Default', 'Network', 'Cookies')));
  assert.ok(fs.existsSync(path.join(dest, 'Local State')));
  assert.ok(fs.existsSync(path.join(dest, '.standin-use-chrome')), 'should remember to launch real Chrome');
});

function write(name, body) {
  const f = path.join(tmp, name);
  fs.writeFileSync(f, body);
  return f;
}
