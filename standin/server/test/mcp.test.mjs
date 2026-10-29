import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'standin-mcp-'));
process.env.STANDIN_PASSPHRASE = 'test-pass';
process.env.STANDIN_VAULT = 'file';
process.env.STANDIN_VAULT_FILE = path.join(tmp, 'secrets.enc');
process.env.STANDIN_PROFILES = path.join(tmp, 'profiles');

const { call, shutdown } = await import('../src/mcp.mjs');
test.after(() => shutdown());
const text = r => r.content.map(c => c.text || `[${c.type}]`).join('\n');
const FORM = 'file://' + path.join(here, 'fixtures', 'form.html');

test('agent flow: open, sign in with hidden secrets, 2FA, capture a key', async () => {
  await call('vault_set', { ref: 'example.username', value: 'j@example.com' });
  await call('vault_set', { ref: 'example.password', value: 'sup3r-secret' });
  await call('vault_set', { ref: 'example.totp', value: 'JBSWY3DPEHPK3PXP' });

  const snap = text(await call('browser_open', { url: FORM, profile: 'mcp-test', headed: false }));
  assert.match(snap, /INTERACTIVE ELEMENTS/);
  assert.match(snap, /#username/);

  const filled = text(await call('browser_fill_secret', { selector: '#username', ref: 'example.username' }));
  assert.ok(!filled.includes('j@example.com'), 'secret leaked into tool output');
  const pw = text(await call('browser_fill_secret', { selector: '#password', ref: 'example.password' }));
  assert.ok(!pw.includes('sup3r-secret'), 'password leaked into tool output');

  await call('browser_click', { selector: '#signin' });
  await call('browser_wait', { selector: '#otp' });
  const otp = text(await call('browser_fill_totp', { selector: '#otp', account: 'example' }));
  assert.ok(!/\b\d{6}\b/.test(otp), '2FA code leaked into tool output');
  await call('browser_click', { selector: '#verify' });

  await call('browser_type', { selector: '#invoice', value: 'KEY-LIVE-123' });
  await call('browser_type', { selector: '#amount', value: '10' });
  await call('browser_type', { selector: 'select#currency', value: 'EUR' });
  await call('browser_type', { selector: '#agree', value: 'true' });
  await call('browser_click', { selector: '#submit' });

  const conf = text(await call('browser_read', { selector: '#confirmation' }));
  assert.equal(conf, 'CONF-KEY-LIVE-123-EUR-10');

  const cap = text(await call('browser_capture_secret', { selector: '#confirmation', ref: 'example.api_key' }));
  assert.ok(!cap.includes('KEY-LIVE-123'), 'captured key leaked into tool output');
  assert.match(text(await call('vault_list', {})), /api_key/);

  const shot = await call('browser_screenshot', {});
  assert.equal(shot.content[0].type, 'image');
});

test('http_request substitutes vault refs without exposing them', async () => {
  const http = await import('node:http');
  const seen = [];
  const srv = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => { seen.push({ auth: req.headers.authorization, body }); res.end('{"ok":true}'); });
  });
  await new Promise(r => srv.listen(0, r));
  try {
    const url = `http://127.0.0.1:${srv.address().port}/v1/keys`;
    const out = text(await call('http_request', {
      method: 'POST', url,
      headers: { Authorization: 'Bearer {{vault.example.password}}' },
      body: JSON.stringify({ key: '{{vault.example.api_key}}' }),
    }));
    assert.match(out, /200/);
    assert.equal(seen[0].auth, 'Bearer sup3r-secret');
    assert.match(seen[0].body, /KEY-LIVE-123/);
  } finally { await new Promise(resolve => srv.close(resolve)); }
});

test('save_task writes a runnable task file', async () => {
  process.chdir(tmp);
  const yaml = `name: t\nprofile: mcp-test\nurl: ${FORM}\nsteps:\n  - extract:\n      x: "#login"\n`;
  const out = text(await call('save_task', { name: 'demo', yaml }));
  assert.match(out, /saved/);
  assert.ok(fs.existsSync(path.join(tmp, 'tasks', 'demo.yaml')));
});
