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

const { call, shutdown, sessions } = await import('../src/mcp.mjs');
test.after(() => shutdown());
const text = r => r.content.map(c => c.text || `[${c.type}]`).join('\n');
const FORM = 'file://' + path.join(here, 'fixtures', 'form.html');

test('agent flow: open, sign in with hidden secrets, 2FA, capture a key', async () => {
  await call('vault_set', { ref: 'example.username', value: 'j@example.com' });
  await call('vault_set', { ref: 'example.password', value: 'sup3r-secret' });
  await call('vault_set', { ref: 'example.totp', value: 'JBSWY3DPEHPK3PXP' });

  await call('standin_session', { profile: 'mcp-test', headed: false });
  await call('browser_navigate', { url: FORM });
  const snap = text(await call('browser_snapshot', {}));
  assert.match(snap, /Sign in/);

  const filled = text(await call('browser_fill_secret', { target: '#username', ref: 'example.username' }));
  assert.ok(!filled.includes('j@example.com'), 'secret leaked into tool output');
  const pw = text(await call('browser_fill_secret', { target: '#password', ref: 'example.password' }));
  assert.ok(!pw.includes('sup3r-secret'), 'password leaked into tool output');

  await call('browser_click', { target: '#signin', element: 'Sign in button' });
  await call('browser_wait_for', { text: '6-digit code' });
  const otp = text(await call('browser_fill_totp', { target: '#otp', account: 'example' }));
  assert.ok(!/\b\d{6}\b/.test(otp), '2FA code leaked into tool output');
  await call('browser_click', { target: '#verify', element: 'Verify button' });

  await call('browser_type', { target: '#invoice', text: 'KEY-LIVE-123', element: '#invoice' });
  await call('browser_type', { target: '#amount', text: '10', element: '#amount' });
  await call('browser_type', { target: 'select#currency', text: 'EUR', element: 'select#currency' });
  await call('browser_type', { target: '#agree', text: 'true', element: '#agree' });
  await call('browser_click', { target: '#submit', element: 'Submit button' });

  const conf = text(await call('browser_read', { target: '#confirmation' }));
  assert.equal(conf, 'CONF-KEY-LIVE-123-EUR-10');

  const cap = text(await call('browser_capture_secret', { target: '#confirmation', ref: 'example.api_key' }));
  assert.ok(!cap.includes('KEY-LIVE-123'), 'captured key leaked into tool output');
  assert.match(text(await call('vault_list', {})), /api_key/);

  const shot = await call('browser_take_screenshot', {});
  assert.ok(shot.content.some(c => c.type === 'image'));
});

test('http_request substitutes vault refs without exposing them', async () => {
  // Set up its own state rather than relying on the capture in the previous test.
  await call('vault_set', { ref: 'example.api_key', value: 'KEY-LIVE-123' });
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

test('secrets used this session are redacted from bridged browser tool output', async () => {
  // A page snapshot taken after filling a password can echo it back. The bridge
  // is stubbed here; call() and the redaction wrapper are the real ones.
  const leaked = 'BRIDGED-SECRET-999';
  await call('vault_set', { ref: 'example.session_secret', value: leaked });
  await call('browser_fill_secret', { target: '#nope', ref: 'example.session_secret' })
    .catch(() => {}); // no browser here; this only registers the value as sensitive

  const fake = {
    profile: 'redact-test', ctx: null, page: null,
    context: async () => null,
    bridge: {
      tools: [], withheld: [],
      names: new Set(['browser_snapshot']),
      call: async () => ({ content: [{ type: 'text', text: `textbox contains ${leaked}` }] }),
      close: async () => {},
    },
  };
  fake.ready = async () => fake;
  sessions.set('redact-test', fake);

  await call('standin_session', { profile: 'redact-test' });
  const out = text(await call('browser_snapshot', {}));
  assert.ok(!out.includes(leaked), `secret leaked through the bridge: ${out}`);
  assert.match(out, /\[REDACTED\]/);
});
