import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawnSync } from 'node:child_process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'standin-security-'));
process.env.STANDIN_HOME = path.join(tmp, 'home');
process.env.STANDIN_PROFILES = path.join(tmp, 'profiles');
const vault = path.join(tmp, 'vault.enc');
const moduleUrl = new URL('../src/vault.mjs', import.meta.url).href;
const run = (code, pass) => spawnSync(process.execPath, ['--input-type=module', '-e', code], {
  env: { ...process.env, STANDIN_HOME: tmp, STANDIN_VAULT_FILE: vault, STANDIN_PASSPHRASE: pass },
  encoding: 'utf8',
});

test('wrong passphrase cannot replace an existing vault', () => {
  const code = `const { vaultSet } = await import(${JSON.stringify(moduleUrl)}); vaultSet('example.password', 'synthetic');`;
  assert.equal(run(code, 'correct-passphrase').status, 0);
  const before = fs.readFileSync(vault);
  assert.notEqual(run(code, 'wrong-passphrase').status, 0);
  assert.deepEqual(fs.readFileSync(vault), before);
});

test('missing key does not create a replacement for an existing vault', () => {
  const code = `const { vaultSet } = await import(${JSON.stringify(moduleUrl)}); vaultSet('example.password', 'synthetic');`;
  const result = run(code, '');
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /vault key is missing/);
  assert.equal(fs.existsSync(path.join(tmp, 'key')), false);
});

test('MCP server starts and lists its tools', async () => {
  const client = new Client({ name: 'standin-test', version: '1.0.0' });
  const transport = new StdioClientTransport({ command: process.execPath, args: [new URL('../src/mcp.mjs', import.meta.url).pathname] });
  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    const names = tools.map(t => t.name);
    // standin's own credential tools
    assert.ok(names.includes('vault_import_document'), 'missing vault_import_document');
    assert.ok(names.includes('browser_fill_secret'), 'missing browser_fill_secret');
    assert.ok(names.includes('browser_capture_secret'), 'missing browser_capture_secret');
    assert.ok(names.includes('standin_session'), 'missing standin_session');
    // browser plumbing now comes from the bridged Playwright MCP
    assert.ok(names.includes('browser_navigate'), 'bridged browser_navigate missing');
    assert.ok(names.includes('browser_snapshot'), 'bridged browser_snapshot missing');
    // tools that would let the model read a secret back must never be advertised
    for (const banned of ['browser_run_code_unsafe', 'browser_storage_state', 'browser_cookie_get',
                          'browser_cookie_list', 'browser_localstorage_get', 'browser_sessionstorage_get']) {
      assert.ok(!names.includes(banned), `${banned} must not be exposed`);
    }
  } finally { await client.close(); }
});

test('HTTP responses redact a vault value echoed by the remote service', async () => {
  const server = http.createServer((req, res) => res.end(req.headers.authorization));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const client = new Client({ name: 'standin-test', version: '1.0.0' });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [new URL('../src/mcp.mjs', import.meta.url).pathname],
    env: { ...process.env, STANDIN_HOME: path.join(tmp, 'mcp'), STANDIN_PASSPHRASE: 'test' },
  });
  try {
    await client.connect(transport);
    await client.callTool({ name: 'vault_set', arguments: { ref: 'example.token', value: 'synthetic-secret-123' } });
    const result = await client.callTool({ name: 'http_request', arguments: {
      url: `http://127.0.0.1:${server.address().port}/`,
      headers: { Authorization: 'Bearer {{vault.example.token}}' },
    } });
    assert.doesNotMatch(JSON.stringify(result), /synthetic-secret-123/);
    assert.match(JSON.stringify(result), /\[REDACTED\]/);
  } finally {
    await client.close();
    await new Promise(resolve => server.close(resolve));
  }
});

test('vault operations prevent prototype pollution', () => {
  const code = `
    const { vaultSet } = await import(${JSON.stringify(moduleUrl)});
    vaultSet('__proto__.polluted', 'yes');
  `;
  const result = run(code, 'correct-passphrase');
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /forbidden keys used/);

  const code2 = `
    const { vaultSet } = await import(${JSON.stringify(moduleUrl)});
    vaultSet('constructor.prototype', 'yes');
  `;
  const result2 = run(code2, 'correct-passphrase');
  assert.notEqual(result2.status, 0);
  assert.match(result2.stderr, /forbidden keys used/);
});

test('mcp run_task prevents path traversal', async () => {
  const { call } = await import('../src/mcp.mjs');
  await assert.rejects(
    () => call('run_task', { name: '../../../../../../tmp/hacked.yaml' }),
    /path traversal detected/
  );
});

test('runner prevents path traversal in download steps', async () => {
  const { runTask } = await import('../src/runner.mjs');
  const task = {
    profile: 'test',
    steps: [
      {
        download: {
           click: '#download-btn',
           as: '../../../../../../../../../../../../../tmp/hacked-standin.txt'
        }
      }
    ]
  };

  const htmlPath = path.join(tmp, 'index.html');
  fs.writeFileSync(htmlPath, `
    <html>
      <body>
        <a id="download-btn" href="data:text/plain;charset=utf-8,HACKED" download="test.txt">Download</a>
      </body>
    </html>
  `);

  task.url = 'file://' + htmlPath;

  const runs = path.join(tmp, 'runs');
  const out = await runTask(task, { outDir: runs });

  assert.equal(out.ok, false);
  assert.match(out.error, /path traversal detected/);
  assert.equal(fs.existsSync('/tmp/hacked-standin.txt'), false);
});
