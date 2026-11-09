import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'standin-elicit-'));
process.env.STANDIN_HOME = path.join(tmp, 'home');
process.env.STANDIN_VAULT = 'file';
process.env.STANDIN_PASSPHRASE = 'test-pass';
process.env.STANDIN_PROFILES = path.join(tmp, 'profiles');

const { createMcpServer, shutdown } = await import('../src/mcp.mjs');
const { getSecret } = await import('../src/vault.mjs');
test.after(() => shutdown());

// Wire the real server to a real client in memory. `respond` stands in for the
// human sitting in front of their MCP client.
async function withClient(respond, { elicitation = true } = {}) {
  const server = createMcpServer();
  const client = new Client({ name: 'elicit-test', version: '1.0.0' },
    { capabilities: elicitation ? { elicitation: {} } : {} });
  const seen = [];
  // The SDK refuses to register this handler unless the client declares the
  // capability, which is exactly the case under test in the last test.
  if (elicitation) {
    client.setRequestHandler(ElicitRequestSchema, async req => {
      seen.push(req.params);
      return respond(req.params);
    });
  }
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return { client, seen, close: () => client.close() };
}

const text = r => (r.content || []).map(c => c.text || `[${c.type}]`).join('\n');

test('vault_add takes a secret from the human and it never reaches the model', async () => {
  const { client, seen, close } = await withClient(() =>
    ({ action: 'accept', content: { value: 'TYPED-BY-HUMAN-42' } }));
  try {
    const res = await client.callTool({ name: 'vault_add', arguments: { ref: 'human.token' } });
    assert.equal(res.isError, undefined, text(res));
    assert.ok(seen.length === 1, 'the user was never prompted');
    assert.match(seen[0].message, /human\.token/);
    // the value landed in the vault...
    assert.equal(getSecret('human.token'), 'TYPED-BY-HUMAN-42');
    // ...and never appeared in what the model sees
    assert.ok(!JSON.stringify(res).includes('TYPED-BY-HUMAN-42'), 'secret leaked to the model');
    assert.match(text(res), /value hidden/);
  } finally { await close(); }
});

test('standin_ask_user blocks for a decision and returns the answer', async () => {
  const { client, seen, close } = await withClient(() =>
    ({ action: 'accept', content: { answer: 'cancel the subscription' } }));
  try {
    const res = await client.callTool({
      name: 'standin_ask_user',
      arguments: { question: 'This plan upgrade costs $20/month. Proceed?', choices: ['proceed', 'cancel the subscription'] },
    });
    assert.match(text(res), /cancel the subscription/);
    assert.deepEqual(seen[0].requestedSchema.properties.answer.enum, ['proceed', 'cancel the subscription']);
  } finally { await close(); }
});

test('the user declining is reported, not silently ignored', async () => {
  const { client, close } = await withClient(() => ({ action: 'decline' }));
  try {
    const res = await client.callTool({ name: 'vault_add', arguments: { ref: 'human.nope' } });
    assert.equal(res.isError, true);
    assert.match(text(res), /declined/);
  } finally { await close(); }
});

test('without elicitation support the agent is told to ask in the chat instead', async () => {
  const { client, close } = await withClient(() => ({ action: 'accept', content: {} }), { elicitation: false });
  try {
    const res = await client.callTool({ name: 'standin_ask_user', arguments: { question: 'Proceed?' } });
    assert.equal(res.isError, true);
    assert.match(text(res), /ask them in the conversation/);
  } finally { await close(); }
});
