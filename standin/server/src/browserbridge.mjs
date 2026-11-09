// Bridges Microsoft's Playwright MCP into standin, in-process.
//
// Why in-process rather than a second server in .mcp.json: the credential tools
// (browser_fill_secret, browser_capture_secret) must type into and read from the
// SAME browser the agent is driving. A sibling server would get its own browser
// and the secrets would land in a different window.
//
// createConnection(config, contextGetter) lets us hand Playwright MCP a context
// we own, so one persistent profile per site is preserved while the browser
// plumbing itself is Microsoft's.
import { createConnection } from '@playwright/mcp';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

// Tools that would defeat the entire point of a credential vault. These are
// filtered out of the list we advertise, so the model never sees them.
//
//   browser_run_code_unsafe  executes arbitrary code in the page; it could read
//                            a filled secret straight out of the DOM.
//   *_get / *_list / storage_state  return cookies, localStorage and session
//                            state to the model. Writing them is fine (that is
//                            how a session is restored); reading them back is
//                            exactly the leak standin exists to prevent.
const NEVER_EXPOSE = new Set([
  'browser_run_code_unsafe',
  'browser_storage_state',
  'browser_cookie_get',
  'browser_cookie_list',
  'browser_localstorage_get',
  'browser_localstorage_list',
  'browser_sessionstorage_get',
  'browser_sessionstorage_list',
]);

/**
 * Open an in-process Playwright MCP connection.
 * @param {object} opts
 * @param {() => Promise<import('playwright').BrowserContext>} opts.contextGetter
 * @param {object} [opts.config] forwarded to createConnection
 */
export async function openBridge({ contextGetter, config = {} } = {}) {
  const server = await createConnection(config, contextGetter);
  const client = new Client({ name: 'standin-bridge', version: '0.4.0' });
  const [serverSide, clientSide] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverSide), client.connect(clientSide)]);

  const listed = await client.listTools();
  const tools = listed.tools.filter(t => !NEVER_EXPOSE.has(t.name));
  const withheld = listed.tools.filter(t => NEVER_EXPOSE.has(t.name)).map(t => t.name);

  return {
    tools,
    withheld,
    names: new Set(tools.map(t => t.name)),
    call: (name, args = {}) => client.callTool({ name, arguments: args }),
    close: () => client.close().catch(() => {}),
  };
}

export { NEVER_EXPOSE };
