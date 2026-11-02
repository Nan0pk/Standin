#!/usr/bin/env node
// standin MCP server: the credential layer, on top of Playwright MCP's browser.
//
// standin no longer implements browser plumbing. Navigation, clicking, typing,
// snapshots and screenshots come from Microsoft's Playwright MCP, bridged in
// process so the credential tools below operate on the very same browser the
// agent is driving. What standin keeps is the part nothing else does: secrets
// that go into pages and come off pages without ever entering the model's
// context.
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import fs from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import { openContext, importChromeSession } from './browser.mjs';
import { HOME, getSecret, vaultSet, vaultList, vaultForget, importDocument } from './vault.mjs';
import { loadTask, runTask, readRows } from './runner.mjs';
import { openBridge } from './browserbridge.mjs';

// --- sessions -----------------------------------------------------------------
// One persistent browser profile per site, each with its own Playwright MCP
// connection. The browser is created lazily: listing tools never launches one.
const sessions = new Map();
let activeProfile = null;

function bridgeConfig() {
  return {
    // Values minted at runtime that must never reach the model in a URL. This is
    // a convenience layer; the authoritative redaction is the dynamic one below.
    redactUrlParams: ['access_token', 'id_token', 'code', 'token', 'session_id', 'sid', 'sig', 'signature', 'api_key'],
    outputDir: path.join(HOME, 'output'),
  };
}

function sessionFor(profile) {
  if (sessions.has(profile)) return sessions.get(profile);
  const s = { profile, ctx: null, page: null, bridge: null, promise: null };
  // The single place a browser is launched; also the contextGetter Playwright
  // MCP calls when one of its tools first needs a page.
  s.context = async () => {
    if (!s.ctx) {
      const o = await openContext({ profile, headed: process.env.STANDIN_HEADED === '1' });
      s.ctx = o.ctx; s.page = o.page;
    }
    return s.ctx;
  };
  s.ready = () => (s.promise ||= openBridge({ contextGetter: s.context, config: bridgeConfig() })
    .then(bridge => { s.bridge = bridge; return s; }));
  sessions.set(profile, s);
  return s;
}

async function active() {
  return (await sessionFor(activeProfile || 'default').ready());
}

// The page the agent is looking at: the most recently opened real page.
async function activePage() {
  const s = await active();
  const ctx = await s.context();
  const pages = ctx.pages().filter(p => !p.url().startsWith('devtools://'));
  return pages.at(-1) || s.page;
}

// Playwright MCP addresses an element by its snapshot ref ("e12") or by a unique
// CSS selector. Accept both, so the credential tools and the bridged browser
// tools share one addressing scheme instead of the agent juggling two.
function locatorFor(page, a) {
  const raw = a.target || a.selector;
  if (!raw) throw new Error('give a target: a snapshot ref like "e12", or a CSS selector');
  return page.locator(/^e\d+$/.test(raw) ? `aria-ref=${raw}` : raw).first();
}

// --- tools standin owns -------------------------------------------------------
// Same addressing as Playwright MCP's own tools: a snapshot ref ("e12") or a
// unique CSS selector. `selector` is kept as an accepted alias.
const TARGET = {
  target: { type: 'string', description: 'Element reference from the page snapshot (e.g. "e12"), or a unique CSS selector' },
  selector: { type: 'string', description: 'Alias for target' },
};

const tools = [
  { name: 'standin_session', description: 'Switch the active browser session, creating it if needed. Use one session per site so its login persists between runs. Every browser_* tool acts on the active session.',
    inputSchema: { type: 'object', properties: { profile: { type: 'string', description: 'session name, e.g. the site name' }, headed: { type: 'boolean', description: 'show the browser window' } }, required: ['profile'] } },
  { name: 'browser_fill_secret', description: 'Fill a field with a vault secret (e.g. "github.password"). The value is never returned to you.',
    inputSchema: { type: 'object', properties: { ...TARGET, ref: { type: 'string', description: 'account.field in the vault' } }, required: ['target', 'ref'] } },
  { name: 'browser_fill_totp', description: 'Fill a 2FA field with a fresh 6-digit code from the vault TOTP seed.',
    inputSchema: { type: 'object', properties: { ...TARGET, account: { type: 'string' } }, required: ['target', 'account'] } },
  { name: 'browser_capture_secret', description: 'Copy a value straight from the page into the vault WITHOUT showing it to you. Use for API keys/tokens.',
    inputSchema: { type: 'object', properties: { ...TARGET, ref: { type: 'string', description: 'where to store it, e.g. "openai.api_key"' } }, required: ['target', 'ref'] } },
  { name: 'browser_read', description: 'Read text from an element (a confirmation number, a total, a status). Not for secrets — use browser_capture_secret for those.',
    inputSchema: { type: 'object', properties: { ...TARGET }, required: ['target'] } },
  { name: 'browser_import_login', description: 'Copy the logged-in session out of the user\'s own Chrome/Edge/Brave into a standin session, so sites they already signed into by hand need no password at all. Try this before asking for credentials.',
    inputSchema: { type: 'object', properties: { profile: { type: 'string', description: 'standin session to create, e.g. the site name' }, chrome_profile: { type: 'string', description: 'e.g. "Default" or "Profile 1"' } }, required: ['profile'] } },
  { name: 'vault_set', description: 'Store a secret or a TOTP base32 seed. ref is "account.field".',
    inputSchema: { type: 'object', properties: { ref: { type: 'string' }, value: { type: 'string' } }, required: ['ref', 'value'] } },
  { name: 'vault_list', description: 'List which accounts/fields exist in the vault (never the values).', inputSchema: { type: 'object', properties: {} } },
  { name: 'vault_import_document', description: 'Read one credentials file (notes, .md, .txt, .env, .json, or a Chrome/1Password/Bitwarden CSV export) and file everything in it into the vault. Values are parsed on the server and never shown to you. Use this the moment the user offers a credentials document.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' }, account: { type: 'string', description: 'fallback account name if the file has no headings' }, delete_after: { type: 'boolean', description: 'delete the source file once imported; this is not secure erasure' } }, required: ['path'] } },
  { name: 'vault_forget', description: 'Delete an account or a single field from the vault.',
    inputSchema: { type: 'object', properties: { ref: { type: 'string' } }, required: ['ref'] } },
  { name: 'http_request', description: 'Call an API. Any {{vault.acct.field}} in url/headers/body is substituted server-side, so keys never enter your context.',
    inputSchema: { type: 'object', properties: { method: { type: 'string' }, url: { type: 'string' }, headers: { type: 'object' }, body: { type: 'string' } }, required: ['url'] } },
  { name: 'save_task', description: 'Save the steps you just performed as a repeatable task file, so this job can run again unattended.',
    inputSchema: { type: 'object', properties: { name: { type: 'string' }, yaml: { type: 'string', description: 'task YAML (see tasks/example-portal.yaml)' } }, required: ['name', 'yaml'] } },
  { name: 'run_task', description: 'Run a saved task, optionally once per row of a CSV/JSON data file.',
    inputSchema: { type: 'object', properties: { name: { type: 'string' }, data: { type: 'string' }, dry: { type: 'boolean' } }, required: ['name'] } },
];

// Protect values used during this server session from accidental echoing by pages or APIs.
// This cannot identify previously unknown secrets displayed by a page.
const sensitive = new Set();
const remember = value => { if (typeof value === 'string' && value) sensitive.add(value); return value; };
const redact = value => [...sensitive].sort((a, b) => b.length - a.length)
  .reduce((text, secret) => text.replaceAll(secret, '[REDACTED]'), String(value));
const ok = t => ({ content: [{ type: 'text', text: redact(t) }] });

// Playwright MCP returns a content array; scrub the text parts on the way out,
// since a snapshot taken after browser_fill_secret can contain the value.
const redactResult = result => ({
  ...result,
  content: (result.content || []).map(c =>
    c.type === 'text' ? { ...c, text: redact(c.text) } : c),
});

async function call(name, a = {}) {
  if (name === 'standin_session') {
    activeProfile = a.profile || 'default';
    if (a.headed !== undefined) process.env.STANDIN_HEADED = a.headed ? '1' : '0';
    const s = await active();
    return ok(`active session is now "${s.profile}"` +
      (s.bridge ? ` (${s.bridge.tools.length} browser tools available).` : '.'));
  }
  if (name === 'vault_set') { vaultSet(a.ref, a.value); remember(a.value); return ok(`stored ${a.ref}`); }
  if (name === 'vault_list') { return ok(vaultList().join('\n') || '(empty)'); }
  if (name === 'vault_forget') { return ok(vaultForget(a.ref) ? `forgot ${a.ref}` : `nothing stored at ${a.ref}`); }
  if (name === 'vault_import_document') {
    const summary = importDocument(a.path, { defaultAccount: a.account });
    const accounts = Object.entries(summary);
    if (!accounts.length) return ok('found nothing that looked like a credential in that file');
    if (a.delete_after) fs.rmSync(a.path, { force: true });
    return ok(`imported ${accounts.length} account(s), values hidden:\n` +
      accounts.map(([k, v]) => `- ${k}: ${[...new Set(v)].join(', ')}`).join('\n') +
      (a.delete_after ? `\nsource file deleted.` : `\nsource file left in place — say the word and I'll delete it.`) +
      `\nrefer to these as {{vault.<account>.<field>}}`);
  }
  if (name === 'browser_import_login') {
    const r = importChromeSession(a.profile, { chromeProfile: a.chrome_profile || 'Default' });
    activeProfile = a.profile;
    return ok(`copied ${r.copied} session file(s) from ${r.from}. Session "${a.profile}" should now already be signed in wherever that browser was. Open a page and check.`);
  }
  if (name === 'http_request') {
    const sub = s => String(s).replace(/\{\{\s*vault\.([^}\s]+)\s*\}\}/g, (_, r) => remember(getSecret(r)));
    const res = await fetch(sub(a.url), {
      method: (a.method || 'GET').toUpperCase(),
      headers: Object.fromEntries(Object.entries(a.headers || {}).map(([k, v]) => [k, sub(v)])),
      body: a.body ? sub(a.body) : undefined,
    });
    const text = await res.text();
    return ok(`${res.status} ${res.statusText}\n${text.slice(0, 4000)}`);
  }
  if (name === 'save_task') {
    const dir = path.join(process.cwd(), 'tasks');
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, `${a.name.replace(/[^\w.-]/g, '_')}.yaml`);
    YAML.parse(a.yaml); // validate
    fs.writeFileSync(file, a.yaml);
    return ok(`saved ${file} — run it with: node src/cli.mjs run ${path.relative(process.cwd(), file)}`);
  }
  if (name === 'run_task') {
    const file = path.join(process.cwd(), 'tasks', a.name.endsWith('.yaml') ? a.name : `${a.name}.yaml`);
    const task = loadTask(file);
    const rows = a.data ? readRows(a.data) : [{}];
    const out = [];
    for (const row of rows) out.push(await runTask(task, { data: row, dry: !!a.dry }));
    return ok(JSON.stringify(out.map(o => ({ ok: o.ok, extracted: o.extracted, error: o.error, runDir: o.runDir })), null, 2));
  }

  switch (name) {
    case 'browser_fill_secret': {
      const page = await activePage();
      await locatorFor(page, a).fill(remember(getSecret(a.ref)));
      return ok(`filled ${a.target || a.selector} from vault ${a.ref} (value hidden)`);
    }
    case 'browser_fill_totp': {
      const page = await activePage();
      await locatorFor(page, a).fill(remember(getSecret(`${a.account}.totp`)));
      return ok(`filled a fresh 2FA code into ${a.target || a.selector}`);
    }
    case 'browser_read': {
      const page = await activePage();
      return ok((await locatorFor(page, a).innerText()).trim().slice(0, 2000));
    }
    case 'browser_capture_secret': {
      const page = await activePage();
      const loc = locatorFor(page, a);
      const val = (await loc.inputValue().catch(() => null)) ?? (await loc.innerText());
      const clean = val.trim();
      if (!clean) throw new Error('nothing to capture at that selector');
      vaultSet(a.ref, clean);
      remember(clean);
      return ok(`captured ${clean.length} chars into vault as ${a.ref} (value hidden). Refer to it later as {{vault.${a.ref}}}`);
    }
  }

  // Everything else is Playwright MCP's: navigate, snapshot, click, type, wait,
  // screenshot, tabs, forms, files, network, cookies, verification, and more.
  const s = await active();
  if (!s.bridge.names.has(name)) throw new Error(`unknown tool ${name}`);
  const result = await s.bridge.call(name, a);
  // A bridged failure arrives as a result, not an exception. Surface it as one,
  // otherwise the agent reads the error text as page content and carries on.
  if (result.isError) {
    const detail = (result.content || []).map(c => c.text || '').join('\n').trim();
    throw new Error(detail.replace(/^#+\s*Error\s*/i, '') || `browser tool ${name} failed`);
  }
  return redactResult(result);
}

export async function shutdown() {
  for (const s of sessions.values()) {
    await s.bridge?.close().catch(() => {});
    if (s.ctx) await s.ctx.close().catch(() => {});
  }
  sessions.clear();
  activeProfile = null;
}

export { call, tools, sessions };

// only speak MCP when launched as a server (so tests can import `call` directly)
if (process.argv[1] && ['mcp.mjs', 'bootstrap.mjs'].includes(path.basename(process.argv[1]))) {
  const server = new Server({ name: 'standin', version: '0.4.0' }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const s = await active();
    return { tools: [...tools, ...s.bridge.tools] };
  });
  server.setRequestHandler(CallToolRequestSchema, async req => {
    try { return await call(req.params.name, req.params.arguments || {}); }
    catch (e) { return { content: [{ type: 'text', text: redact(`error: ${e.message}`) }], isError: true }; }
  });
  await server.connect(new StdioServerTransport());
}
