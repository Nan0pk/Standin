#!/usr/bin/env node
// standin MCP server: a browser + a vault + an HTTP caller, exposed as tools.
// Point any agent (Claude Code, Cowork, Cursor) at this and it can log into
// things, grab API keys, and paste them elsewhere — without secrets ever
// passing through the model's context.
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import fs from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import { openContext, importChromeSession, chromeUserData } from './browser.mjs';
import { getSecret, vaultSet, vaultList, vaultForget, importDocument } from './vault.mjs';
import { loadTask, runTask, readRows } from './runner.mjs';

let session = null; // { ctx, page, profile }

async function ensure(profile = 'default', headed) {
  if (session && session.profile === profile) return session;
  if (session) { await session.ctx.close().catch(() => {}); session = null; }
  const headless = headed === undefined ? process.env.STANDIN_HEADED !== '1' : !headed;
  const s = await openContext({ profile, headed: !headless });
  session = { ...s, profile };
  return session;
}

const INTERACTIVE = 'a,button,input,select,textarea,summary,[role=button],[role=link],[role=tab],[contenteditable=true]';

async function snapshot(page) {
  const els = await page.$$eval(INTERACTIVE, nodes => nodes.slice(0, 120).map((el, i) => {
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) return null;
    const label = el.getAttribute('aria-label') || el.getAttribute('placeholder') || el.getAttribute('name') ||
      (el.labels && el.labels[0] && el.labels[0].innerText) || el.innerText || '';
    let sel = el.id ? `#${CSS.escape(el.id)}`
      : el.getAttribute('name') ? `${el.tagName.toLowerCase()}[name="${el.getAttribute('name')}"]`
      : el.getAttribute('data-testid') ? `[data-testid="${el.getAttribute('data-testid')}"]`
      : null;
    if (!sel) {
      const same = [...document.querySelectorAll(el.tagName)];
      sel = `${el.tagName.toLowerCase()}:nth-of-type(${same.indexOf(el) + 1})`;
    }
    return { tag: el.tagName.toLowerCase(), type: el.getAttribute('type') || '', label: String(label).trim().slice(0, 60), selector: sel };
  }).filter(Boolean));
  const text = (await page.locator('body').innerText().catch(() => '')).slice(0, 3000);
  return `URL: ${page.url()}\nTITLE: ${await page.title()}\n\nVISIBLE TEXT:\n${text}\n\nINTERACTIVE ELEMENTS:\n` +
    els.map(e => `- ${e.tag}${e.type ? `[${e.type}]` : ''} "${e.label}" -> ${e.selector}`).join('\n');
}

const tools = [
  { name: 'browser_open', description: 'Open a URL in a persistent browser profile (stays logged in between runs).',
    inputSchema: { type: 'object', properties: { url: { type: 'string' }, profile: { type: 'string', description: 'session name, e.g. the site name' }, headed: { type: 'boolean' } }, required: ['url'] } },
  { name: 'browser_snapshot', description: 'Read the current page: URL, visible text, and every clickable/fillable element with a selector to use.',
    inputSchema: { type: 'object', properties: {} } },
  { name: 'browser_click', description: 'Click an element by CSS selector or exact visible text.',
    inputSchema: { type: 'object', properties: { selector: { type: 'string' }, text: { type: 'string' } } } },
  { name: 'browser_type', description: 'Type non-secret text into a field. Handles text inputs, selects and checkboxes.',
    inputSchema: { type: 'object', properties: { selector: { type: 'string' }, value: { type: 'string' }, enter: { type: 'boolean' } }, required: ['selector', 'value'] } },
  { name: 'browser_fill_secret', description: 'Fill a field with a vault secret (e.g. "github.password"). The value is never returned to you.',
    inputSchema: { type: 'object', properties: { selector: { type: 'string' }, ref: { type: 'string', description: 'account.field in the vault' } }, required: ['selector', 'ref'] } },
  { name: 'browser_fill_totp', description: 'Fill a 2FA field with a fresh 6-digit code from the vault TOTP seed.',
    inputSchema: { type: 'object', properties: { selector: { type: 'string' }, account: { type: 'string' } }, required: ['selector', 'account'] } },
  { name: 'browser_read', description: 'Read text from a selector (use to grab a freshly generated API key, confirmation number, etc).',
    inputSchema: { type: 'object', properties: { selector: { type: 'string' } }, required: ['selector'] } },
  { name: 'browser_capture_secret', description: 'Copy a value straight from the page into the vault WITHOUT showing it to you. Use for API keys/tokens.',
    inputSchema: { type: 'object', properties: { selector: { type: 'string' }, ref: { type: 'string', description: 'where to store it, e.g. "openai.api_key"' } }, required: ['selector', 'ref'] } },
  { name: 'browser_screenshot', description: 'Screenshot the page (returned as an image).', inputSchema: { type: 'object', properties: {} } },
  { name: 'browser_wait', description: 'Wait for a selector to appear, or for N milliseconds.',
    inputSchema: { type: 'object', properties: { selector: { type: 'string' }, ms: { type: 'number' } } } },
  { name: 'vault_set', description: 'Store a secret or a TOTP base32 seed. ref is "account.field".',
    inputSchema: { type: 'object', properties: { ref: { type: 'string' }, value: { type: 'string' } }, required: ['ref', 'value'] } },
  { name: 'vault_list', description: 'List which accounts/fields exist in the vault (never the values).', inputSchema: { type: 'object', properties: {} } },
  { name: 'vault_import_document', description: 'Read one credentials file (notes, .md, .txt, .env, .json, or a Chrome/1Password/Bitwarden CSV export) and file everything in it into the vault. Values are parsed on the server and never shown to you. Use this the moment the user offers a credentials document.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' }, account: { type: 'string', description: 'fallback account name if the file has no headings' }, delete_after: { type: 'boolean', description: 'delete the source file once imported; this is not secure erasure' } }, required: ['path'] } },
  { name: 'vault_forget', description: 'Delete an account or a single field from the vault.',
    inputSchema: { type: 'object', properties: { ref: { type: 'string' } }, required: ['ref'] } },
  { name: 'browser_import_login', description: 'Copy the logged-in session out of the user\'s own Chrome/Edge/Brave into a standin profile, so sites they already signed into by hand need no password at all. Try this before asking for credentials.',
    inputSchema: { type: 'object', properties: { profile: { type: 'string', description: 'standin profile to create, e.g. the site name' }, chrome_profile: { type: 'string', description: 'e.g. "Default" or "Profile 1"' } }, required: ['profile'] } },
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

async function target(page, a) {
  if (a.selector) return page.locator(a.selector).first();
  if (a.text) return page.getByText(a.text, { exact: false }).first();
  throw new Error('give a selector or text');
}

async function call(name, a = {}) {
  if (name === 'browser_open') {
    const s = await ensure(a.profile || 'default', a.headed);
    await s.page.goto(a.url, { waitUntil: 'domcontentloaded' });
    return ok(await snapshot(s.page));
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
    return ok(`copied ${r.copied} session file(s) from ${r.from}. Profile "${a.profile}" should now already be signed in wherever that browser was. Open a page and check.`);
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

  const s = session || await ensure();
  const page = s.page;
  switch (name) {
    case 'browser_snapshot': return ok(await snapshot(page));
    case 'browser_click': {
      await (await target(page, a)).click();
      await page.waitForLoadState('domcontentloaded').catch(() => {});
      await page.waitForTimeout(400);
      return ok(await snapshot(page));
    }
    case 'browser_type': {
      const loc = page.locator(a.selector).first();
      const info = await loc.evaluate(el => ({ tag: el.tagName.toLowerCase(), type: (el.getAttribute('type') || '').toLowerCase() }));
      if (info.tag === 'select') await loc.selectOption({ label: a.value }).catch(() => loc.selectOption(a.value));
      else if (info.type === 'checkbox' || info.type === 'radio') await loc.setChecked(!/^(false|0|no|off)$/i.test(a.value));
      else { await loc.fill(''); await loc.fill(a.value); }
      if (a.enter) await loc.press('Enter');
      return ok(`typed into ${a.selector}`);
    }
    case 'browser_fill_secret':
      await page.locator(a.selector).first().fill(remember(getSecret(a.ref)));
      return ok(`filled ${a.selector} from vault ${a.ref} (value hidden)`);
    case 'browser_fill_totp':
      await page.locator(a.selector).first().fill(remember(getSecret(`${a.account}.totp`)));
      return ok(`filled a fresh 2FA code into ${a.selector}`);
    case 'browser_read':
      return ok((await page.locator(a.selector).first().innerText()).trim().slice(0, 2000));
    case 'browser_capture_secret': {
      const loc = page.locator(a.selector).first();
      const val = (await loc.inputValue().catch(() => null)) ?? (await loc.innerText());
      const clean = val.trim();
      if (!clean) throw new Error('nothing to capture at that selector');
      vaultSet(a.ref, clean);
      remember(clean);
      return ok(`captured ${clean.length} chars into vault as ${a.ref} (value hidden). Refer to it later as {{vault.${a.ref}}}`);
    }
    case 'browser_screenshot': {
      const buf = await page.screenshot({ fullPage: false });
      return { content: [{ type: 'image', data: buf.toString('base64'), mimeType: 'image/png' }] };
    }
    case 'browser_wait':
      if (a.selector) await page.locator(a.selector).first().waitFor({ state: 'visible' });
      else await page.waitForTimeout(a.ms || 1000);
      return ok('done');
    default: throw new Error(`unknown tool ${name}`);
  }
}

export async function shutdown() {
  if (session) { await session.ctx.close().catch(() => {}); session = null; }
}

export { call, tools };

// only speak MCP when launched as a server (so tests can import `call` directly)
if (process.argv[1] && ['mcp.mjs', 'bootstrap.mjs'].includes(path.basename(process.argv[1]))) {
  const server = new Server({ name: 'standin', version: '0.2.0' }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
  server.setRequestHandler(CallToolRequestSchema, async req => {
    try { return await call(req.params.name, req.params.arguments || {}); }
    catch (e) { return { content: [{ type: 'text', text: redact(`error: ${e.message}`) }], isError: true }; }
  });
  await server.connect(new StdioServerTransport());
}
