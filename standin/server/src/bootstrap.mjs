#!/usr/bin/env node
// First-run setup, so the plugin needs no configuration at all.
// Installs deps if missing, then hands off to the MCP server on stdio.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const stamp = path.join(root, 'node_modules', '.standin-ready');

if (!fs.existsSync(stamp)) {
  // stdout is the MCP channel — every setup message must go to stderr.
  const log = m => process.stderr.write(`[standin setup] ${m}\n`);
  log('first run: installing the browser driver (about a minute, once)');
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const r = spawnSync(npm, ['install', '--omit=dev', '--no-audit', '--no-fund', '--loglevel=error'],
    { cwd: root, stdio: ['ignore', 2, 2] });
  if (r.status !== 0) throw new Error('npm install failed; retry setup after resolving the error');
  // Only download Chromium if the machine has no Chrome to borrow.
  const hasChrome = ['google-chrome', 'chromium', 'chrome'].some(b =>
    spawnSync(process.platform === 'win32' ? 'where' : 'which', [b], { stdio: 'ignore' }).status === 0);
  if (!hasChrome) {
    const browser = spawnSync(npm, ['exec', '--', 'playwright', 'install', 'chromium'], { cwd: root, stdio: ['ignore', 2, 2] });
    if (browser.status !== 0) throw new Error('Chromium installation failed; retry setup after resolving the error');
  }
  fs.mkdirSync(path.dirname(stamp), { recursive: true });
  fs.writeFileSync(stamp, new Date().toISOString());
  log('ready');
}

await import(path.join(root, 'src', 'mcp.mjs'));
