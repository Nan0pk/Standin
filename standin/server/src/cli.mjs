#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { spawnSync } from 'node:child_process';
import { loadTask, runTask, readRows } from './runner.mjs';
import { vaultSet, vaultList } from './vault.mjs';
import { openContext } from './browser.mjs';
import { nango } from './apis.mjs';

const argv = process.argv.slice(2);
const cmd = argv[0];
const flag = (name, def) => {
  const i = argv.indexOf(`--${name}`);
  if (i < 0) return def;
  const next = argv[i + 1];
  return !next || next.startsWith('--') ? true : next;
};

const usage = `standin — fills the forms, keeps the logins, calls the APIs

  standin login <task.yaml|profile>     open a real browser, sign in by hand once (session is kept)
  standin run <task.yaml> [--data rows.csv|rows.json] [--dry] [--headed] [--limit N]
  standin record <url> [--profile name] capture selectors with Playwright codegen
  standin vault-set <acct.field> <val>  store a secret (or a TOTP base32 seed as acct.totp)
  standin vault-list
  standin api <provider> <connection> <METHOD> <path> [--body '{"a":1}']
`;

async function main() {
  switch (cmd) {
    case 'login': {
      const target = argv[1];
      if (!target) return console.log(usage);
      let profile = target, url = flag('url');
      if (target.endsWith('.yaml') || target.endsWith('.yml')) {
        const t = loadTask(target);
        profile = t.profile || 'default';
        url = url || t.url;
      }
      const { ctx, page } = await openContext({ profile, headed: true });
      if (url) await page.goto(url);
      console.log(`\nSigning in to profile "${profile}". Do the login + 2FA in the window.\nPress Enter here when you are through.`);
      await new Promise(r => {
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        rl.question('', () => { rl.close(); r(); });
      });
      await ctx.close();
      console.log(`Saved. Runs on profile "${profile}" are signed in from now on.`);
      break;
    }
    case 'run': {
      const file = argv[1];
      if (!file) return console.log(usage);
      const task = loadTask(file);
      const dataFile = flag('data');
      const rows = typeof dataFile === 'string' ? readRows(dataFile) : [{}];
      const limit = Number(flag('limit', rows.length));
      const results = [];
      for (const [i, row] of rows.slice(0, limit).entries()) {
        const r = await runTask(task, { data: row, dry: !!flag('dry'), headed: !!flag('headed') });
        results.push({ row: i + 1, ...r });
        console.log(`${r.ok ? 'ok  ' : 'FAIL'} row ${i + 1}${r.ok ? '' : ' — ' + r.error} ${JSON.stringify(r.extracted)} (${r.runDir})`);
      }
      const summary = path.join(process.cwd(), 'runs', 'summary.json');
      fs.mkdirSync(path.dirname(summary), { recursive: true });
      fs.writeFileSync(summary, JSON.stringify(results, null, 2));
      const bad = results.filter(r => !r.ok).length;
      console.log(`\n${results.length - bad}/${results.length} done. Screenshots + result.json per run. Summary: ${summary}`);
      process.exitCode = bad ? 1 : 0;
      break;
    }
    case 'record': {
      const url = argv[1] || 'about:blank';
      const profile = flag('profile', 'default');
      const dir = path.join(process.env.STANDIN_PROFILES || path.join(process.cwd(), 'profiles'), String(profile));
      spawnSync('npx', ['playwright', 'codegen', '--user-data-dir', dir, url], { stdio: 'inherit' });
      break;
    }
    case 'vault-set': {
      if (!argv[2]) return console.log(usage);
      vaultSet(argv[1], argv.slice(2).join(' '));
      console.log(`stored ${argv[1]}`);
      break;
    }
    case 'vault-list':
      console.log(vaultList().join('\n') || '(empty)');
      break;
    case 'api': {
      const [, provider, connection, method, p] = argv;
      if (!p) return console.log(usage);
      const body = flag('body');
      const out = await nango({ provider, connection, method: method.toUpperCase(), path: p, body: typeof body === 'string' ? body : undefined });
      console.log(typeof out === 'string' ? out : JSON.stringify(out, null, 2));
      break;
    }
    default:
      console.log(usage);
  }
}

main().catch(e => { console.error('error:', e.message); process.exit(1); });
