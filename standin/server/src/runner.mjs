import fs from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import { getSecret } from './vault.mjs';
import { openContext, aiAct } from './browser.mjs';

export function loadTask(file) {
  return YAML.parse(fs.readFileSync(file, 'utf8'));
}

export function resolve(str, data) {
  if (typeof str !== 'string') return str;
  return str.replace(/\{\{\s*([^}]+?)\s*\}\}/g, (_, ref) => {
    if (ref.startsWith('vault.')) return getSecret(ref.slice(6));
    if (ref.startsWith('data.')) {
      const v = data[ref.slice(5)];
      if (v == null) throw new Error(`missing data field "${ref.slice(5)}"`);
      return String(v);
    }
    if (ref.startsWith('env.')) return process.env[ref.slice(4)] ?? '';
    throw new Error(`unknown reference {{${ref}}}`);
  });
}

async function setField(page, selector, rawValue, data) {
  const value = resolve(rawValue, data);
  const loc = page.locator(selector).first();
  await loc.waitFor({ state: 'visible' });
  const info = await loc.evaluate(el => ({ tag: el.tagName.toLowerCase(), type: (el.getAttribute('type') || '').toLowerCase() }));
  if (info.tag === 'select') return loc.selectOption({ label: value }).catch(() => loc.selectOption(value));
  if (info.type === 'checkbox' || info.type === 'radio') return loc.setChecked(!/^(false|0|no|off)$/i.test(value));
  if (info.type === 'file') return loc.setInputFiles(value.split(',').map(s => s.trim()));
  await loc.fill('');
  return loc.fill(value);
}

async function visible(page, selector, timeout = 3000) {
  try { await page.locator(selector).first().waitFor({ state: 'visible', timeout }); return true; }
  catch { return false; }
}

export async function runTask(task, { data = {}, dry = false, headed = false, outDir } = {}) {
  const runDir = outDir || path.join(process.cwd(), 'runs', new Date().toISOString().replace(/[:.]/g, '-'));
  fs.mkdirSync(runDir, { recursive: true });
  const { ctx, page } = await openContext({ profile: task.profile || 'default', headed, downloadDir: runDir });
  const extracted = {};
  const log = [];
  try {
    if (task.url) { await page.goto(resolve(task.url, data)); log.push(`goto ${task.url}`); }
    for (const step of task.steps || []) {
      const kind = Object.keys(step)[0];
      const arg = step[kind];
      if (dry && (kind === 'submit' || step.submit === true)) { log.push(`DRY: skipped ${kind}`); continue; }
      switch (kind) {
        case 'goto':
          await page.goto(new URL(resolve(arg, data), page.url()).toString()); break;
        case 'login': {
          // only fires when the sign-in form is actually on screen
          if (arg.ifSelector && !(await visible(page, arg.ifSelector))) { log.push('login: already signed in'); break; }
          for (const [sel, val] of Object.entries(arg.fields || {})) await setField(page, sel, val, data);
          if (arg.submit) await page.locator(arg.submit).first().click();
          if (arg.otp) { // 2FA screen appears after password
            if (await visible(page, arg.otp.selector, arg.otp.timeout || 15000)) {
              await setField(page, arg.otp.selector, arg.otp.value || '{{vault.' + (task.account || '') + '.totp}}', data);
              if (arg.otp.submit) await page.locator(arg.otp.submit).first().click();
            }
          }
          await page.waitForLoadState('networkidle').catch(() => {});
          break;
        }
        case 'fill':
          for (const [sel, val] of Object.entries(arg)) await setField(page, sel, val, data);
          break;
        case 'click':
          await page.locator(resolve(arg, data)).first().click(); break;
        case 'submit':
          await Promise.all([
            page.waitForLoadState('networkidle').catch(() => {}),
            page.locator(resolve(arg, data)).first().click(),
          ]); break;
        case 'press':
          await page.keyboard.press(arg); break;
        case 'waitFor':
          await page.locator(resolve(arg, data)).first().waitFor({ state: 'visible' }); break;
        case 'sleep':
          await page.waitForTimeout(Number(arg)); break;
        case 'extract':
          for (const [name, sel] of Object.entries(arg)) {
            extracted[name] = (await page.locator(sel).first().innerText()).trim();
          }
          break;
        case 'download': {
          const [dl] = await Promise.all([
            page.waitForEvent('download'),
            page.locator(resolve(arg.click, data)).first().click(),
          ]);
          // Security: Prevent path traversal by ensuring the resolved path is within runDir
          const dest = path.resolve(runDir, arg.as ? resolve(arg.as, data) : dl.suggestedFilename());
          if (!dest.startsWith(path.resolve(runDir) + path.sep)) throw new Error('Security: Path traversal detected');
          await dl.saveAs(dest);
          extracted[arg.name || 'download'] = dest;
          break;
        }
        case 'screenshot': {
          // Security: Prevent path traversal by ensuring the resolved path is within runDir
          const shotDest = path.resolve(runDir, `${arg || 'shot'}.png`);
          if (!shotDest.startsWith(path.resolve(runDir) + path.sep)) throw new Error('Security: Path traversal detected');
          await page.screenshot({ path: shotDest, fullPage: true });
          break;
        }
        case 'ai':
          await aiAct(page, resolve(arg, data)); break;
        case 'if': {
          if (await visible(page, arg.selector, arg.timeout || 3000)) {
            await runTask({ profile: task.profile, steps: arg.then }, { data, dry, headed, outDir: runDir });
          }
          break;
        }
        default:
          throw new Error(`unknown step "${kind}"`);
      }
      log.push(kind);
    }
    await page.screenshot({ path: path.join(runDir, 'final.png'), fullPage: true }).catch(() => {});
    fs.writeFileSync(path.join(runDir, 'result.json'), JSON.stringify({ ok: true, extracted, log }, null, 2));
    return { ok: true, extracted, runDir };
  } catch (err) {
    await page.screenshot({ path: path.join(runDir, 'error.png'), fullPage: true }).catch(() => {});
    fs.writeFileSync(path.join(runDir, 'result.json'), JSON.stringify({ ok: false, error: String(err), extracted, log }, null, 2));
    return { ok: false, error: String(err.message || err), extracted, runDir };
  } finally {
    await ctx.close().catch(() => {});
  }
}

export function readRows(file) {
  const text = fs.readFileSync(file, 'utf8');
  if (file.endsWith('.json')) {
    const j = JSON.parse(text);
    return Array.isArray(j) ? j : [j];
  }
  // minimal CSV (quoted fields supported)
  const lines = text.trim().split(/\r?\n/);
  const parse = l => l.match(/("([^"]|"")*"|[^,]*)(,|$)/g).slice(0, -1)
    .map(c => c.replace(/,$/, '').replace(/^"|"$/g, '').replace(/""/g, '"'));
  const head = parse(lines[0]);
  return lines.slice(1).filter(Boolean).map(l => Object.fromEntries(parse(l).map((v, i) => [head[i], v])));
}
