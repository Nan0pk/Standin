import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { chromium } from 'playwright';
import { HOME } from './vault.mjs';

const PROFILES = process.env.STANDIN_PROFILES || path.join(HOME, 'profiles');

// Where the user's real Chrome keeps its profiles.
export function chromeUserData() {
  const h = os.homedir();
  const candidates = process.platform === 'darwin'
    ? [`${h}/Library/Application Support/Google/Chrome`, `${h}/Library/Application Support/Chromium`,
       `${h}/Library/Application Support/Microsoft Edge`, `${h}/Library/Application Support/BraveSoftware/Brave-Browser`]
    : process.platform === 'win32'
      ? [`${process.env.LOCALAPPDATA}\\Google\\Chrome\\User Data`, `${process.env.LOCALAPPDATA}\\Microsoft\\Edge\\User Data`,
         `${process.env.LOCALAPPDATA}\\BraveSoftware\\Brave-Browser\\User Data`]
      : [`${h}/.config/google-chrome`, `${h}/.config/chromium`, `${h}/.config/microsoft-edge`,
         `${h}/.config/BraveSoftware/Brave-Browser`];
  return candidates.find(p => p && fs.existsSync(p)) || null;
}

// Copy the cookies/logins out of the user's real browser profile into a standin
// profile, so anything they already signed into by hand is already signed in here.
// Chrome can stay open; we only read. Launching with channel:'chrome' afterwards
// keeps the OS keyring key that those cookies are encrypted with.
export function importChromeSession(profile, { chromeProfile = 'Default', source } = {}) {
  const src = source || chromeUserData();
  if (!src) throw new Error('no Chrome/Chromium/Edge/Brave profile found on this machine');
  const from = path.join(src, chromeProfile);
  if (!fs.existsSync(from)) throw new Error(`no such browser profile: ${from}`);
  const dest = path.join(PROFILES, profile);
  fs.mkdirSync(path.join(dest, 'Default', 'Network'), { recursive: true });
  const copy = (rel, to) => {
    const s = path.join(from, rel);
    if (!fs.existsSync(s)) return 0;
    const d = path.join(dest, to);
    fs.mkdirSync(path.dirname(d), { recursive: true });
    fs.cpSync(s, d, { recursive: true, force: true });
    return 1;
  };
  let n = 0;
  n += copy('Network/Cookies', 'Default/Network/Cookies');
  n += copy('Cookies', 'Default/Cookies');
  n += copy('Login Data', 'Default/Login Data');
  n += copy('Local Storage', 'Default/Local Storage');
  n += copy('Preferences', 'Default/Preferences');
  if (fs.existsSync(path.join(src, 'Local State'))) {
    fs.copyFileSync(path.join(src, 'Local State'), path.join(dest, 'Local State'));
    n++;
  }
  if (!n) throw new Error('found the profile but no cookie store in it');
  fs.writeFileSync(path.join(dest, '.standin-use-chrome'), '1');
  return { copied: n, from, into: dest };
}

// One persistent profile per site => sign in once, stay signed in.
export async function openContext({ profile = 'default', headed = false, downloadDir, useChrome } = {}) {
  const dir = path.join(PROFILES, profile);
  fs.mkdirSync(dir, { recursive: true });
  const wantsChrome = useChrome ?? (fs.existsSync(path.join(dir, '.standin-use-chrome')) || process.env.STANDIN_BROWSER === 'chrome');
  const base = {
    headless: !headed,
    viewport: { width: 1440, height: 900 },
    acceptDownloads: true,
    downloadsPath: downloadDir,
    args: ['--disable-blink-features=AutomationControlled'],
  };
  let ctx;
  const attempts = [];
  if (process.env.STANDIN_CHROME_PATH) attempts.push({ ...base, executablePath: process.env.STANDIN_CHROME_PATH });
  if (wantsChrome) attempts.push({ ...base, channel: 'chrome' });
  attempts.push(base, { ...base, channel: 'chrome' }, { ...base, channel: 'msedge' });
  let lastErr;
  for (const opts of attempts) {
    try { ctx = await chromium.launchPersistentContext(dir, opts); break; }
    catch (e) { lastErr = e; }
  }
  if (!ctx) throw new Error(`could not start a browser: ${lastErr?.message}\nTry: npx playwright install chromium`);
  ctx.setDefaultTimeout(Number(process.env.STANDIN_TIMEOUT || 20000));
  const page = ctx.pages()[0] || await ctx.newPage();
  return { ctx, page };
}

// Optional AI escape hatch: only loaded if a task uses an `ai:` step.
export async function aiAct(page, instruction) {
  let Stagehand;
  try {
    ({ Stagehand } = await import('@browserbasehq/stagehand'));
  } catch {
    throw new Error('ai step needs: npm i @browserbasehq/stagehand  + ANTHROPIC_API_KEY or OPENAI_API_KEY');
  }
  const sh = new Stagehand({ env: 'LOCAL', page, modelName: process.env.STANDIN_MODEL || 'claude-sonnet-4-5' });
  await sh.init();
  await sh.page.act(instruction);
}
