// Secret access. Backends: env | file (AES-256-GCM) | keepassxc | bitwarden
// Lookup key format: <account>.<field>   e.g. acme.password, acme.username, acme.totp
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

export const HOME = process.env.STANDIN_HOME || path.join(process.env.HOME || process.cwd(), '.standin');
const BACKEND = process.env.STANDIN_VAULT || 'file';
const VAULT_FILE = process.env.STANDIN_VAULT_FILE || path.join(HOME, 'vault.enc');
const KDB = process.env.STANDIN_KEEPASS_DB;

// Zero config: if the user gave no passphrase, generate a random 32-byte key once
// and keep it at ~/.standin/key (0600). Same protection as an ssh private key.
function passphrase() {
  if (process.env.STANDIN_PASSPHRASE) return process.env.STANDIN_PASSPHRASE;
  const keyFile = path.join(HOME, 'key');
  if (!fs.existsSync(keyFile)) {
    if (fs.existsSync(VAULT_FILE)) throw new Error('vault key is missing; refusing to generate a replacement for an existing vault');
    fs.mkdirSync(HOME, { recursive: true, mode: 0o700 });
    try { fs.writeFileSync(keyFile, crypto.randomBytes(32).toString('hex'), { mode: 0o600, flag: 'wx' }); }
    catch (err) { if (err.code !== 'EEXIST') throw err; }
  }
  return fs.readFileSync(keyFile, 'utf8').trim();
}

function key(salt) {
  return crypto.scryptSync(passphrase(), salt, 32);
}

export function encryptJson(obj) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key(salt), iv);
  const enc = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return Buffer.concat([salt, iv, c.getAuthTag(), enc]).toString('base64');
}

function decryptJson(b64) {
  const buf = Buffer.from(b64, 'base64');
  const salt = buf.subarray(0, 16), iv = buf.subarray(16, 28), tag = buf.subarray(28, 44);
  const d = crypto.createDecipheriv('aes-256-gcm', key(salt), iv);
  d.setAuthTag(tag);
  return JSON.parse(Buffer.concat([d.update(buf.subarray(44)), d.final()]).toString('utf8'));
}

let fileCache = null;
function fileVault() {
  if (fileCache) return fileCache;
  if (!fs.existsSync(VAULT_FILE)) throw new Error(`vault file missing: ${VAULT_FILE} (run: standin vault-set acme.password ...)`);
  fileCache = decryptJson(fs.readFileSync(VAULT_FILE, 'utf8'));
  return fileCache;
}

function writeVault(data) {
  fs.mkdirSync(path.dirname(VAULT_FILE), { recursive: true, mode: 0o700 });
  const temporary = `${VAULT_FILE}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(temporary, encryptJson(data), { mode: 0o600, flag: 'wx' });
    fs.renameSync(temporary, VAULT_FILE);
  } finally {
    try { fs.unlinkSync(temporary); } catch (err) { if (err.code !== 'ENOENT') throw err; }
  }
}

export function vaultSet(dotted, value) {
  const data = fs.existsSync(VAULT_FILE) ? fileVault() : {};
  const [acct, field] = split(dotted);
  data[acct] ||= {};
  data[acct][field] = value;
  writeVault(data);
  fileCache = data;
}

export function vaultForget(dotted) {
  const data = fileVault();
  const [acct, field] = dotted.includes('.') ? split(dotted) : [dotted, null];
  if (!data[acct]) return false;
  if (field) delete data[acct][field]; else delete data[acct];
  writeVault(data);
  fileCache = data;
  return true;
}

// --- credential document import -------------------------------------------------
// Hand it one file (notes, .env, a Chrome/1Password/Bitwarden CSV export, JSON)
// and it files everything into the vault. Values are never returned.
const FIELD_MAP = [
  [/^(user(name)?|login|email|e-?mail|account)$/i, 'username'],
  [/^(pass(word)?|pwd|pw)$/i, 'password'],
  [/^(totp|2fa|otp|mfa)([ _-]?(secret|seed|key))?$/i, 'totp'],
  [/^(api[ _-]?key|api[ _-]?token|access[ _-]?token|token|secret[ _-]?key|client[ _-]?secret)$/i, 'api_key'],
  [/^(client[ _-]?id|key[ _-]?id)$/i, 'client_id'],
  [/^(url|site|website|host|login[ _-]?uri)$/i, 'url'],
];

const slug = s => String(s).trim().toLowerCase()
  .replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '')
  .replace(/\.(com|net|org|io|co|dev|ai|app)(\.[a-z]{2})?$/, '')
  .replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'unnamed';

function normField(raw) {
  const k = String(raw).trim();
  for (const [re, name] of FIELD_MAP) if (re.test(k)) return name;
  return k.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
}

function csvRows(text) {
  const lines = text.trim().split(/\r?\n/);
  const parse = l => (l.match(/("([^"]|"")*"|[^,]*)(,|$)/g) || []).slice(0, -1)
    .map(c => c.replace(/,$/, '').replace(/^"|"$/g, '').replace(/""/g, '"'));
  const head = parse(lines[0]).map(h => h.trim());
  return lines.slice(1).filter(Boolean).map(l => Object.fromEntries(parse(l).map((v, i) => [head[i], v])));
}

function flatten(obj, prefix, out) {
  for (const [k, v] of Object.entries(obj)) {
    if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, prefix ? `${prefix}_${k}` : k, out);
    else out.push([prefix || 'unnamed', k, String(v)]);
  }
  return out;
}

export function importDocument(file, { defaultAccount } = {}) {
  const text = fs.readFileSync(file, 'utf8');
  const ext = path.extname(file).toLowerCase();
  const triples = []; // [account, field, value]

  if (ext === '.json') {
    const j = JSON.parse(text);
    if (Array.isArray(j)) for (const row of j) rowTriples(row, triples);
    else flatten(j, defaultAccount || '', triples);
  } else if (ext === '.csv' || ext === '.tsv') {
    for (const row of csvRows(text.replace(/\t/g, ','))) rowTriples(row, triples);
  } else {
    // free-form notes / .env / markdown
    let account = defaultAccount || null;
    for (const line of text.split(/\r?\n/)) {
      const l = line.trim();
      if (!l || l.startsWith('#') && !l.includes('=')) {
        const h = l.match(/^#{1,6}\s*(.+)$/) || l.match(/^\[(.+)\]$/);
        if (h) account = slug(h[1]);
        continue;
      }
      const head = l.match(/^([A-Za-z0-9 ._-]{2,40})\s*[:=]\s*$/); // "GitHub:" on its own line
      if (head) { account = slug(head[1]); continue; }
      const kv = l.match(/^(?:export\s+)?["']?([A-Za-z0-9 ._\-\/]{1,60}?)["']?\s*[:=]\s*["']?(.+?)["']?\s*$/);
      if (!kv) continue;
      let [, rawKey, value] = kv;
      if (!value || /^(xxx+|<.*>|your[- _])/i.test(value)) continue;
      let acct = account, field = rawKey;
      // With no heading in play (a .env file, say), read the account off the key prefix:
      // ACME_PASSWORD -> acme.password. Under a heading, the heading wins and the whole
      // key is the field name, so "secret key" under "## Stripe" stays stripe.api_key.
      if (!acct) {
        const parts = rawKey.trim().split(/[ _.]+/);
        if (parts.length > 1 && /^(user|username|password|pass|token|key|secret|totp|url|email|id|sid)$/i.test(parts[parts.length - 1])) {
          acct = slug(parts.slice(0, -1).join('_'));
          field = parts[parts.length - 1];
        }
      }
      triples.push([acct || 'unnamed', field, value]);
    }
  }

  const summary = {};
  for (const [acct, rawField, value] of triples) {
    const a = slug(acct), f = normField(rawField);
    if (!f || !value) continue;
    vaultSet(`${a}.${f}`, value);
    (summary[a] ||= []).push(f);
  }
  return summary;

  function rowTriples(row, out) {
    const nameKey = Object.keys(row).find(k => /^(name|title|item|service|account|site|url|login[ _-]?uri)$/i.test(k));
    const acct = slug(row[nameKey] || defaultAccount || 'unnamed');
    for (const [k, v] of Object.entries(row)) {
      if (k === nameKey || v == null || v === '') continue;
      out.push([acct, k, String(v)]);
    }
  }
}

export function vaultList() {
  const data = fileVault();
  return Object.entries(data).map(([a, f]) => `${a}: ${Object.keys(f).join(', ')}`);
}

function split(dotted) {
  const i = dotted.indexOf('.');
  if (i < 0) throw new Error(`bad secret ref "${dotted}", expected account.field`);
  return [dotted.slice(0, i), dotted.slice(i + 1)];
}

// RFC 6238 TOTP from a base32 secret
export function totp(base32Secret, step = 30, digits = 6) {
  const clean = base32Secret.replace(/=+$/, '').replace(/\s/g, '').toUpperCase();
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const ch of clean) {
    const v = alpha.indexOf(ch);
    if (v < 0) throw new Error('invalid base32 in TOTP secret');
    bits += v.toString(2).padStart(5, '0');
  }
  const bytes = Buffer.from(bits.match(/.{8}/g)?.map(b => parseInt(b, 2)) || []);
  const counter = Math.floor(Date.now() / 1000 / step);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', bytes).update(msg).digest();
  const off = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[off] & 0x7f) << 24 | hmac[off + 1] << 16 | hmac[off + 2] << 8 | hmac[off + 3]) % 10 ** digits;
  return String(code).padStart(digits, '0');
}

export function getSecret(dotted) {
  const [acct, field] = split(dotted);
  if (BACKEND === 'env') {
    const k = `VAULT_${acct}_${field}`.toUpperCase().replace(/[^A-Z0-9_]/g, '_');
    const v = process.env[k];
    if (!v) throw new Error(`env vault: ${k} not set`);
    return field === 'totp' ? totp(v) : v;
  }
  if (BACKEND === 'keepassxc') {
    if (!KDB) throw new Error('STANDIN_KEEPASS_DB not set');
    const args = field === 'totp'
      ? ['show', '-t', KDB, acct]
      : ['show', '-a', field === 'username' ? 'UserName' : field === 'password' ? 'Password' : field, KDB, acct];
    return run('keepassxc-cli', args, passphrase());
  }
  if (BACKEND === 'bitwarden') {
    if (field === 'totp') return run('bw', ['get', 'totp', acct]);
    return run('bw', ['get', field === 'username' ? 'username' : 'password', acct]);
  }
  // file backend
  const entry = fileVault()[acct];
  if (!entry) throw new Error(`vault: no account "${acct}"`);
  if (field === 'totp') {
    const seed = entry.totp || entry.totp_secret;
    if (!seed) throw new Error(`vault: no totp secret for "${acct}"`);
    return totp(seed);
  }
  if (entry[field] == null) throw new Error(`vault: no field "${field}" on "${acct}"`);
  return entry[field];
}

function run(cmd, args, stdin) {
  try {
    return execFileSync(cmd, args, { input: stdin ? stdin + '\n' : undefined, encoding: 'utf8' }).trim();
  } catch (e) {
    throw new Error(`${cmd} failed: ${(e.stderr || e.message).toString().trim()}`);
  }
}
