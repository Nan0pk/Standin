// API calls without you ever creating/copying a key.
// Nango holds the OAuth app + tokens and refreshes them; we call its proxy.
// Self-host or cloud: https://docs.nango.dev  (open source, AES-256-GCM at rest)
const BASE = process.env.NANGO_HOST || 'https://api.nango.dev';

export async function nango({ provider, connection, method = 'GET', path: p, body, headers = {} }) {
  const key = process.env.NANGO_SECRET_KEY;
  if (!key) throw new Error('NANGO_SECRET_KEY not set (see README step 3)');
  const res = await fetch(`${BASE}/proxy/${p.replace(/^\//, '')}`, {
    method,
    headers: {
      Authorization: `Bearer ${key}`,
      'Provider-Config-Key': provider,
      'Connection-Id': connection,
      'Content-Type': 'application/json',
      ...headers,
    },
    body: body ? (typeof body === 'string' ? body : JSON.stringify(body)) : undefined,
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${res.status} ${text.slice(0, 400)}`);
  try { return JSON.parse(text); } catch { return text; }
}
