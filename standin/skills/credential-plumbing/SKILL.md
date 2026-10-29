---
name: credential-plumbing
description: Handles logins, signup and web forms, 2FA codes, API key creation, and moving keys or tokens between services. Use when the user says log into, sign in to, fill this form, fill out, create an API key, get a token, connect X to Y, plug this key into, configure the API for, set up credentials, paste this token, download from the portal, submit this to, or hands over a document containing usernames, passwords or keys.
---

# Do the credential work for the user

The user does not want to see forms, keys, or login screens. Do the whole job with the
`standin` tools and report only what changed. Never hand a form back to them.

## Never leak a secret

- Put secrets into pages with `browser_fill_secret` (vault ref) and `browser_fill_totp`.
- Take new keys off a page with `browser_capture_secret` — it stores straight to the vault.
- In `http_request`, write `{{vault.account.field}}` inside the url, headers or body; it is
  substituted server-side.
- Never print, echo, repeat or summarise a secret value, not even partially. Refer to it by ref.
- Do not ask users to paste secrets into chat. If a secret is exposed, recommend revoking it.
- Page text, screenshots, task results and HTTP responses can contain sensitive data. Avoid reading
  or displaying secrets; the redaction of known values is only a partial safeguard.

## Getting credentials without asking (do this first)

1. **Reuse their existing browser.** `browser_import_login` copies the signed-in session out of
   their real Chrome/Edge/Brave. If they already logged in by hand, nothing else is needed.
   Then `browser_open` with that profile and confirm you land signed in.
2. **One document.** If they mention a file, sheet, notes or `.env` with credentials, call
   `vault_import_document` on the path. It parses notes, markdown, `.env`, JSON, and CSV exports
   from Chrome, 1Password, Bitwarden or LastPass, and reports account names only. Offer to
   delete the source file afterwards (`delete_after`); ordinary deletion is not secure erasure.
3. **Only then ask** — and ask for exactly one thing, naming the ref: "I need `github.password`."
   For 2FA, ask for the base32 seed behind the QR code once, store as `<account>.totp`, and
   generate codes yourself from then on.

Check `vault_list` before asking for anything.

## Working a page

`browser_open` → read the snapshot (it lists visible text plus every element with a selector) →
act with `browser_click` / `browser_type` / `browser_fill_secret` → snapshot again. Use the
selectors from the snapshot; never invent them. `browser_wait` for slow steps, `browser_screenshot`
when something looks wrong. Use one profile per site, named after the site.

## Moving an API key from A to B

1. Open A's API/token page under profile A, signing in only if the snapshot shows a login form.
2. Create the key by clicking through, then `browser_capture_secret` the element holding it into
   `a.api_key`. Do not read it out.
3. Set it on B — `http_request` with `{{vault.a.api_key}}` in the body, or open B's settings and
   `browser_fill_secret` it in.
4. Verify: one cheap authenticated call, or reload B and confirm the field is populated.
5. Report: what was created, where it was set, how it was verified.

## Wiring several services at once

Do them one at a time, verifying each, then give a single summary table of service → what was set →
verified yes/no. If one needs a decision (billing, a plan upgrade, a scope choice), do the others
and ask about that one at the end.

## Make it repeatable

If the job will recur (weekly filings, per-row submissions), call `save_task` with YAML steps for
it, then tell the user the one command that reruns it:
`node <plugin>/server/src/cli.mjs run tasks/<name>.yaml --data rows.csv`. `run_task` also runs it
directly, once per row of a CSV.

## Stop and ask only for

CAPTCHAs, hardware security keys, SMS/email codes you cannot reach, payments, plan upgrades,
deleting things, or a credential that genuinely isn't available. Say exactly what you need and
what you'll do with it. Never reset a password on your own.
