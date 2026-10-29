# standin

Standin is an experimental MCP server and Claude plugin for browser tasks, credential storage, and repeatable workflows. It needs further security review before use with real accounts.

```
"log into DigitalOcean, create an API token, and set it in Vercel as DO_TOKEN"
"here are my credentials — credentials.md — set everything up"
"I'm already logged into the tax portal in Chrome, grab last month's invoices"
"configure the APIs for Stripe, Twilio and Postmark and plug them into my app"
```

## Configuration

None. First use installs its own browser driver and creates an encrypted vault at `~/.standin`.
No API keys, no passphrase, no config file. It borrows Chrome if you already have it.

## How it gets your credentials

Three ways, in the order it will try them:

1. **From the browser you already use.** If you're logged into a site in Chrome, Edge or Brave,
   it attempts to copy that session. Browser encryption, profile layout, and site policies can prevent the copy from working.
2. **From one document.** Hand it a file — notes, markdown, `.env`, JSON, or a password-manager
   CSV export (Chrome, 1Password, Bitwarden, LastPass). It files everything into the vault by
   itself and can delete the file afterwards. Deletion is not secure erasure.
3. **By asking**, once, for the single thing it's missing — naming exactly what it needs.

For 2FA, give it the base32 seed behind the QR code once; it generates the codes itself after that.

## Where secrets live

`~/.standin/vault.enc` uses AES-256-GCM. By default a random key is stored alongside it at
`~/.standin/key` with mode 600; anyone who can read both files can decrypt the vault. Set
`STANDIN_PASSPHRASE` for a user-provided passphrase instead. Back up the vault and its key.

Secret-fill and capture tools avoid returning the actual value directly, and text outputs redact
exact values used during the current server session. This does not guarantee secrecy: a page
may display a new secret before it is captured; screenshots, task results, server responses,
encoded values, logs, and tool arguments can expose sensitive data. Websites receive submitted
data, and the AI provider may receive tool outputs. Review these limits before using real credentials.

## What it will stop and ask about

The included skill instructs the agent to ask about CAPTCHAs, hardware security keys, SMS codes,
payments, plan upgrades, and deletions. These are instructions to the agent, not enforced controls.

## Repeating a job

Ask it to remember a job and it saves the steps, so the same thing can run again unattended —
once per row of a spreadsheet if you want, or on a schedule.

## Tools it adds

`browser_open`, `browser_snapshot`, `browser_click`, `browser_type`, `browser_fill_secret`,
`browser_fill_totp`, `browser_capture_secret`, `browser_read`, `browser_wait`,
`browser_screenshot`, `browser_import_login`, `vault_import_document`, `vault_set`, `vault_list`,
`vault_forget`, `http_request`, `save_task`, `run_task`.

## Checking it yourself

```bash
cd server && npm install && npm test
```
