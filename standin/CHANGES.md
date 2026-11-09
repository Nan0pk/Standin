# Changes

Brief log of what was added and subtracted as better projects are absorbed.

## 0.4.0 (continued)

### Added
- Pluggable browser backend. `STANDIN_CDP_ENDPOINT` points Playwright MCP at any
  CDP-speaking browser — Lightpanda, Steel, Browserbase, a patchright-patched
  Chromium — with no code change, because the credential tools only ever need a
  page. `STANDIN_CDP_HEADERS` carries auth for a remote grid.
- Recovered the elicitation commit, which the squash-merge of PR #10 had dropped.

### Assessed, not adopted
- Lightpanda 1.0.2 — see the assessment in the commit message. Kept as an
  optional backend rather than the default.

## 0.4.0

### Added
- `src/browserbridge.mjs` — embeds `@playwright/mcp` in process via
  `createConnection(config, contextGetter)`, so the credential tools and the
  browser tools drive one shared browser. A sibling server would get its own
  window and secrets would be typed into the wrong one.
- 24 browser tools inherited from Playwright MCP: navigation, tabs, forms, file
  upload, drag, hover, key press, dialogs, console, network inspection,
  screenshots, resize, element finding, waiting, and `browser_verify_*`
  assertions.
- Unified element addressing. Credential tools now take the same `target` as
  the bridged tools — a snapshot reference like `e12`, or a unique CSS
  selector. A bare reference is resolved through Playwright's `aria-ref`
  engine.
- `standin_session` — switch the active per-site session (replaces the
  `profile` argument that `browser_open` used to carry).
- `standin_ask_user` — blocks and asks the human through MCP elicitation. For
  CAPTCHAs, SMS/email codes, payments, upgrades and deletions.
- `vault_add` — the human types a secret straight into the vault through
  elicitation. The value never passes through the model.
- Secret redaction now covers bridged tool output, not just standin's own.
- A failed browser action now surfaces as an error. Previously it came back as
  result text, so the agent read `### Error: could not start a browser` as page
  content and continued against a page that never loaded.
- `MIT LICENSE` (the repository had none, so it could not lawfully be used)
  and an Apache-2.0 `NOTICE` for the embedded Microsoft component.
- Tests: bridged-tool withholding, bridged-output redaction, error surfacing,
  and four elicitation tests.

### Subtracted
- 7 hand-rolled tools replaced by Playwright MCP equivalents: `browser_open`,
  `browser_snapshot`, `browser_click`, `browser_type`, `browser_read`*,
  `browser_wait`, `browser_screenshot`. (*`browser_read` was kept — see note.)
- `snapshot()` and its `INTERACTIVE` selector list. This deletes the broken
  document-wide `:nth-of-type` fallback rather than fixing it; it produced
  selectors that matched the wrong element or three elements at once.
- `target()` helper; Playwright MCP does element resolution.
- 8 tools deliberately never advertised, because they would let the model read
  a secret back: `browser_run_code_unsafe`, `browser_storage_state`, and the
  cookie / localStorage / sessionStorage getters.
- Test coupling: `mcp.test.mjs` no longer depends on state left by the previous
  test.

### Kept, against the plan
- `browser_read` was scheduled for removal as redundant with `browser_find`.
  It stays: it is two lines, and it is the read-side counterpart of
  `browser_capture_secret`, so the "read the confirmation, capture the key"
  flow stays inside one tool family.

### Still open
- `http_request` has no egress allowlist. A stored secret can still be
  substituted into a request to any address, including a cloud metadata
  endpoint.
- `browser_evaluate` is bridged through and its return value reaches the model.
  Needs a policy gate.
- No audit log, no per-secret policy, no vault leases.
- KeePass and Bitwarden backends still write to the file vault while reading
  from the external CLI.
