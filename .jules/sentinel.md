## 2026-02-30 - Path Traversal in Runner file downloads/screenshots
**Vulnerability:** The `runTask` execution logic in `runner.mjs` allowed arbitrary file writes outside of the sandbox via relative path traversals (e.g. `../../etc/passwd`) or absolute paths when evaluating task configuration payload arguments (`as` for download, and `arg` for screenshot).
**Learning:** `path.join(base, user_input)` combined with download functionality without verifying absolute prefix containment leads to path traversal.
**Prevention:** Use `path.resolve` to calculate the absolute canonical path, and explicitly verify it is contained in the target sandbox directory by asserting `dest.startsWith(path.resolve(runDir) + path.sep)`. Throw an error otherwise.
## 2024-11-09 - Fix prototype pollution in vault

**Vulnerability:** A prototype pollution vulnerability existed in `standin/server/src/vault.mjs` through the `split` function parsing vault paths. Specifically, writing to an object using a split string without filtering special keys allowed values to overwrite properties in the global `Object.prototype`, which could alter default logic execution and behavior elsewhere in the server.

**Learning:** Destructuring strings into Object paths and directly assigning properties `data[acct] ||= {}; data[acct][field] = value;` is unsafe if `acct` or `field` can be parsed as `__proto__`, `constructor`, or `prototype` (especially from user-provided or externally sourced string references like `{{vault.__proto__.something}}`).

**Prevention:** Always validate or sanitize split string keys prior to using them as dynamic property indices on unsealed JavaScript Objects. Reject explicit usage of `__proto__`, `constructor`, or `prototype` if the destination path modifies properties.
## 2023-10-25 - Prevent SSRF in `http_request` MCP Tool
**Vulnerability:** The `http_request` MCP tool directly passed user-supplied URLs to `fetch()` without protocol validation, allowing Server-Side Request Forgery (SSRF) and Local File Inclusion (LFI) via `file://` or `data://` protocols.
**Learning:** Tools relying on `fetch` or HTTP clients with user-supplied URLs must restrict protocols, as underlying mechanisms might resolve non-HTTP schemes exposing local files or memory.
**Prevention:** Always parse untrusted URLs using `new URL()` and explicitly allow-list valid protocols (`http:` and `https:`) before making external requests.
