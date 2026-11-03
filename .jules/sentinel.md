## 2026-02-30 - Path Traversal in Runner file downloads/screenshots
**Vulnerability:** The `runTask` execution logic in `runner.mjs` allowed arbitrary file writes outside of the sandbox via relative path traversals (e.g. `../../etc/passwd`) or absolute paths when evaluating task configuration payload arguments (`as` for download, and `arg` for screenshot).
**Learning:** `path.join(base, user_input)` combined with download functionality without verifying absolute prefix containment leads to path traversal.
**Prevention:** Use `path.resolve` to calculate the absolute canonical path, and explicitly verify it is contained in the target sandbox directory by asserting `dest.startsWith(path.resolve(runDir) + path.sep)`. Throw an error otherwise.
## 2024-03-24 - MCP Parameter Path Traversal
**Vulnerability:** Path traversal in `run_task` tool of MCP server, allowing arbitrary file reading/execution as a task via the `name` parameter (e.g. `../../etc/passwd`).
**Learning:** MCP server tool parameters provided by AI agents must be treated as untrusted input. The `name` argument was concatenated directly into a `path.join` call without sanitization.
**Prevention:** Sanitize filename arguments in tool inputs by stripping out path separator characters and non-alphanumeric characters (e.g. `replace(/[^\w.-]/g, '_')`) before using them in `path.join`.
