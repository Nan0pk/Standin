## 2026-02-30 - Path Traversal in Runner file downloads/screenshots
**Vulnerability:** The `runTask` execution logic in `runner.mjs` allowed arbitrary file writes outside of the sandbox via relative path traversals (e.g. `../../etc/passwd`) or absolute paths when evaluating task configuration payload arguments (`as` for download, and `arg` for screenshot).
**Learning:** `path.join(base, user_input)` combined with download functionality without verifying absolute prefix containment leads to path traversal.
**Prevention:** Use `path.resolve` to calculate the absolute canonical path, and explicitly verify it is contained in the target sandbox directory by asserting `dest.startsWith(path.resolve(runDir) + path.sep)`. Throw an error otherwise.
## 2026-11-06 - [Prototype Pollution via Dot Notation]
**Vulnerability:** The vault configuration allowed prototype pollution when splitting dotted keys (like `__proto__.shell`) in `vaultSet`, because the parsed keys were used directly in object assignment (`data[acct] ||= {}; data[acct][field] = value`).
**Learning:** Functions that parse structured string keys (like dot notation) and assign properties dynamically are a major risk vector for prototype pollution if keys aren't strictly checked against restricted prototypes (`__proto__`, `constructor`, `prototype`).
**Prevention:** Always validate and block restricted prototype properties during key parsing.
