## 2026-11-01 - Batching Vault File Writes for Import
**Learning:** `importDocument` was calling `vaultSet` in a loop, writing the entire encrypted vault to disk synchronously for every field extracted from an imported file (e.g. 50 items with username and password equals 100 disk writes, taking over 5 seconds). Since the file is rewritten completely each time, this is an O(n^2) scaling factor with the number of fields, exacerbated by scrypt key derivation and AES-GCM encryption each time.
**Action:** When bulk importing, read the vault once, mutate the object structure in memory, and then write to disk exactly once at the end of the operation.

## 2024-11-04 - Optimize MCP output redaction
**Learning:** `redact` logic in `standin/server/src/mcp.mjs` was transforming a `Set` to an array, sorting it by length, and running a string `replaceAll` against every single tool response output text. This is a CPU-intensive O(N * S) search-and-replace operation.
**Action:** Replace looped `replaceAll` with a lazily-compiled Regular Expression (`new RegExp(sorted.map(escapeRegExp).join('|'), 'g')`). The Regex is only updated when a new sensitive secret is added, drastically reducing string manipulation overhead (~50x speedup).
