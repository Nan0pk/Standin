## 2026-11-01 - Batching Vault File Writes for Import
**Learning:** `importDocument` was calling `vaultSet` in a loop, writing the entire encrypted vault to disk synchronously for every field extracted from an imported file (e.g. 50 items with username and password equals 100 disk writes, taking over 5 seconds). Since the file is rewritten completely each time, this is an O(n^2) scaling factor with the number of fields, exacerbated by scrypt key derivation and AES-GCM encryption each time.
**Action:** When bulk importing, read the vault once, mutate the object structure in memory, and then write to disk exactly once at the end of the operation.

## 2024-06-18 - Optimized String Redaction
**Learning:** In `mcp.mjs`, redaction of secrets from MCP tool output involved re-sorting the secrets array and looping over every secret with `replaceAll` for every string chunk, which created an $O(N \times S)$ bottleneck.
**Action:** Caching a compiled RegExp `(secret1|secret2|...)` with invalidation only upon new secret addition sped up string redaction by 300x in benchmarks.
