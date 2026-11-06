## 2026-11-01 - Batching Vault File Writes for Import
**Learning:** `importDocument` was calling `vaultSet` in a loop, writing the entire encrypted vault to disk synchronously for every field extracted from an imported file (e.g. 50 items with username and password equals 100 disk writes, taking over 5 seconds). Since the file is rewritten completely each time, this is an O(n^2) scaling factor with the number of fields, exacerbated by scrypt key derivation and AES-GCM encryption each time.
**Action:** When bulk importing, read the vault once, mutate the object structure in memory, and then write to disk exactly once at the end of the operation.

## 2024-11-06 - Replace sequential replaceAll with dynamic Regex
**Learning:** Using `String.prototype.replaceAll` in a `.reduce()` loop over a dynamic set of values is a performance anti-pattern (O(N*M)) compared to dynamically building a single regex for masking operations. This becomes noticeable when redacting many secrets from a large string.
**Action:** When performing many string replacements against the same target string, dynamically build a single `RegExp` using alternation (`|`) to allow the regex engine to process the string in a single pass.
