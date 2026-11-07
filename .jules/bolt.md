## 2026-11-01 - Batching Vault File Writes for Import
**Learning:** `importDocument` was calling `vaultSet` in a loop, writing the entire encrypted vault to disk synchronously for every field extracted from an imported file (e.g. 50 items with username and password equals 100 disk writes, taking over 5 seconds). Since the file is rewritten completely each time, this is an O(n^2) scaling factor with the number of fields, exacerbated by scrypt key derivation and AES-GCM encryption each time.
**Action:** When bulk importing, read the vault once, mutate the object structure in memory, and then write to disk exactly once at the end of the operation.

## 2023-10-27 - O(N) Replacement in Redaction
**Learning:** `redact` used to run a `Set` traversal (O(N) operations) executing `.replaceAll()` for every single sensitive string in a loop. With a high number of sensitive items and large output content (like a full DOM snapshot), this was extremely slow, dropping performance to a crawl.
**Action:** Replace `reduce()` with an efficiently cached RegExp compilation. `new RegExp(sortedKeys, 'g')` compiles the match rules natively, requiring only a single O(1) loop iteration (`.replace()`) per target string. We track `sensitive.size` to cache the pattern until an invalidation occurs.
