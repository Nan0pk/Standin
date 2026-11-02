## 2026-11-01 - Batching Vault File Writes for Import
**Learning:** `importDocument` was calling `vaultSet` in a loop, writing the entire encrypted vault to disk synchronously for every field extracted from an imported file (e.g. 50 items with username and password equals 100 disk writes, taking over 5 seconds). Since the file is rewritten completely each time, this is an O(n^2) scaling factor with the number of fields, exacerbated by scrypt key derivation and AES-GCM encryption each time.
**Action:** When bulk importing, read the vault once, mutate the object structure in memory, and then write to disk exactly once at the end of the operation.

## 2024-05-18 - Optimize selector generation O(n²) in mcp.mjs snapshot
**Learning:** In `mcp.mjs`'s `snapshot` function, evaluating the fallback selector for DOM elements ran `document.querySelectorAll(el.tagName)` for each element repeatedly in an `Array.prototype.map()` loop up to 120 times, which is an O(N²) operation causing slowdowns in DOM inspection for pages with many interactable elements.
**Action:** Caching the output of `document.querySelectorAll(tagName)` in a Map or plain object per tagName reduces this bottleneck to O(N).
