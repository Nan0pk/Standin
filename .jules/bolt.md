## 2026-10-31 - [Batch AES file writing in vault imports]
**Learning:** Calling a function that performs AES encryption and disk writes within a loop (like `vaultSet` in `importDocument`) degrades performance to O(N). Encrypting and writing the entire file for every single cell in a CSV import is a severe bottleneck.
**Action:** Batch data processing in memory before performing expensive I/O and encryption operations. Turn O(N) file encryptions/writes into O(1).
