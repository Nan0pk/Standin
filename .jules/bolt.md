## 2024-03-24 - Batch Synchronous Disk Operations
**Learning:** During bulk operations (like importing a large CSV of credentials), reusing standard single-item update functions (`vaultSet`) which perform synchronous file system and heavy cryptographic operations leads to an O(N²) performance bottleneck.
**Action:** When performing bulk updates, ensure operations that write to disk or perform expensive computations (like AES encryption) are lifted out of the loop and executed once at the end of the batch process.
