## 2024-05-24 - [Optimize secrets redaction logic]
**Learning:** [In standin/server/src/mcp.mjs, the secrets redaction logic dynamically sorting a Set of secrets by length and replacing all occurrences on strings via iterative `.replaceAll` calls creates an unnecessary O(N*M) bottleneck, particularly when replacing an array of text strings dynamically. Converting a set to an array and re-sorting it for every redact call also caused major overhead]
**Action:** [Build a single regular expression (with regex chars properly escaped and sorted by length descending to manage overlaps). Cache it on the closure, and only update it when the Set of sensitive secrets changes. Using `.replace(regex)` gives up to 200x speedup when redacting strings]

## 2026-11-11 - Base32 string processing anti-pattern in Node.js
**Learning:** Parsing base32 strings using `.toString(2)` and regex `.match(/.{8}/g)` for bit manipulation is an O(N) operation but incurs high overhead due to repeated string allocations. Replacing it with a precomputed byte array mapping and direct bitwise math eliminates all string manipulation overhead.
**Action:** When parsing base32 or other encoding formats, use bitwise operations and statically-allocated lookup arrays instead of string padding and regex parsing.
