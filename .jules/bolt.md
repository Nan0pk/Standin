## 2024-05-24 - [Optimize secrets redaction logic]
**Learning:** [In standin/server/src/mcp.mjs, the secrets redaction logic dynamically sorting a Set of secrets by length and replacing all occurrences on strings via iterative `.replaceAll` calls creates an unnecessary O(N*M) bottleneck, particularly when replacing an array of text strings dynamically. Converting a set to an array and re-sorting it for every redact call also caused major overhead]
**Action:** [Build a single regular expression (with regex chars properly escaped and sorted by length descending to manage overlaps). Cache it on the closure, and only update it when the Set of sensitive secrets changes. Using `.replace(regex)` gives up to 200x speedup when redacting strings]

## 2024-05-24 - [Optimize Base32 string decoding]
**Learning:** [In cryptography or encoding algorithms (e.g. TOTP in standin/server/src/vault.mjs), converting characters to a long binary string using `Number.toString(2)` and parsing bytes out of it via regex like `.match(/.{8}/g)` creates an extreme bottleneck due to string allocations and regex overhead. Bitwise operations onto a `Uint8Array` are significantly faster.]
**Action:** [Use bitwise shifting (`<<` and `>>`) and typed arrays to decode base32/base64 strings. It operates much closer to the metal and provides a ~2x performance speedup in this case without reducing readability.]
