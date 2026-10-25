# Offline CyberChef integration

Select the operator configuration and data directory through
[static-provider configuration](static-configuration.md); production does not
infer either from the checkout location.

Five typed tools expose the existing reviewed offline subset of the installed
official CyberChef source. This is twenty named operations, not the whole
CyberChef catalog: Base64/hex/URL/text encoding, gzip/zlib, SHA2/HMAC/CRC, XOR,
known-parameter AES and JSON formatting. Module selection is fixed in source.

## Agreed capability-family coverage

The delivery scope is these explicit offline families, not every upstream
CyberChef operation. The current catalog covers each requested family:

| Requested outcome | Implemented operations | Current real verification |
| --- | --- | --- |
| Encoding/decoding | Base64, Hex, URL, text encoding pairs | Six byte-preserving encoding/compression roundtrips include Unicode |
| Compression/decompression | Gzip/Gunzip, Zlib Deflate/Inflate | Paired output is reread and equals the original bytes |
| Hash and keyed checksum facts | SHA2, HMAC, CRC Checksum | Independent Node hash/HMAC and known CRC-32 vector |
| Known-parameter encryption/decryption | AES Encrypt/Decrypt, XOR | Independent AES cipher bytes, plaintext readback and independent XOR bytes |
| Format conversion/normalization | Hex/text representation, JSON Beautify/Minify | Byte identity and parsed JSON equality |
| Reproducible recipes | Validate, execute, digest-bound save/replay | CLI/MCP agreement, altered-receipt refusal, exact operation catalog and recovery |

All twenty advertised operations were exercised in the current grouped receipt.
No additional algorithm or format is implied by a family label. In particular,
this does not advertise RSA, every compression codec, arbitrary operation imports
or network recipes. Discovery returns the exact supported names and parameters;
an unsupported request must remain unsupported rather than be guessed.

| MCP tool                          | Purpose                                              |
| --------------------------------- | ---------------------------------------------------- |
| `forge_list_cyberchef_operations` | Exact operation names and argument defaults/types    |
| `forge_validate_cyberchef_recipe` | Canonical recipe and digest                          |
| `forge_run_cyberchef_recipe`      | New derived output, bounded preview and saved recipe |
| `forge_replay_cyberchef_recipe`   | Digest-checked saved recipe on a chosen input        |
| `forge_suggest_cyberchef_steps`   | Non-executing candidate labels, not algorithm proof  |

Recipes use CyberChef's exported `{op,args}` format. Omitted arguments use
installed defaults; AES, HMAC and XOR require explicit nonempty known keys.
The catalog reports argument order and options, so callers need not guess.
For byte-exact AES, select Hex input/output and use To Hex/From Hex around the
cipher steps. CyberChef's Raw string mode follows its own text conversion
semantics; do not assume it is an arbitrary UTF-8 byte-preserving interface.
No downloaded URL, listener, external command or arbitrary module is exposed.

Add `cyberchef` to ignored `.forge-local/config/tools.json` with an absolute
`root`, pinned `node: {path,sha256}`, `package_lock_sha256` and `input_roots`.
Use an already installed official CyberChef source and its own dependencies.
Then explicitly record its twenty-two fixed entry hashes:

```text
python -I -S scripts/forge/pin-cyberchef-entrypoints.py
```

This records the selected installation; it does not update, download or certify
the engine. Entry sources and lockfile are checked, but not every installed
transitive dependency. Neither this worker nor static script filtering is an
operating-system sandbox.

Inputs remain unchanged. Private outputs, logs and saved recipes live under
`.forge-local/work/cyberchef`. Output previews stop at 4096 bytes; the full output
remains available by path/digest. Recipe receipts can contain supplied keys;
they are private analysis data and must never be committed or uploaded.

CLI names replace underscores with hyphens and take the same JSON arguments.
`node scripts/forge/verify-cyberchef.mjs` runs the complete affected group with
encoding/compression roundtrips, independent hash/HMAC/CRC/AES vectors, every
exposed operation, saved-recipe replay, rejection and CLI/MCP parity. Individual
passes do not establish every AES mode or every operation parameter combination.
