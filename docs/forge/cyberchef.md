# Offline CyberChef integration

Select the operator configuration and data directory through
[static-provider configuration](static-configuration.md); production does not
infer either from the checkout location.

Five typed tools expose the existing reviewed offline subset of the installed
official CyberChef source. This is twenty named operations, not the whole
CyberChef catalog: Base64/hex/URL/text encoding, gzip/zlib, SHA2/HMAC/CRC, XOR,
known-parameter AES and JSON formatting. Module selection is fixed in source.

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
