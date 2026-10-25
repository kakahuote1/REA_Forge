# capa, FLOSS and API-hash evidence

Use `forge_analyze_capabilities` for static capability-rule candidates and
addresses, `forge_recover_strings` for static/decoded/stack/tight strings, and
`forge_list_api_hash_types` / `forge_lookup_api_hash` for exact read-only FLARE
database queries. The CLI uses the same names with underscores changed to
hyphens and one JSON argument. No binary session is required.

Each operation retains complete engine JSON within its output bound and
returns a bounded inline page. Use `forge_read_enrichment_result` with the
returned receipt path and digest for later pages without re-running analysis.
Both receipt and full-result digests are checked. This is historical readback,
not fresh execution, original-file freshness or cryptographic authentication.

## Explicit local configuration

Continue using `REA_FORGE_STATIC_CONFIG` and `REA_FORGE_DATA_ROOT`. Add members
`capa`, `floss`, `api_hashes` and `enrichment` to that existing private file.
Every member has `input_roots` containing admitted absolute local directories.

- `capa` and `floss`: `version` plus `executable: { path, sha256 }`.
- `api_hashes`: `version` plus `database: { path, sha256 }`.
- `enrichment`: only the roots; retained readback does not require an engine.

Availability checks configuration and file presence without starting engines.
A missing FLOSS installation does not disable capa, hash queries or retained
readback. Calls verify the selected executable/database digest. Assets stay
operator-supplied; Forge does not download or update them.

## Interpretation and limits

capa uses the fixed Vivisect backend and bundled rules, not an IDA backend or
caller-selected rules. FLOSS uses fixed JSON options and the chosen string
categories. Input files are copied and hash-bound; their operating-system
entry points are never run. FLOSS/Vivisect static emulation is performed by
trusted analysis engines, not by launching a target process.

Hash lookup accepts only a 32-bit value and an optional exact hash-type ID.
Results include candidate collisions, library and symbol names. It accepts no
SQL, custom database or upstream IDAPython plugin code.

Inputs are at most 32 MiB; complete engine JSON is at most 8 MiB. Inline pages
contain at most 100 rows. Text previews and per-rule address previews state
their truncation; full results remain retained. Engine calls have a selected
1–45,000 ms run deadline inside the existing 55-second owned helper envelope.
The existing REA process owner settles the helper family and retains cleanup
failure authority. Native engine calls and all internal children are hidden.

Rule matches do not prove malware intent. Strings may be emulator artifacts.
API-hash matches do not prove a unique algorithm or function. Corroborate each
candidate with static disassembly and, when needed, authorized guest debugging.
