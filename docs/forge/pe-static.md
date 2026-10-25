# PE facts and ordinary UPX transforms

The host static workbench reuses the previously audited pure pefile parsers,
not the old MCP/session controller. Native `inspect_pe_resources`,
`inspect_pe_certificates` and `inspect_native_exports` remain independent
exact-format readers. Parser observations and native strict-format observations
retain their different coverage rather than being merged into a loader claim.

| Task                                                                  | Shared CLI/MCP operation        |
| --------------------------------------------------------------------- | ------------------------------- |
| Headers, sections, entropy, imports/exports, resources, TLS/CLR/flags | `forge_inspect_pe`              |
| Static dependency candidates and host APISet/KnownDLL/SxS metadata    | `forge_resolve_pe_dependencies` |
| Verify a selected file with UPX's fixed test command                  | `forge_test_upx`                |
| Test, unpack into a fresh file, retain its identity                   | `forge_unpack_upx`              |
| Page facts/graph collections or read retained artifact bytes          | `forge_read_pe_result`          |

`REA_FORGE_STATIC_CONFIG` selects independent `pe_parser`, `upx`, and
`pe_results` families. Each declares admitted `input_roots`. The parser family
selects a hash-pinned `pefile: {path, sha256}` module and exact `version`; UPX
selects an `executable` pin and version. Pins do not authenticate every
transitive installed Python dependency. Missing UPX must not disable parsing
or historical result reading. No target code or Windows DLL is loaded.

Select a `facet`, offset and limit to keep answers small. Dependency collections
include nodes, edges, missing, previously_examined_edges, source manifests and
SxS candidates. Caller-selected depth defaults to two (maximum ten), with at
most 48 nodes and 512 edges. Depth/node/edge limits and parser table limits
constrain coverage. Revisited edges are not proof of a directed cycle. Candidate
ordering is a static model, not proof of architecture-compatible runtime
resolution, activation contexts, process search paths or Windows loader choices.
APISet supports the observed v6 namespace; unsupported schema versions remain
explicit. KnownDLL directory-valued registry entries are not DLL-name mappings.

Inputs and derived outputs are bounded to 256 MiB within the existing owned
helper's 55-second/1-GiB process-family policy. Native UPX pipelines have a
caller-selected 1–45-second cumulative deadline. UPX test success is a verified
UPX input; non-success is `not_verified`, not evidence that no packer exists.
Unpacking creates a new retained output and never overwrites the input. It
does not establish benignness, program equivalence or support other protectors.

Results retain receipt/full-JSON/output identities. Re-reading requires receipt
path plus SHA-256. Artifact index zero reads exact full JSON bytes; subsequent
indices select derived files. Windows are at most 64 KiB. Large inline facets
are explicitly omitted with a retained-byte route, not silently truncated.
Readback verifies retained bytes, not current freshness of the original file.

G07 remains incomplete until its separately tracked DiE rule-evaluation and
Unipacker emulation integrations are delivered in an appropriate execution
domain. Dynamic dumping belongs to the guest/debugger chain. The host surface
above is not a claim that every historical workbench operation is migrated.

`scripts/forge/verify-pe-static.mjs` exercises this entire host subset against
already installed known-source plain/UPX-packed fixtures, including native
readers, dependency metadata, output readback, malformed requests, real native
deadline/cancellation and CLI/MCP parity. It never executes the fixtures.
