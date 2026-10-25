# Forge static tools

Use the actual advertised schema and `binary_session` availability first.
These tools take explicit inputs and do not require `open_binary`. The explicit
private configuration selects engine pins, allowed roots and data ownership.
Readiness checks only configuration and file presence; the call performs the
existing engine verification. A missing family does not disable its peers.

| Task                                                              | Tool family                                                                                                      | Workflow                                                                                                                  |
| ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Understand a binary format                                        | `forge_list_binary_assets`, `forge_inspect_binary_structure`, `forge_read_binary_template_rows`                  | Select an approved template; inspect fields/ranges and page the retained export                                           |
| Read, search or compare bytes                                     | `forge_read_binary_bytes`, `forge_search_binary_bytes`, `forge_compare_binary_files`                             | Use explicit input paths and preserve identities and truncation                                                           |
| Edit binary bytes or restore                                      | `forge_edit_binary_copy`, `forge_edit_binary_in_place`, `forge_run_binary_script`, `forge_restore_binary_backup` | Prefer a copy; deliberate in-place edits require backup/readback. Only constrained scripts on non-PE copies are supported |
| Java source and bytecode                                          | `forge_inspect_java`, `forge_decompile_java`, `forge_disassemble_java`                                           | Select exact classes; compare decompilers with javap/bytecode facts                                                       |
| Java references, changes and comparison                           | `forge_search_java`, `forge_java_call_graph`, `forge_edit_java`, `forge_compare_java`                            | Recaf edit/compile/repackage, then reread the actual class/JAR without executing it                                       |
| .NET source, IL, metadata and resources                           | `forge_inspect_dotnet`, `forge_decompile_dotnet`, `forge_read_dotnet_resource`                                   | Select exact tokens and C#/VB/IL; retain read-only facts                                                                  |
| .NET editing and compilation                                      | `forge_edit_dotnet`, `forge_compile_dotnet`                                                                      | Apply advertised modifications and reread the output; never initialize the target on the host as validation               |
| Offline operation discovery and recipe checking                   | `forge_list_cyberchef_operations`, `forge_validate_cyberchef_recipe`, `forge_suggest_cyberchef_steps`            | Discover the current subset, validate explicit parameters; suggestions are not proof of the original algorithm            |
| Decode, decompress, hash, known-parameter crypto or recipe replay | `forge_run_cyberchef_recipe`, `forge_replay_cyberchef_recipe`                                                    | Save/replay recipes; verify independent vectors and round trips                                                           |

Select exact inputs from the current catalog. Do not invent operation names or claim the supported
CyberChef subset covers every upstream operation. IDA handles locating code
and recovering custom semantics; guest debuggers handle runtime buffers when
their dynamic path is configured. Retained Evidence, input/output digests,
readback and limitations apply equally to CLI and MCP.

For static capability candidates use `forge_analyze_capabilities` (capa),
`forge_recover_strings` (FLOSS), and `forge_list_api_hash_types` /
`forge_lookup_api_hash` (FLARE). Page retained output with
`forge_read_enrichment_result`; rule/string/hash candidates need corroboration.

For saved traffic, start with native `inspect_pcap_capture` or
`inspect_web_network_capture` for HAR/SAZ. Use `forge_inspect_packet_tree`,
`forge_extract_packet_fields`, `forge_pcap_statistics`,
`forge_follow_packet_stream` and `forge_export_packet_objects` for offline
detail. The default scans 2048 source frames; explicitly set `packet_limit: 0`
for the whole file within fixed budgets. TLS keys must be explicitly selected.
No live capture, profile edits or endpoint requests happen through these tools.

For exported OpenAPI/Swagger/Postman JSON use `forge_inspect_api_asset`,
`forge_compare_api_assets` or `forge_export_api_asset`. These inspect documents,
not Apipost GUI projects or live API suites. Read saved pages/text/exact bytes
with `forge_read_traffic_result` using the returned receipt digest.

For Python, use native `inspect_python_pyc` for supported CPython header/marshal
facts and native artifact inspection/extraction for PyInstaller. Use
`forge_disassemble_python` for xdis facts and versioned disassembly;
`forge_decompile_legacy_python` selects uncompyle6/decompyle3 from actual version
facts. Its source is unverified reconstruction. `forge_read_python_result`
pages retained text. The modern `forge_decompile_modern_python` model path is
still under current Forge acceptance; do not present historical model passes
as current integration proof. Honor `resource_constraint`; do not automatically
download models, change the sample or weaken admission to retry it.

For Android, use native `inspect_android_package`, `search_android_classes`,
`inspect_android_class`, `inspect_android_method` and `trace_android_references`
for static JADX observations; `decode_android_resources` reads resources.
Use `forge_prepare_android_project` to retain a copied decoded project,
`forge_build_android_project` for exact hash-bound edits and rebuilding,
`forge_disassemble_dex` / `forge_assemble_dex` for selected DEX/Smali transforms,
and `forge_sign_apk` / `forge_verify_apk` for signing and cryptographic checks.
Page project files or exact artifact bytes with `forge_read_android_result`.
Keep the receipt path plus SHA-256 between calls. Test keys are not production
identities; passwords are operator-configured files, never tool arguments.
Native `inspect_apk_signature` reports declarations separately from cryptographic
verification. These static tools do not install or execute APKs; use an explicit
guest/device workflow for runtime validation. See `docs/forge/android-build.md`.

For PE facts use `forge_inspect_pe` and select a facet/page; native
`inspect_pe_resources`, `inspect_pe_certificates` and `inspect_native_exports`
retain their exact-format contracts. `forge_resolve_pe_dependencies` returns
static candidates, not Windows loader truth; control depth/node budgets and
keep source coverage. `forge_test_upx` verifies the selected packed input;
`forge_unpack_upx` creates a fresh output, which should be inspected afterward.
Use `forge_read_pe_result` for retained graph/fact pages and exact artifact
bytes. No target or dependency is loaded. DiE, Unipacker emulation and dynamic
dumping remain under execution-domain integration, not available through this
host subset. See `docs/forge/pe-static.md` for these explicit boundaries.

For HAP/HSP/App Pack, reuse `inspect_artifact`, `extract_artifact` and
`project_harmony_application_graph` for the authenticated application graph.
Use `forge_inspect_hap` for full bounded extraction/metadata, then
`forge_inspect_abc` for header/classes/methods or legacy resource indexes.
`forge_disassemble_ark` gives independent official assembly;
`forge_render_abc_method` selects exact offsets and encoded references or
experimental JS. `forge_decompile_hap` is a separate JADX-HAP reconstruction
that requires real ABC and source outputs. Never call resource-only results
successful decompilation. `forge_sign_hap` makes a new copy and
`forge_verify_hap_signature` performs actual offline verification; default
test identity is not deployable or trusted. Preserve receipt path/digest and
use `forge_read_harmony_result` for facets, JSONL/text pages or raw artifact
bytes. All of these are static; code reconstruction and signatures do not
prove runtime behavior or benignness. See `docs/forge/harmony-static.md`.
## Explicit live-process observations

For process identity and system tables, use `forge_inspect_system`; select an
exact PID first and preserve its `created_100ns` decimal string. Use
`forge_observe_process` with that same identity for modules/threads/handles/
regions/details/connections, or `forge_scan_process` for fixed no-dump Hollows
Hunter/PE-sieve candidates. Do not pass an unqualified PID from an old receipt.
Use `forge_read_system_result` for historical paging/export and
`forge_compare_process_snapshots` for complete same-target snapshot changes.
Queries are not atomic; driver-service status is not loaded-driver truth,
connection tables are not capture, and scan negatives do not prove benignness.
No target launch, driver, process control or memory dump occurs on this path.
Dynamic changes remain on the selected guest/debugger chain.
## IDA work-IDB edits and analysis extensions

Use the native `ida` provider for ordinary static questions. For a deliberate
new work-IDB artifact use `forge_edit_ida_database`, or
`forge_run_ida_safe_python` for bounded JSON/db batches. Preserve the returned
database and before-snapshot identities. `forge_restore_ida_database` derives
a restored copy only after authenticating the current expected digest.
Use `forge_scan_ida_crypto` for FindCrypt3/YARA candidates;
`forge_ida_enum`/`forge_ida_struct_typer` preview unless explicit selections are
provided. Use `forge_snapshot_ida_database` and
`forge_compare_ida_snapshots` for the bounded exchange matcher,
`forge_export_ida_data` for literals, `forge_assemble_ida` for encoding, and
`forge_read_ida_result` for retained readback. These are not original plugin or
raw IDAPython entry points. Raw code, target launch and debugging use the
selected guest chain, never an attempted host-facade bypass.
