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
