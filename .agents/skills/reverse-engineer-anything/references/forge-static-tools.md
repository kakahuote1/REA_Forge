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
