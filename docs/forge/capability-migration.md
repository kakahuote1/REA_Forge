# Capability migration map

This document specifies migration intent. It does not advertise implemented
Forge tools. The local inventory binds legacy declarations to observed source
hashes; old approvals do not establish a current Forge pass.

| Domain                    | Adopt from official REA                                             | Additional downstream work                                                                                                                                        |
| ------------------------- | ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Native static / IDA       | Existing native queries and Evidence contracts                      | Preserve useful local IDA analysis/extensions and explicitly typed database edits; keep upstream IDA queries read-only                                            |
| Windows debugging         | Shared process supervision and Evidence                             | Guest IDA debugging/full scripting, x64dbg and WinDbg with exact target binding and lifecycle                                                                     |
| .NET                      | Existing metadata/CIL inspection and application graphs             | dnSpy decompilation, typed IL/member/resource editing, derived compilation and readback                                                                           |
| Java                      | General artifact inventory                                          | Recaf edit/repackage, Vineflower/CFR/BCV alternatives and javap facts                                                                                             |
| Android static            | Existing JADX, apktool and signature observations where verified    | Preserve rebuild, smali and signing outcomes; JEB remains conditional on actual engine/license/interface                                                          |
| Android runtime           | Existing ADB/Frida concepts and canonical result delivery           | LDPlayer lifecycle, existing Frida 16.5.2 environment, selected-device scope and portable setup                                                                   |
| HarmonyOS                 | Existing package inventory                                          | Available ABC/Ark disassembly/decompilation and signing verification; unavailable engines stay explicit                                                           |
| PE and ordinary unpacking | Available static format and artifact primitives                     | Existing PE workbench and ordinary unpack/extraction outcomes; excluded bypass workflows are not migrated                                                         |
| Python                    | Existing packaged-app inventory and bytecode facts where equivalent | Version-specific decompilation, established older-version engines and PyLingual model/runtime routing                                                             |
| Binary editing            | Existing artifact identity and comparison semantics                 | 010 templates, byte search, comparison, derived edits, backup and recovery                                                                                        |
| Cryptography / encoding   | Existing relevant artifact facts                                    | Official local CyberChef recipes, reproducible inputs and outputs                                                                                                 |
| Traffic                   | Existing offline capture/HAR/SAZ primitives where equivalent        | Fiddler Classic selected-source live control; existing Wireshark/TShark and approved Apipost functionality; Burp/DudeSuite/Yakit conditional gaps remain explicit |
| System investigation      | Existing applicable observation contracts                           | System Informer and Hollows Hunter/PE-sieve workflows plus planned WinDbg, without silently installing drivers                                                    |
| Human workbench           | Shared CLI/MCP workflows                                            | Reconnect the existing editor/runtime controls to Forge without duplicating the control plane                                                                     |

GDA/C32Asm and superseded generic bundle registries are not separate migration
goals. The former framework's router is replaced by REA composition rather than
being embedded as another permanently running server.

## Current engineering order

1. Establish the official Windows build and a real harmless CLI/MCP baseline.
2. Inventory source/dependency/consumer identity and select minimal adapters.
3. Migrate complete static capability groups, starting with 010; retain typed
   operations and private artifact provenance rather than porting old governance.
4. Migrate guest/mobile execution and the human editor as complete groups.
5. Verify cutover and absence of old active-path dependencies before removing
   superseded framework directories and measuring recovered disk space.

Each completed capability group receives one concentrated acceptance run.
Internal edits do not trigger the entire test inventory. A failed group is
repaired and rerun at its affected boundary, with the failed receipt retained.
