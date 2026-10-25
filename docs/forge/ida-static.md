# IDA static work copies

Ordinary function, pseudocode, instruction and reference questions use REA's
existing `ida` provider and its documented `REA_IDA_MCP_CONFIG`. Its upstream
read-only semantics are unchanged. Forge's optional registration selects the
existing IDA MCP dependency with a task-owned plugin profile and reader-only
tool list; it does not adopt or save a human GUI database.

The additional typed operations use the installed IDALib and existing reviewed
analysis libraries directly, under the shared owned static helper. They do not
start a second MCP platform or expose the upstream raw Python/debugger API.

| Task                                                                    | Operation                                                    |
| ----------------------------------------------------------------------- | ------------------------------------------------------------ |
| Rename/comment/type/prototype, definitions and preimage-checked patches | `forge_edit_ida_database`                                    |
| Batch JSON/db automation in the bounded static facade                   | `forge_run_ida_safe_python`                                  |
| FindCrypt3/YARA candidates and bounded review                           | `forge_scan_ida_crypto`                                      |
| AutoEnum preview and explicitly selected type creation                  | `forge_ida_enum`                                             |
| FLARE-style structure function-pointer preview/selected apply           | `forge_ida_struct_typer`                                     |
| Bounded function exchange and offline comparison                        | `forge_snapshot_ida_database`, `forge_compare_ida_snapshots` |
| Mapped-range data literals; separate Keystone encoding                  | `forge_export_ida_data`, `forge_assemble_ida`                |
| Derive an exact restored work copy from a before snapshot               | `forge_restore_ida_database`                                 |
| Digest-bound metadata and artifact bytes                                | `forge_read_ida_result`                                      |

Inputs stay unchanged. Editable operations retain `before.i64` and
`database.i64`; reopening either is explicit. Restore verifies current/backup
digests and derives a new file rather than overwriting a database. Read-only
queries do not retain duplicate input binaries or before/after IDBs. Whole-copy
reversal replaces process-local plugin revert tokens; it does not claim that
unrelated later edits can be selectively undone.

## Authority and lifecycle

The host facade accepts at most12,000characters/600AST nodes,64query rows,
256loop steps and32writes. It exposes JSON builtins and
`db.functions/lookup/rename/comment/set_type/save/status`, not IDAPython modules,
imports, reflection, filesystem, network, process control, plugins or debugging.
The migrated producer rejects rebinding its loop counter/db/builtins and admits
only the same bounded arithmetic for augmented assignments. Rejected code never
falls back to raw Python. Runtime target operations belong to the selected guest.

Each typed call has a1–45second native deadline inside the existing55second/
1GiB owned helper. IDALib work stays on the thread that initialized it. Parent
helpers retain bounded logs; failure or timeout is not a completed database.
Pins cover the chosen library source tree and approved files, not every OS or
transitive dependency. No license/EULA state is copied, patched or accepted.

The task-owned `IDAUSR/plugins` supplies unique skip stubs and a private
`plugins.cfg` headless exclusion list. Nested `ida-plugin.json` entries have
matching task-owned descriptors; flat basename overrides alone are insufficient
for those packages on the tested IDA9.1 installation. This combines the
documented [first duplicate-name precedence](https://docs.hex-rays.com/8.4/user-guide/user-interface/menu-bar/windows/environment-variables)
and installed GUI-only plugin flag without changing the original installation.
Only explicitly pinned IDAPython, offline decompilers and required official
DWARF/EH/core support DLLs are admitted. The core `dbg.dll` dependency is not a
grant to load a debug backend or run a target. Current native/
Python module paths are observed separately; that is not a trace of all past
execution. Application filtering is not an OS/network sandbox. In particular,
[batch mode](https://docs.hex-rays.com/9.1/user-guide/configuration/command-line-switches)
alone is not claimed to disable every plugin. Native reader startup profiles
are small explicit retained artifacts, not copies of an engine installation.
The library uses its autonomous API directly: an extra `-A` argument caused
internal error30602 on the tested9.1 build and is not supplied.

The static profile neither loads the original community plugins nor advertises
every plugin's GUI/heuristics. Crypto, inferred types and difference matches
remain candidates. Snapshot per-function byte/instruction limits are explicit;
no semantic-equivalence, dynamic-call-graph or runtime-safety proof is implied.

## Configuration and verification

The explicit Forge configuration has `ida_host`, `ida_assembly`, `ida_exchange`
and `ida_results`. It selects the local installation/Python, reviewed typed
library source tree and exact plugin pins. Readiness does not initialize IDA.
Commercial engines and configuration stay outside the public repository.
Actual acceptance is recorded separately; implementation/catalog presence is
not proof of a working license, completed group or current Codex connection.
The native reader negotiates single-reply versus paged decompilation from the
connected tool's advertised properties. It does not send unknown pagination
arguments, discard continuation markers, or retry a rejected request blindly.
