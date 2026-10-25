# Read-only system observations

Use `forge_inspect_system` with an explicit PID to obtain its exact decimal
`created_100ns`. Pass both to `forge_observe_process` or `forge_scan_process`.
An open query-only process handle spans each operation. An exited, unreadable
or changed identity is a failure, not an empty successful observation.

| Question | Native operation |
| --- | --- |
| Process identities or service/driver-service/kernel-module tables | `forge_inspect_system` |
| Selected process, threads/extended metadata, modules, handles, regions, optional command line, connections | `forge_observe_process` |
| One-shot Hollows Hunter / embedded PE-sieve candidate scan | `forge_scan_process` |
| Compare complete retained collections with the same process identity | `forge_compare_process_snapshots` |
| Page/export digest-bound historical snapshots | `forge_read_system_result` |

System Informer uses the already built phlib user-mode helper. No desktop GUI,
driver, service startup or privilege adjustment is acquired. Driver services
are SCM state, distinct from kernel modules. Regions describe metadata, not
memory contents; handles omit object names. Extended threads expose OS-reported
entry/TEB/stack boundaries where visible, not stack frames or thread suspension.
Connection tables use the explicitly labelled Windows IP Helper supplement,
not traffic capture, DNS resolution or network requests.

The scanner invocation is fixed to one PID, JSON output and no-dump filter2.
It accepts no custom flags, loop, all-process selection or output directory.
Suspicious rows are candidates; a negative scan does not prove benignness or
absence of a rootkit. These are non-atomic before/after observations. Creation
stamps/100ns values are decimal strings, not lossy JavaScript numbers. Retained
differences cannot exclude transient handle, address or thread reuse.

The explicit Forge configuration selects `system_informer`, `hollows_hunter`
and `system_results`. Engine families pin `executable`, `source_commit` and
`version`; results use the operator data root. Readiness never launches them.
Native phlib requests have an8-second cap, scanner requests1–45seconds, inside
the shared55-second owned helper. Snapshots16MiB, rows16,384 and inline pages
100rows/256KiB are bounded. Full snapshot path/hash provides export without
requerying a process. Optional command-line observations may contain sensitive
caller-selected values and are not silently rewritten.

Original tools, user processes and GUIs are borrowed, not terminated or closed.
Only the analyzer/request process family belongs to REA. Pinning and fixed
arguments are not an OS sandbox or complete transitive-dependency proof.
