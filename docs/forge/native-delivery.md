# Native integration and delivery

This fork extends REA's existing composition, contracts, application services,
CLI/MCP adapters, Evidence, setup and bundled skill. It does not embed the old
router, add an agent loop, or require one persistent MCP server per engine.
Workstation execution state and receipts remain private. This document fixes
delivery scope; it does not announce that the remaining capabilities work.

## Delivery families

Each family needs explicit target identity, declared effects, bounded execution,
observed cleanup, original/derived provenance and a real grouped acceptance.
Use an existing REA operation when its intent and authority match. New behavior
uses a thin provider/port implementation and shared CLI/MCP workflow.

| ID | Operations to deliver | Existing implementation to reuse | Additional boundary |
| --- | --- | --- | --- |
| G01 | Template fields/offsets, byte reads/search/compare, edits, backup/restore | Forge binary-editor contracts and 010 bridge | Explicit configuration, accurate availability and configurable reviewed assets |
| G02 | JVM facts, decompile/disassemble, search/calls, compile/edit/repackage/compare | Forge Java contracts; Recaf, Vineflower, CFR, BCV and javap | Configuration and readiness; never execute selected classes |
| G03 | Managed metadata/resources, C#/VB/IL, typed edits, compile/readback | Forge dotnet contracts and dnSpy worker | Configuration, readiness and native lifecycle faults |
| G04 | Offline operation discovery, recipe validation/run/replay, candidate hints | Forge CyberChef contracts and official operation code | Cover requested operation families; the verified twenty-operation baseline is not the entire engine |
| G05 | Native static queries; separate IDB edits/save, controlled Python, approved analysis extensions | REA IDA provider and existing typed static adapters | Preserve read-only upstream semantics and borrowed GUI databases |
| G06 | Packaged Python inventory/extract, version/implementation facts, version-matched decompilation | REA artifact/PYC readers; existing xdis and decompiler integrations | Report exact supported versions/models and unsupported cases |
| G07 | PE structure/dependencies, ordinary packer identification/unpack | REA format readers; existing PE workbench, DiE/UPX integration | Distinguish static dependency candidates from Windows loader behavior |
| G08 | Capability-rule matches, recovered strings, API-hash lookup | Existing capa/FLOSS/FLARE-hash integrations | These are analysis capabilities, not obsolete governance |
| G09 | Android code/references, resource decode/rebuild, smali/dex edits, signing/verification | REA JADX/apktool/signature readers; existing reconstruction code | Verify rebuilt bytes; device install belongs to G13 |
| G10 | HAP inventory/graph, ABC/Ark analysis, available decompilers and signature checks | REA package inventory; existing HAP/ABC adapters | Record exact missing optional engines without blocking available ones |
| G11 | Guest identity/cases, full IDAPython and harmless native debugging | Existing guest transport and IDA integration | Guest execution only; preserve NAT and sharing settings |
| G12 | Guest debugger launch/attach, break/step/registers/memory, symbols and dumps | Existing x64dbg/WinDbg integration and REA ownership primitives | Do not close or kill borrowed user sessions |
| G13 | Named emulator instances, controlled lifecycle, root/ADB preparation and APK install | REA ADB operations and existing LDPlayer API code | Explicit selected instance; destructive actions need separate confirmation |
| G14 | Frida device/process selection, attach/spawn, JS/TS load/reload/messages/RPC and recovery | REA instrumentation ports and existing 16.5.2 client/server chain | Keep incompatible binding versions separate; no implicit target installation |
| G15 | Classic GUI/CA control, capture start/stop, chosen traffic sources, recovery and SAZ readback | Existing Fiddler Classic plugin; REA capture Evidence | Host traffic off by default; requested capture and current readiness are different facts |
| G16 | Recorded PCAP/TLS/fields/streams/objects, HAR/SAZ, existing Apipost documents | REA capture readers and existing platform-specific adapters | No implicit live capture or remote requests |
| G17 | Explicit-process observations and scan findings | Existing System Informer, Hollows Hunter/PE-sieve; G12 WinDbg | Read-only scope; no silent driver installation or process-wide cleanup |
| G18 | Explicitly inventoried DudeSuite/Yakit request, session or traffic APIs | Actual installed interfaces, only where established | Opening a GUI is not a functional MCP adapter; absent interfaces remain unresolved |

The human editor remains a separate delivery consumer of these same services:
top instance/app/PID selection, file tree and editor, session controls, bottom
output, and a separate Fiddler panel. Its actual interaction and restart paths
require acceptance; backend tests do not establish GUI readiness.

## Scope-qualified exceptions

- Burp configuration remains user-deferred. Do not modify the user's older
  installation or repeat the previous GUI startup/export experiment.
- JEB supplements Android/Java only with an applicable license and actual
  supported interface. Its remote debugger remains deferred.
- Optional Ark engines retain their specific missing-prerequisite report.
- DudeSuite and Yakit remain required integration investigations, not silently
  excluded because another tool has related functionality.
- Snapshot deletion and destructive emulator actions need individual approval;
  contract checks must not perform real destructive actions to obtain coverage.
- Superseded tool registries and governance pipelines are not runtime
  dependencies to migrate. Their useful engine capabilities are mapped above.

## Native integration work package

1. Parse operator-selected provider settings once at their owning boundary and
   inject them through composition. Do not infer configuration from a checkout.
2. Keep target-free operations usable before `open_binary`; report missing
   engines in capability availability rather than hiding or inventing tools.
3. Keep application services, results and lifecycle shared by CLI and MCP.
4. Register the local fork entrypoint through REA setup. Setup/doctor and bundled
   recovery instructions must not redirect callers to the upstream npm package.
5. Extend the authored skill and its managed references; regenerate outputs.
6. Enforce host/guest effects at execution boundaries before daily activation.

The checked source baseline is `293832bafc9a054914ec514fe906dd4936c7a372`, with
the existing downstream static groups through `61cd545`. Keep the existing
compatible pinned runtime; do not follow main or upgrade installed engines
without a demonstrated prerequisite.

## Verification and publication

Finish a complete work package before its concentrated affected checks. Reuse
unchanged real-engine evidence and rerun changed boundaries; do not run every
regression after an internal edit. A failed check is repaired and rerun only at
its affected boundary. All commands need real deadlines, hidden subprocesses,
bounded diagnostics and retained ownership when cleanup cannot be confirmed.

Final publication additionally requires actual client discovery and calls,
human GUI interaction, independent launch without the old framework, and
verified retained data before retiring any superseded directory. A catalog,
registration file, historical pass or successful build is not that proof.
