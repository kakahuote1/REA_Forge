# Verified downstream scope

## PE/UPX host subset, 2026-10-25

Five added operations reuse audited pure PE/dependency parsers and fixed UPX
commands through native configuration, service, CLI/MCP and Evidence. The whole
host subset passed against existing known-source plain/packed PE fixtures in
10.391 seconds. Independent PE header bytes, native resource/certificate/export
readers, real APISet/KnownDLL metadata, bounded dependency graph/readback,
UPX packed/nonpacked test outcomes, fresh unpacked output/headers and original
hashes were checked. Negative requests, a real 1 ms native timeout,
cancellation/recovery and CLI parity passed; temporary ownership settled.
The first run's mistaken x86 assumption was corrected to an independent byte
oracle; the fixture was actually PE32+. No fixture or dependency was executed.

Migration also corrects producing boundaries: entropy no longer scans a section
256 times, the TLS reader avoids a whole-file copy, DLL identities do not become
paths, Unicode/DTD manifest handling is explicit, KnownDLL directory entries do
not become DLL names, depth truncation is reported, and previously examined
edges are not claimed to establish cycles. Parser observations retain their
limits rather than becoming an authoritative Windows loader result.

The source group passed 157 unique cases (40 service/config/effects, four Python
boundary cases and 113 module checks). One stale effects exception was removed
and only that failing file was rerun. The test type graph passed in 7.344 seconds;
the bounded production build passed in 99.500 seconds. Targeted lint has no
errors and retains the standard registration-parameter warning. CPU time and
peak process-family memory were not measured.

G07 stays unchecked: DiE rule evaluation and existing Unipacker emulation still
need their execution-domain integration; dynamic dumping belongs to the guest
chain. See [host operation scope](pe-static.md). This subset does not replace
those remaining requirements or authorize retirement of their installations.

## Android static analysis and derived builds, 2026-10-25

Seven added operations reuse the native CLI/MCP/Evidence path. A known-source
12,691-byte harmless APK was decoded, its application label changed in a new
project, rebuilt, test-signed, cryptographically verified and decoded again.
REA's native signature declarations independently matched the certificate.
Native JADX package/class/method/reference queries and apktool resource reading
worked against the derived APK. A separate known-answer Smali fixture assembled
to DEX, disassembled, changed its integer from 42 to 43, reassembled and reread;
DEX SHA-1/Adler-32 checks passed. No APK was installed or executed.

The group also covers test-key reuse, receipt/edit/key-read rejection,
unconfigured signing profiles, invalid input, unsigned APK status, an actual
1 ms native deadline, cancellation/recovery and CLI/MCP readback parity.
Already-passed artifacts were hash-verified before reusing failed-run
checkpoints. Initial fixture/selector assertions were corrected without
repeating successful engines. Windows case-colliding archive names are
explicitly unsupported by this build path, not evidence of a malformed APK.

Real cleanup testing found upstream JADX engine temporary directories outside
the existing resource root. JVM temp/home and child TEMP now belong to that
root. The affected native close/recovery tail passed in 12.749 seconds; its
test owner non-recursively reclaimed an empty Java prerequisite performance
directory. Unknown leftovers would still fail the check. The complete earlier
functional tail passed its checks in 78.285 seconds before reporting that
cleanup omission; its receipt and failed status remain retained.

The group has 165 unique passing cases (46 service/config/effects, 114 existing
module/timeout checks and five owned Python boundary cases). The test dependency
type graph passed in 15.203 seconds. The final affected production build passed
under its 300-second hard limit, taking 207.641 seconds including orchestration.
Current stdio startup/config-recovery/scoped setup dry-run passed in 25.315
seconds: 272 tools, 52 Forge entries. No daily client settings were changed.
CPU time and peak process-family memory were not measured. Installation belongs
to G13; see [operation scope](android-build.md).

The Python extraction-to-xdis boundary was separately read through the current
CLI using an already retained PyInstaller member. Its source hash was unchanged;
no extraction, target execution or model inference was repeated. G06 modern
inference remains unverified.

## Python non-model subset, 2026-10-25

Current real CLI/MCP evidence covers native CPython facts, native PyInstaller
inventory/extraction with 157 output hashes, all three xdis renderings,
uncompyle6/decompyle3 reconstruction and text readback, explicit engine/version
refusal, an actual 1 ms library deadline, cancellation/recovery and CLI routing.
The source group passed 38 cases plus 113 module boundaries; the test dependency
type graph passed. Production builds passed, with the final affected build
taking 86.891 seconds. Current stdio startup passed in 8.245 seconds with 265
tools and 45 Forge entries, including missing-model isolation. Daily Codex
registration remains unchanged.

Modern PyLingual inference has not passed current Forge acceptance. The real
attempt was refused before model loading at 1,974,095,872 available bytes,
below the configured 3 GiB admission. Temporarily suspending the task-started
Win10 preserved its state but yielded only 2,748,981,248 available bytes. The
VM was resumed and its single UID11 snapshot remained unchanged, without a
pending consolidation. Other VMs and VM settings were not changed.

The producing error now uses REA's retryable `resource_constraint` category,
not unsupported-target reporting. Its deterministic refusal/cleanup tail passed
in 4.477 seconds using an owned policy fixture, without loading models or
re-running passed bytecode engines. The G06 checkbox stays open for actual
3.9–3.12 inference and remaining group closure. CPU time and peak process-family
memory were not measured. See [Python scope](python-bytecode.md).

## Offline traffic and API documents, 2026-10-25

Nine added operations share the native CLI/MCP/Evidence path. The installed
TShark/capinfos report 4.2.6, despite their enclosing folder label. Real offline
checks cover protocol trees/paging, exact fields, statistics, directional stream
bytes, HTTP object/body hashes, TLS 1.2 and TLS 1.3 early data with explicit
keys, wrong/no-key isolation, native HAR/SAZ body recovery, and structural
OpenAPI/Swagger/Postman inspection/comparison/export. No live capture, GUI,
proxy change or endpoint request was involved.

One negative test exposed Wiretap's implicit non-PCAP format guessing. The
producing boundary now requires a PCAP/PCAPNG header. Passed engine artifacts
and source hashes were verified and reused; only the affected negative and
remaining tail were rerun. That tail passed in 51.078 seconds, including a real
1 ms native deadline, cancellation/recovery, explicit whole-file scanning,
shared-helper G08 readback/deadline checks, CLI parity and temporary cleanup.
The new header check also accepts both selected public TLS container headers.

The source group covers 155 unique passing cases; the test dependency type
graph and production build passed. Targeted lint has no errors after splitting
an oversized test group and retains 11 warnings. Current production startup
passed in 26.249 seconds: 261 tools, 41 Forge operations, missing-TShark
isolation and same-connection recovery. No daily Codex configuration was changed.
CPU time and peak family memory were not measured in this group.

This completes the G16 offline subset, not its pending guest Apipost CLI-suite
migration or the whole delivery plan. See [offline scope](offline-traffic.md).

## Native enrichment, 2026-10-25

Five target-free operations now share native CLI/MCP/Evidence: pinned capa
capability rules, FLOSS strings, FLARE hash-type/catalog lookup and retained
result paging. Actual capa 9.4.0 and FLOSS 3.1.1 analyzed a source-generated,
unexecuted PE. Checks observed a real XOR rule with addresses/ATT&CK/MBC,
a known static string, and the known XOR-created marker as decoded/tight
strings. An independently calculated ROR13+ADD vector matched LoadLibraryA.

The concentrated engine run and affected-tail completion cover retained JSON
digests/paging, malformed inputs, an actual 1 ms native deadline, active
cancellation/recovery, CLI/MCP equality, original preservation and closed
temporary/process owners. Two verifier assertions were repaired at their
representations: case-insensitive rule naming and canonical timeout-envelope
decoding. Already-passed engine results were hash-verified and reused rather
than re-running them.

The final production build passed in 68.094 seconds. The affected source checks
cover 144 unique cases, including 113 module-boundary cases; the test/dependency
type graph passed. Targeted lint has no errors and retains 16 warnings. A current
production startup check passed in 6.099 seconds with 252 tools, 32 Forge
operations available without opening a target, missing-FLOSS isolation and
same-connection recovery. Daily Codex activation remains pending. See
[native enrichment](native-enrichment.md) for exact scope and configuration.

## Host execution admission, 2026-10-25

The 21 current host target-execution/device-mutation operations are refused
before dispatch through the shared application rule. CLI reuses canonical aliases;
MCP retains the rule when the SDK replaces deferred callbacks. The same producing
wrapper also preserves request tracking. Session discovery reports
`execution_domain_required`, while static helpers and owned cleanup remain usable.

The complete affected group finished with 54 passing cases after scoped repairs.
Actual CLI aliases and fake guest-environment claims were covered. A current
production stdio run passed safe representative refusals, lazy materialization,
static discovery/recovery, isolated setup dry-run and archive parity in 5.052
seconds. Typechecking, the final build and eight module boundaries passed;
targeted lint retains warnings but has no errors. No target, GUI, guest, device
or capture was started. This is not delivery of the pending guest transport or
management approval path. See [host boundary](host-execution-boundary.md).

## Local distribution and bundled skill, 2026-10-25

Production setup now binds the public local launcher and exact Node executable.
Doctor distinguishes this local distribution from an upstream npm registration;
the live server exposes `forge-local` alongside its path/version/catalog identity.
Skill 45-forge.1 carries ten managed files, including local launcher, static-tool
selection and shared-ownership references. Generated templates remain portable;
installation and doctor additionally verify the machine-local launcher binding.

The focused package finished with 67 passing cases and four platform-conditioned
skips. Two initial failures were repaired: a fixture still asserting npm startup
and asymmetric path normalization in the existing Windows identity comparison.
Only those two branches were rerun, and both passed. Typechecking, eight selected
module boundaries, skill validation, generation checks and the final build passed.
Targeted lint has no errors but retains style/complexity/size warnings.

The actual CLI/stdio MCP startup acceptance passed in 5.485 seconds, including
independent cwd/config, all 27 target-free static entries, missing-peer isolation,
same-connection recovery, local launcher identity and an isolated Codex setup
dry-run that produced no writes. Actual CLI setup/doctor and skill installation
were tested only in owned temporary homes, including backup/readback/idempotence
and binding drift. The static engines were not rerun after unchanged core logic.
Their current receipts in the next section remain the engine evidence.

No daily client activation, GUI, device, guest, proxy or capture was changed.
Shared-ownership instructions do not replace the pending execution boundary or
certify future persistent-service integrations. See [local distribution](local-distribution.md).

## Native configuration and discovery, 2026-10-25

The four existing static families now receive explicit operator configuration
and data selectors through REA composition. CLI and MCP share narrow application
ports. Session discovery reports their individual file-presence readiness before
opening a binary; readiness is not a license or engine-execution claim.

The affected source group passed 43 tests, typechecking, and ten selected module
boundaries. The runtime/catalog/skill build passed in 22.735 seconds. Targeted
lint has no errors and retains three size/parameter warnings. The source test
selector initially refused the new adapter directory; the existing adapters
project now explicitly owns it, and the complete selected group passed.

Real CLI/stdio MCP groups passed again with the explicit configuration path:
010 in 20.368 seconds, Java in 32.996, CyberChef in 22.120, and dnSpy in 84.712
(76 successful native calls and all thirteen effectful edits/readbacks).
The original preservation, native cancellation, recovery and owned-request
closure checks passed. Fixtures were source-owned and target code did not run.

The affected production startup check passed in 4.614 seconds: a separate
operator configuration file and independent working directory, all 27 static
operations available without `open_binary`, missing Java isolated from its
peers, malformed optional configuration reported without breaking status, and
same-connection recovery after repair. The complete catalog remains 247 tools.
No GUI, device, VM, proxy capture or user client configuration was changed.

This verifies the configuration/discovery work package, not daily Codex
activation, the remaining host/guest execution policy, new engine migrations,
human-workbench delivery, or old-framework retirement. Earlier group limitations
below still apply. Machine-local receipts remain private.

## Earlier static-engine verification

The 010 fault-path acceptance also exercised actual 35-second native expiry,
owned-handle termination and same-connection recovery, separately from the
completed functional inventory.

Workstation verification on Windows, 2026-10-22. This records completed groups,
not completion of the migration or availability of every upstream provider.
External engines are separately installed and operator-configured.

| Group             | New tools | Real workflow verified                                                                                                                                                                                                            |
| ----------------- | --------: | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 010 Editor        |        10 | Header/ZIP/PNG templates and retained CSV; read/search/native comparison; derived edits, constrained script, original edit/backup/restore; CLI/MCP parity; native cancellation and owned-resource closure                         |
| Java              |         7 | Six decompiler routes; four bytecode renderers; metadata/search/calls; compilation, renaming, export, JASM and archive comparison; effectful dead-code/duplicate-annotation removal; malformed input and CLI/MCP parity           |
| Offline CyberChef |         5 | All twenty reviewed operations; six encoding/compression roundtrips; independent hash/HMAC/CRC/AES vectors; canonical recipes, saved replay, bounded previews, rejection and CLI/MCP parity                                       |
| .NET / dnSpy      |         5 | C#/VB/IL rendering; metadata/types/resources; thirteen effectful edits and fresh readback; library/console compilation; catch/finally, locals/branches and attribute targets; CLI/MCP parity; active native cancellation/recovery |

The current catalog has 247 entries: 220 inherited plus 27 downstream tools.
Catalog presence is not evidence that an external engine, license, device or
guest is configured. Native target execution, injection and full guest control
have not been migrated by these static groups. Daily Codex cutover and old
framework retirement are also not complete.

The Windows baseline build and real ZIP CLI/stdio MCP workflow passed. Group
verification uses the installed engines and generated source-owned fixtures,
preserves original hashes, closes owned requests, and retains private receipts.
Java's transformer tests require a nonzero effect: counters decrease and output
digests change. Historical numeric PIDs are not treated as process ownership.
Helper families have a 1 GiB memory bound and enforced command deadlines.

The dnSpy group passed in 143.194 seconds, including 76 successful native
commands with owned-handle wait completion and a separately observed active
native cancellation. The group's fixture initializer never ran. This does not
establish IL runtime correctness or strong-name validity; dnSpy's actual native
deadline and every permission/capacity fault remain outside this lane.

The direct tool-effects contract tests and affected module-boundary checks pass.
Full upstream PR regression, every parameter/capacity/permission combination,
hostile-parser sandboxing and complete transitive-dependency authentication are
not established by this acceptance. Static lint has no errors, with remaining
non-blocking size/complexity/parameter warnings. Raw machine-local receipts,
fixtures, commercial engines and credentials are intentionally not published.
## Harmony static group, 2026-10-25

The native CLI/stdio group passed with installed, pinned Windows engines. REA's
existing inventory and Harmony application projection were reused. On the same
known HAP/ABC, abcde and official Ark observed16classes/123methods; selected
instructions and encoded references were read back, supported experimental JS
was retained, and unsupported opcode reconstruction failed explicitly.
JADX-HAP produced16 actual source files from extracted ABC. The legacy resource
fixture yielded118entries; RestoolV2 remains explicitly unsupported.

Fresh self-signed test signing and independent signature verification passed,
including a configured-profile route using fixture keys, unchanged certificate/
profile hashes and unsigned/tampered negatives. This does not establish platform
trust, deployment rights or production-key acceptance. Actual Java/Ark/signature
deadlines, cancellation recovery, missing-engine isolation, CLI parity, original
preservation and owned request cleanup passed. Successful producers were reused
only after receipt/full-artifact hash checks. Final affected tail7.630seconds;
CPU and peak process-family memory were not measured.

The group added8 operations; the observed catalog285/Forge65 is not proof of
daily Codex activation. Optional Linux engines/assembler prerequisites, guest
runtime and human workbench remain separately tracked. No target, GUI, device,
trust store or operator configuration was changed.
