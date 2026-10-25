# Existing guest transport and case identity

The Forge guest adapter reuses the installed authenticated Windows bridge. It
does not start another remote service, replace its credentials or restart it.
This is the identity foundation for guest analysis; it does not yet expose
arbitrary execution, IDA debugging or VM management as Forge tools.

## Identity and ownership

An explicitly selected private configuration binds a guest ID, VMX path,
host-only bridge URL, protected token file and expected computer name. The
current adapter accepts only the reviewed direct-child bridge protocol 2.0.0.
Unrecognized versions and mismatched authenticated machine names fail closed.

The existing health response has no process generation. A fixed, shipped
metadata probe observes its own parent, which that reviewed protocol starts
directly from the bridge. It reads the parent's PID and exact UTC creation
ticks. `bridgeInstanceId` is a SHA-256-derived label for those observed fields,
not a server nonce or a hypervisor attestation. The probe accepts no caller
code. Native parent lookup follows the documented
[PROCESS_BASIC_INFORMATION layout](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess);
unavailable or changed native behavior fails the probe.

Cases belong to one application-service owner and contain the observed runtime
identity. Every use observes it again. PID reuse, a different creation time,
machine change, closed case and late observation after owner close refuse the
operation. Case IDs and claimed identities in a request do not create authority.
Closing the owner does not stop the borrowed bridge or its other sessions.

The configured VMX is a selected deployment association, not proof that the
endpoint is cryptographically attached to that hypervisor VM. Bridge creation
identity is not guest boot identity, target-process ownership or a license to
signal arbitrary PIDs. A restored snapshot can restore identical in-guest state;
management cutovers must invalidate their cases independently. Target job
ownership, exact sample identity and runtime dispatch remain separate work.

## Case-file transfer

The internal file port reuses the bridge's existing `write-file`, `read-file`
and bounded `run` routes. It creates an exclusive UUID directory under the
selected guest's case parent, with an exact owner marker. Callers cannot choose
a guest destination or supply a PowerShell program through this port. Shipped
programs attribute the bridge parent again before accessing a case and reject
reparse paths, changed owner markers and unexpected transfer members.

Files are limited to 16 MiB per transfer. The existing 64 KiB host request bound
requires 40 KiB binary chunks after Base64/JSON expansion. Four requests may be
in flight; a case serializes transfers, readback and release. Reassembly checks
every part's extent and the whole-file SHA-256 before publishing a new file.
Readback hashes the locked source, slices it through the same bounded protocol,
then independently checks the received bytes. It never imports or runs them.

Transfer work has a 90-second cooperative budget. Already-dispatched mutations
drain their bounded responses; each generated child has a 15-second guest
deadline and a host settlement window. Cancellation prevents subsequent work,
not the recording of a completed physical outcome. Unknown write settlement
retains the exact case root and refuses automatic deletion. Closing drains
owned operations before releasing known-settled cases, never the borrowed
bridge. This is a reviewed application boundary, not an OS sandbox against
other privileged guest processes.

## Emulator and management foundations

The read-only LDPlayer adapter uses the selected pinned `ldconsole list2` and
the physical creation/file identities of the nonzero instance directory,
descriptor and writable disks. A deterministic VBox UUID or display name alone
does not identify a replacement. Names are preserved for humans; missing
process creation metadata remains unknown. Closing this adapter releases its
query helper, not an emulator instance. This case identity does not authorize
Android execution, signal a PID, or attest an Android boot.

The shared management application defines one-shot, expiring proposals,
revalidation, single-action serialization and incident latching. Deletion,
reset and overwrite require a separate trusted confirmation port with an exact
typed object name. No tool argument can act as that confirmation. Snapshot
creation/revert requires a substantive task-necessity record. The application
contract alone is not a delivered management feature: concrete durable journal,
OS serialization, vendor postflight and native client input adapters must be
integrated before exposing a management tool. Real destructive tests remain
subject to individual user approval.

## Bounds and verification

Health requests have an absolute five-second deadline. The fixed metadata child
has the existing bridge's five-second run limit; the host allows a bounded
cleanup window and limits request/response JSON to 64 KiB. No redirects are
followed. Transport credentials and remote failure bodies are not returned in
diagnostics. Cancellation closes only the owned socket. A lost response is not
proof of remote cleanup; this metadata-only adapter makes no such claim.

The expanded foundation group passed 71 deterministic source checks plus four
pure emulator-parser/physical-identity checks. They cover the existing metadata
boundary, case invalidation, one-shot management confirmation, transfer
hashes/bounds, cancellation, close races and retention of uncertain writes.
The management tests use recording ports; they do not certify a vendor writer
or real human confirmation UI.

The production foundation build passed an actual 131,091-byte transfer to the
configured Windows guest, complete byte/hash readback, owned-case removal and
closed-case refusal. The bridge process identity remained unchanged. The
selected nonzero emulator instance passed read-only physical-generation
revalidation and explicit invalidation. No target, emulator lifecycle action,
GUI or configuration change was used. Private receipts retain timings and
observed identities; CPU and peak process-family memory were not measured.
This does not certify G11's debugger/target-job lifecycle or daily client
activation.

## Owned IDA job transport

The next internal port reuses the existing PowerShell worker and independent
Windows JobObject guard. It can run through the already-authenticated bridge
without adopting an interactive desktop or creating a daemon. The worker
verifies the configured headless frontend, staged input and wrapper digests,
joins containment before launching IDA, and records exact creation timestamps.
Only owned stop markers are used; caller-selected PIDs cannot be signalled.

Launch is single-shot. A real bridge call completed with empty stdout even
though its worker and durable launch receipt existed. The port reads that
exact job's persisted receipt rather than starting another worker. Completion
requires a matching guard receipt, zero active contained processes, and exact
worker/guard creation-identity exit observations. Missing receipts, access
failures and a successful script result alone do not establish cleanup.

The current real probe verified this launch/recovery/containment lifecycle but
did not execute IDAPython successfully: IDA's SYSTEM context reported an
unaccepted license agreement and exited before producing the script result.
The installed interactive agent also lacked the required owned-launch protocol
and had no logged-in user session. These are current prerequisites, not proof
that an earlier configured guest still works. No license state was changed or
GUI opened to pass this check. The installation's automatically loaded optional
AI plugin also needs a reviewed owned profile before claiming local-only IDA
analysis. No plugin network transfer was established by this probe.

This internal transport is not yet the public G11 execution/debugger surface.
It does not confer authority to manage VM snapshots or emulator instances.
