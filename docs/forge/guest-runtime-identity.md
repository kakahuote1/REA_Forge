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

## Bounds and verification

Health requests have an absolute five-second deadline. The fixed metadata child
has the existing bridge's five-second run limit; the host allows a bounded
cleanup window and limits request/response JSON to 64 KiB. No redirects are
followed. Transport credentials and remote failure bodies are not returned in
diagnostics. Cancellation closes only the owned socket. A lost response is not
proof of remote cleanup; this metadata-only adapter makes no such claim.

The current source group has 27 deterministic checks for case freshness,
creation-identity changes, malformed metadata, version/guest mismatch,
cancellation, close races, bounded responses, refusal and absolute deadlines.
The actual configured Windows guest passed two identity observations, matching
case readback and closed-case refusal without restarting its bridge or running
a target. The workstation receipt is private; this does not certify G11's
debugger or target-job lifecycle.
