# Sharing tools with the operator

Treat an existing GUI, IDB, debugger or persistent service as borrowed unless
its ownership record proves this operation created it. Opening, refreshing,
switching targets or exiting a frontend must not implicitly configure, stop,
delete, save or capture. Observe current state rather than trusting saved intent.

- Analyze a copy when making changes. Record original/output paths and hashes.
  An explicit in-place edit must use its advertised backup/readback path.
- Do not save or close an operator's GUI database, detach their debugger,
  restart their server or kill an unrelated process to resolve a conflict.
  Report a busy/mismatched owner and continue with an independent working copy.
- Cancellation and deadlines reclaim only resources created by this request.
  Preserve user Frida servers and capture/CA configuration until the operator
  explicitly chooses the corresponding stop/revoke/delete action.
- Distinguish configured/requested/observed-ready/stopped/offline/conflicted.
  A persisted capture request with Fiddler offline is not active capture.
- Static host operations and guest target execution are distinct. Never fall
  back from an unavailable guest to host execution or arbitrary host Python.
- Snapshot deletion and emulator reset/disk overwrite need individual external
  confirmation and serialized post-operation verification. A tool argument
  asserting approval, general automatic approval or a missing GUI is not consent.

These instructions describe the ownership contract. Only claim a feature is
implemented when the connected tools enforce it and the current acceptance
record covers it; a guide alone is not an execution boundary.
