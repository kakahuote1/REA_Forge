# Host execution admission

Forge's local CLI and eager/deferred MCP dispatch use one application-level
admission function before a registered operation body runs. Canonical REA
effects determine which current operations can run foreign code or change a
device. CLI aliases use the existing `CLI_COMMAND_TOOL_ALIASES`, not another
router. The ordinary inventory stays complete; session availability identifies
these refused operations as `execution_domain_required`.

Host refusal covers raw GDB/Rizin/Cutter consoles, debugger and Frida session
startup, instrumentation/script load/resume, active browser/Electron/native
execution scenarios and device mutations. Supplying a remote-looking address,
an environment variable or a request claiming approval does not grant a verified
guest identity. Guest/device transport and management confirmation are separate
delivery packages; the host guard does not certify them.

Trusted static analyzers, decompilers/compilers that do not run selected code,
recorded captures, byte/metadata reads and the existing constrained 010 recipe
remain available subject to their own configuration and validation. The 010
exception is this named reviewed endpoint, not permission for arbitrary scripts
or a claim of OS sandboxing. Session cleanup can release its existing owned
resources; the guard must not strand them after a policy change.

This boundary covers the fork's registered public operations. It cannot confine
an independent shell or code running with the operator's OS account, nor is it
an attestation against malicious tools, guest escapes or falsely declared new
extensions. Every new operation still needs a truthful canonical effect audit
and an execution-domain decision before integration. Human/AI ownership and
destructive management retain their independent confirmation requirements.
