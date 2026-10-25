# Forge bridge provenance

The selected 010 algorithms, Java API workers and dnSpy static API worker were migrated
from this fork owner's existing local integration project at the owner's
request. They are source-level adapters, not copies of that project's MCP
server, registry, background services or router.

Recaf, Vineflower, CFR, Bytecode Viewer, the JDK and 010 Editor remain separately
installed engines under their respective licenses. Their binaries, commercial
licenses and third-party template assets are not included here. API imports do
not grant redistribution rights to an engine. Preserve engine-specific notices
if creating a separate engine distribution.

dnSpy/dnlib, dnSpy's ILSpy decompilers, Roslyn and the .NET runtime also remain
separate installed dependencies under their own licenses. Only the owner's
authored static adapter source is migrated here; engine DLLs are not committed.

capa and FLOSS executables and the FLARE-IDA shellcode hash database are
operator-supplied Mandiant dependencies under their respective Apache-2.0
licenses. The Forge source invokes their fixed local CLI/read-only database
interfaces; their binaries, bundled rules and database are not redistributed
in this repository. Preserve their notices when moving private runtime assets.
