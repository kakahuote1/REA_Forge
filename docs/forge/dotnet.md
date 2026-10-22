# dnSpy static analysis and derived editing

Forge adds five typed CLI/MCP operations backed by the installed dnSpy/dnlib,
ILSpy decompiler and Roslyn APIs. It retains upstream REA's metadata/CIL tools;
their read-only contracts are unchanged.

| Task                                                                  | MCP operation                | Selection                                                                    |
| --------------------------------------------------------------------- | ---------------------------- | ---------------------------------------------------------------------------- |
| Read types, signatures, IL operands, references or resource inventory | `forge_inspect_dotnet`       | Local assembly; `view` is `types`, `metadata`, `resources` or `capabilities` |
| Render source for a type                                              | `forge_decompile_dotnet`     | Observed type token and installed language                                   |
| Read embedded bytes                                                   | `forge_read_dotnet_resource` | Exact resource name                                                          |
| Modify a derived file                                                 | `forge_edit_dotnet`          | Typed action, observed tokens and new output filename                        |
| Compile a C# source file                                              | `forge_compile_dotnet`       | Source path, output filename and `library` or `console` output kind          |

CLI names replace underscores with hyphens. Each accepts one JSON argument
matching its MCP input schema, followed by `--format json` when JSON output is
needed. For example:

```text
rea forge-inspect-dotnet "{\"path\":\"C:/analysis/example.dll\",\"view\":\"types\"}" --format json
```

Configure an operator-owned `dotnet.input_roots` list and `python_executable`
in ignored `.forge-local/config/tools.json`. Inputs outside those roots are
rejected. Derived Forge .NET workspaces are admitted for subsequent readback.
The actual installed decompiler languages are reported by `capabilities`;
an unavailable language fails explicitly. IL instruction facts remain available
through type inspection and upstream CIL inspection independently of a textual
IL decompiler.

## Editing and readback

The thirteen actions rename a type/method/field/property/event, change a method
signature or field/property type, replace custom attributes, replace an embedded
resource, change assembly identity, replace one instruction with NOP, or replace
a typed method body. Method bodies support constant/argument/local operations,
selected arithmetic, branches, existing method/field/type references, catch and
finally ranges. `endfinally` is supported for complete finally bodies.

Every edit creates a new private output, records its digest, and opens it again
for type and metadata facts. Output readback returns the first eight types;
follow its explicit pagination to inspect remaining types. Names and tokens
come from the selected artifact, not from a different build. Re-enumerate tokens
after writing instead of assuming a writer preserves every token.

Resource bytes are not deserialized into runtime objects. Compilation invokes
fixed Roslyn APIs with platform metadata references; it accepts neither a custom
MSBuild project nor analyzers/source generators. Library output does not require
`Main`. Optional embedded bytes must be paired with their resource name.

## Process and dependency ownership

`scripts/forge/build-dotnet-worker.py` builds the authored C# adapter offline
against operator-selected installed APIs. A matching installed .NET 5 SDK is
needed for this API version. The script uses isolated caches, disables compiler
sharing and node reuse, and copies only the .NET Core runtime needed for calls.
It does not copy the old MCP framework or a complete SDK into the runtime.
Engine/runtime binaries and build manifests stay private and are not published.

The request worker checks source and engine/runtime file identities, then starts
one hidden native process with a private request. It opens no socket or named
pipe. Each native command has a 35-second time/output bound; REA additionally
owns the complete helper family, with a 55-second deadline and 1 GiB memory
bound. Cancellation and close use REA's existing admission and cleanup owners.
Failed cleanup is not inferred from an old numeric PID or silently discarded.

## Limits

- No target execution, debugging, arbitrary dnSpy plugin or general script
  endpoint. The separately planned guest domain owns runtime work.
- Static engine restrictions are not an operating-system sandbox. The required
  .NET 5 runtime is old; these checks do not establish resistance to a malicious
  parser exploit. Untrusted-engine execution belongs in an isolated guest.
- A saved and readable assembly is not proof of valid IL, correct behavior,
  compatible callers, preserved strong-name signatures or retained Authenticode.
  Type/signature edits do not automatically rewrite all call sites and accessors.
- Fixed compilation references cover installed platform assemblies, not every
  application's external dependencies or original build environment.
- Inputs are at most 64 MiB, C# source at most 1 MiB and embedded resources at
  most 4 MiB. Detailed type pages have explicit output budgets. Structured type
  signatures have three container levels; method bodies have at most 512
  instructions, 64 locals and 16 handlers. Integer JSON operands stay within
  JavaScript's exact integer range.
- Private working copies and derived outputs are retained. The migration's
  shared deduplication/retention step must complete before daily client cutover.

## Group verification

After building the CLI/MCP runtime and native adapter, run
`node scripts/forge/verify-dotnet.mjs` using the configured portable Node runtime.
The lane creates its own C# and malformed-file fixtures, exercises all five
public operations and thirteen edit actions, checks fresh output facts and
digests, compares CLI/MCP observations, and tests rejected requests and active
native cancellation followed by same-connection recovery. It also checks catch
and finally readback, attribute targets, library/console compilation and that a
fixture's observable static initializer was never executed.

Machine-local receipts record actual outcomes. Having this verifier or a tool
catalog entry is not itself a passing result. This lane does not cover every
capacity/permission fault, late cancellation phase or native timeout scenario.
