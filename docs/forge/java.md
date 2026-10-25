# Static Java integration

Select the operator configuration and data directory through
[static-provider configuration](static-configuration.md); production does not
infer either from the checkout location.

Forge uses the installed Recaf core APIs for editing and inspection, standalone
Vineflower/CFR and Bytecode Viewer library APIs for alternate renderings, and
the installed JDK's javap for bytecode facts. It does not launch those tools'
GUIs or execute the analyzed classes. JEB is a separate, conditional provider.

## Configure and build

In the ignored `.forge-local/config/tools.json`, add a `java` object with
`java`, `javac`, `javap`, `recaf`, `cfr`, `vineflower` and `bcv` entries. Each
entry has exactly `path` (absolute installed file) and `sha256` (observed digest).
Add `input_roots`, an array of explicit absolute input directories. The common
top-level `python_executable` must also be configured.

Build the authored API workers with:

```text
python -I -S scripts/forge/build-java-workers.py
```

Compiled workers and their source/engine/class digests live in ignored
`.forge-local/build/java`. Changing sources or engine pins requires rebuilding.
No engine JARs, JDKs, licensed tools or machine configuration are redistributed.

## Tools

| MCP tool                 | Scope                                                                           |
| ------------------------ | ------------------------------------------------------------------------------- |
| `forge_inspect_java`     | Class/member/classfile inspection                                               |
| `forge_decompile_java`   | Explicit standalone CFR/Vineflower, Recaf CFR/Vineflower or BCV Procyon/JD-Core |
| `forge_disassemble_java` | javap, Recaf ASM, BCV textifier/ASMifier                                        |
| `forge_search_java`      | Class/member names, constants and references                                    |
| `forge_java_call_graph`  | Exact method's static bytecode calls                                            |
| `forge_edit_java`        | Typed derived edit/compile/assemble/export actions                              |
| `forge_compare_java`     | Class/member/bytecode comparison                                                |

CLI names replace underscores with hyphens and accept one JSON argument with
the same schema. Use JVM internal names such as `example/Main`, not display
labels, filenames, dotted paths or process identifiers.

`forge_edit_java.action` selects class/method/field rename, one of two audited
transformers, class export, single-source compilation, multi-source compilation
with optional dependencies, or Recaf JASM assembly. Every edit creates a new
artifact and re-reads it. Compilation uses `-proc:none`; it does not run compiled
classes or annotation processors. ASM textifier output is not Recaf JASM input.

External rendering dependencies are supported by standalone CFR/Vineflower.
Other engines reject that option rather than silently ignoring it. Output text,
archive expansion, source counts, process duration and memory are bounded.
Format coverage and cross-engine source agreement are not semantic-equivalence
proofs, and static calls do not resolve all reflection or dynamic dispatch.

Retained inputs, derived artifacts, native logs and receipts live in ignored
`.forge-local/work/java`. Each public call owns a fresh helper and process
family using REA's supervisor; optional discovery performs no engine startup.
The helper's owner deadline is 55 seconds and each native call has a 30-second
deadline. These restrictions do not constitute an operating-system sandbox.

`node scripts/forge/verify-java.mjs` performs concentrated real-engine CLI/MCP
acceptance on self-created fixtures. Its machine-local receipts list exactly
which paths passed; source availability alone is not a runtime pass.
