# Local Forge launcher

Setup binds this reference to the Node executable and public launcher of the
build performing installation. It is compared during doctor and reinstallation;
moving the build or changing Node requires a reviewed scoped setup repair.
The source/package template contains no workstation paths or secrets.

Exact argv prefix (append CLI arguments as distinct arguments):

```json
{{REA_FORGE_ARGV_PREFIX}}
```

PowerShell examples:

```powershell
{{REA_FORGE_POWERSHELL_PREFIX}} doctor --client codex --json
{{REA_FORGE_POWERSHELL_PREFIX}} setup --client codex --dry-run --json
{{REA_FORGE_POWERSHELL_PREFIX}} mcp doctor --json
```

POSIX shell example:

```sh
{{REA_FORGE_POSIX_PREFIX}} doctor --client codex --json
```

Unresolved launcher placeholders mean this is an authored
or packaged template, not a bound installation. Obtain the reviewed local
Node/launcher paths from the operator's registration; do not guess another build.
Preserve `REA_FORGE_STATIC_CONFIG` and `REA_FORGE_DATA_ROOT` from the reviewed
registration for static helper calls. The binding contains no environment
values. A missing provider affects that family only; do not reinstall all tools.

`binary_session` reports distribution `forge-local`, package version, public
command path and catalog digest. Compare them with this build's doctor/catalog.
This identifies the live process, not a guarantee that an engine or target ran.
