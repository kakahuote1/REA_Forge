# Explicit static-provider configuration

Forge's four static families use REA's provider composition and environment
selection. Configure the local REA entrypoint with two absolute paths:

```powershell
$env:REA_FORGE_STATIC_CONFIG = 'D:\Analysis\forge\tools.json'
$env:REA_FORGE_DATA_ROOT = 'D:\Analysis\forge\data'
```

These paths are examples, not installed defaults. Existing operators can select
their current private configuration and data directory; no copy of an engine,
model or SDK is required merely to select them. Package source locations are
separate from configuration and data. Changing the working directory does not
change these selections. Setup preserves explicitly selected values in the
reviewed REA registration without persisting unrelated environment variables.

The selected JSON keeps the existing `python_executable` and `editor010`,
`java`, `dotnet`, `cyberchef` member formats described by each integration.
It is a regular UTF-8 JSON file (an initial BOM is accepted), bounded to 64 KiB.
Missing configuration affects these optional providers, not unrelated REA tools.

Each operation reads a validated configuration snapshot, then supplies a private
copy to its owned helper. Configuration edits during a request do not change
the settings used by that request's helper. The next request reads the selected
file again. Request snapshots are removed through the existing resource owner;
failed cleanup retains its recovery ownership.

`binary_session` reports these target-free operations without requiring
`open_binary`. Readiness checks configuration and required file presence only:
they do not launch Python, start an engine, test a commercial license, or prove
runtime compatibility. Actual operations retain their existing executable/hash
admission and real-engine verification requirements. Missing one family does
not make a configured peer unavailable.

The data directory owns retained work, reviewed assets, entry pins and generated
workers. If relocating it, provision its needed generated assets first:
`build/java/manifest.json`, the dotnet worker/runtime, or CyberChef entry pins,
as appropriate. A path change alone does not relocate these files. Use the
existing build/asset scripts with explicit selected configuration; do not
silently fall back to a checkout's `.forge-local` directory in production.

Human GUI ownership and host/guest execution policy are separate requirements;
file-presence readiness does not authorize arbitrary scripts or target execution.
