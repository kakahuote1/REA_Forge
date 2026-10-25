# 010 Editor integration

`node scripts/forge/verify-editor010-deadline.mjs` separately exercises actual
35-second native expiry, owned-handle termination and same-connection recovery.
It does not rerun the unrelated functional inventory.

The Forge extension adds ten typed CLI/MCP operations for binary structure,
byte search/comparison and controlled edits. It does not embed the former MCP
server. Each operation uses an owned, non-listening helper; native 010 calls
use `-noui -nowarnings`. Optional discovery starts neither Python nor 010.

## Local configuration

Select configuration and data explicitly as described in
[static-provider configuration](static-configuration.md). The private file
below is an example location, not a production lookup default.

Install a licensed 010 Editor and Python separately. Create the ignored file
`.forge-local/config/tools.json`, using actual absolute paths and executable
SHA-256 rather than the illustrative values below:

```json
{
  "python_executable": "C:/tools/python/python.exe",
  "editor010": {
    "executable": "C:/tools/010Editor/010Editor.exe",
    "executable_sha256": "<64 lowercase hexadecimal characters>",
    "input_roots": ["C:/analysis/inputs"],
    "asset_roots": ["C:/analysis/templates"]
  }
}
```

No commercial binaries, local paths, templates, samples or machine credentials
are distributed by this integration. Configure reviewed templates locally.
ZIP.bt 2.5 and PNG.bt 2.3 have exact reviewed digest entries; arbitrary assets
are not approved just because their names match those templates.

## Operations

| MCP tool                          | Purpose                                                       |
| --------------------------------- | ------------------------------------------------------------- |
| `forge_inspect_binary_structure`  | Native template CSV fields, values, offsets and parse extent  |
| `forge_read_binary_template_rows` | Digest-checked retained CSV paging/filtering                  |
| `forge_read_binary_bytes`         | Bounded hexadecimal/text range                                |
| `forge_search_binary_bytes`       | Exact hexadecimal needle and matching offsets                 |
| `forge_compare_binary_files`      | Native comparison and independently derived byte facts        |
| `forge_edit_binary_copy`          | Derived insert/replace/delete, original unchanged             |
| `forge_run_binary_script`         | Constrained 010 script on a private non-PE copy               |
| `forge_edit_binary_in_place`      | Explicit non-PE original edit with expected digest and backup |
| `forge_restore_binary_backup`     | Provenance-bound restore with a recovery backup               |
| `forge_list_binary_assets`        | Asset identities; listing does not approve execution          |

CLI names replace underscores with hyphens. Each takes one JSON argument using
the same input schema as MCP. Example, from a configured checkout:

```powershell
node scripts/rea.mjs forge-read-binary-bytes '{"path":"C:/analysis/inputs/sample.bin","offset":0,"length":32}' --format json
```

Results use REA's canonical Evidence, including original identity, operation,
parameters and limitations. Retained outputs and backups live under ignored
`.forge-local/work/010editor`; request directories are closed after each call.
Do not delete retained workspaces while downstream edits or backups depend on
them. PE mutation belongs to the separate IDA workflow.

Static asset filtering is not an OS sandbox or a promise to execute arbitrary
third-party scripts safely. The host adapter never executes the analyzed file.
The helper has a 55-second owner deadline; native 010 calls have a 35-second
deadline, with retained cleanup failure reported rather than inferred success.

## Verification

`node scripts/forge/verify-editor010.mjs` runs the complete affected group against
the installed engine with self-created fixtures. It checks all ten advertised
tools, real native templates/scripts, original hashes, edits/restoration,
representative CLI/MCP fact parity, malformed/missing inputs, real cancellation
after native start and observed process/request-directory closure. Machine-local
receipts are private. Successful acceptance is not hostile-parser isolation or
proof of every platform fault mode.
