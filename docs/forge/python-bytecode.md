# Version-qualified Python bytecode

Use native `inspect_python_pyc` for CPython 3.7–3.13 header/marshal facts without
a Python installation. Native `inspect-artifact` / `extract-artifact` inspect
and materialize supported PyInstaller CArchive/PYZ contents. Derived PYC headers
remain explicitly reconstructed evidence, not original file bytes.

Forge supplements those operations with pinned xdis disassembly, legacy source
reconstruction and already installed offline PyLingual models. The four added
operations share native CLI/MCP/Evidence and need no `open_binary`:

- `forge_disassemble_python`: actual xdis version/implementation facts and
  classic, extended or xasm text.
- `forge_decompile_legacy_python`: uncompyle6 through 3.6; decompyle3 for
  3.7–3.8. An explicit engine is honored or refused, not silently replaced.
- `forge_decompile_modern_python`: qualified CPython 3.9–3.12 model sets.
- `forge_read_python_result`: digest-checked retained text windows.

## Operator assets

The existing explicit private config accepts `xdis`, `python_legacy`,
`pylingual` and `python_results`, each with admitted `input_roots`. xdis/legacy
use a pinned `python` executable and pinned package directories. The directory
pin hashes sorted `.py` relative names, NUL, bytes and newline, matching the
reviewed installed-source identity. Legacy additionally selects `spark_parser`,
`uncompyle6` and `decompyle3`. Readback needs no engine.

PyLingual selects `python`, `root` and a pinned `models_manifest`. That manifest
contains qualified versions, source/model/tokenizer file digests, runtime
versions and fixed verification interpreters. Only the selected version's
local models are loaded. No model download, pyenv/bootstrap or Redis is used.
The default free-memory admission is 3 GiB, an operator resource policy rather
than a measured minimum for every input. Status checks presence only; actual
resource/identity checks happen on calls.

## Execution and interpretation

Inputs are at most 8 MiB. Complete text is at most 1 MiB, retained JSON at most
2 MiB; inline windows at most 65,536 characters. Legacy calls have 1–35,000 ms
engine deadlines in the existing 55-second/1-GiB helper family. Model calls have
1–112,000 ms engine deadlines in a separate 135-second/6-GiB owned family. Set
the model client's timeout above 135 seconds. Cancellation and cleanup use the
existing REA process owner, with failed cleanup retained for retry.

Target PYC modules and reconstructed source are never imported or executed.
The fixed model verifier compiles generated source with the matching trusted
interpreter, then compares bytecode. Its equivalence flag is the engine's
comparison result, not proof of all program semantics. Legacy text remains
unverified reconstruction. Unsupported versions, explicit-engine mismatch and
parser failures stay explicit; they do not justify executing the target.

Trusted analyzer code and model/runtime dependencies are operator-supplied.
Pins, resource budgets and Python socket audit hooks are not an OS parser or
network security sandbox. Global Python, user profiles and tools are not
installed or upgraded by this provider.

## Verification status

The non-model subset has passed current real CLI/MCP verification: installed
known-source legacy PYC, native packaged-file inventory/extraction, all xdis
renderings, version choices, text readback, actual deadlines, cancellation and
cleanup. Current modern-model inference remains unverified because measured
available RAM was below the resource admission. A separate deterministic
resource-refusal check passed without model loading. The G06 group remains
open; current receipts and remaining scope are in the private checklist and
[verification index](verification.md).

Operator-provided engines retain their upstream licenses: python-xdis
(GPL-2.0-or-later), uncompyle6 and decompyle3 (GPL-3.0-or-later), PyLingual
(source-declared GPL-3.0). Their libraries, models and runtimes are not bundled
into this source package.
