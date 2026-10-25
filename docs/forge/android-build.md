# Android working artifacts

Use REA's native JADX operations for APK declarations, class/method inspection
and static references, `decode_android_resources` for resource queries, and
`inspect_apk_signature` for signature declarations. These readers do not execute
Android code. Their operator-provided engines retain their native setup and
doctor configuration.

Forge adds the following shared CLI/MCP operations:

| Analyst task                                                   | Operation                       |
| -------------------------------------------------------------- | ------------------------------- |
| Decode an APK or copy an existing decoded project              | `forge_prepare_android_project` |
| Apply exact hash-bound text edits and rebuild a fresh project  | `forge_build_android_project`   |
| Disassemble one DEX or an exact APK `classes*.dex` entry       | `forge_disassemble_dex`         |
| Copy, optionally edit, and assemble a Smali tree               | `forge_assemble_dex`            |
| Sign a derived APK using a test identity or configured profile | `forge_sign_apk`                |
| Perform apksigner cryptographic verification                   | `forge_verify_apk`              |
| Page retained file identities or read exact byte/text windows  | `forge_read_android_result`     |

The operator's `REA_FORGE_STATIC_CONFIG` selects `apk_workspace`, `smali`,
`apk_signing`, and `android_results` families. Each selects input roots; engine
families declare a version and hash-pinned `java` plus `apktool`,
`smali`/`baksmali`, or `keytool`/`apksigner` entries. An absent signer does not
disable decoding or DEX analysis. The static helper and data root use the same
explicit configuration as other Forge capabilities.

Results retain a receipt path and SHA-256, project file identities, native
output identities, diffs, and derived artifact identities. Supply both receipt
fields to subsequent operations. Changing a borrowed project externally
invalidates its receipt; explicitly prepare the edited directory to import a
new snapshot. Hash-bound replacements require exactly one occurrence. Original
APKs, borrowed projects and signing keys remain unchanged. Directory digests
cover a sorted manifest of directory names and regular-file identities.

The default `test` signing profile generates a PKCS#12 test key with the public
standard Android test password. Its retained key receipt can be reused to keep
the same certificate. Private keystore bytes are not exposed by result reading.
Production profiles are operator-only configuration: `profiles.<name>` selects
`keystore: {path, sha256}`, `alias`, `password_file`, and optional
`key_password_file`. Password contents never become MCP arguments or evidence.

Archive/project admission is bounded to 30,000 entries and 256 MiB. DEX files
are bounded to 64 MiB; edits to 64 replacements and 1 MiB aggregate request
JSON; exact read windows to 64 KiB. Each native pipeline has a caller-selected
1–45 second deadline inside the owned helper's 55 second budget. Reparse points,
ambiguous Windows paths, encrypted ZIP members, and case-colliding archive
names are rejected. Pinned engines and these bounds are not an OS sandbox.

Successful verification means the selected apksigner validated the retained
APK. It does not establish benignness, bytecode equivalence, universal Android
compatibility, or device installation. Installation belongs to the explicit
guest/device workflow. OEM frameworks and unsupported DEX formats remain
explicit failures. Source reads are decompiler observations rather than
original source code.

Run `scripts/forge/verify-android-build.mjs` against an explicit installed
harmless APK using `REA_FORGE_ANDROID_FIXTURE`. The acceptance script exercises
decode/edit/build/sign/redecode, known-answer Smali round trips, native reader
integration, negative cases, deadlines, cancellation and CLI/MCP parity. It
never installs or executes the APK. A failed run retains checkpoints; select
its receipt with `REA_FORGE_ANDROID_RESUME` to hash-check and reuse completed
steps rather than repeat engine work.
