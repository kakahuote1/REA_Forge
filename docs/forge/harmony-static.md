# HarmonyOS static analysis

Forge reuses REA's `inspect_artifact`, `extract_artifact` and
`project_harmony_application_graph` for authenticated package inventory and
application projection. It adds fixed adapters for the installed static code,
resource and signing engines. The former release-gate graph is not a runtime
dependency.

| Question | Operation |
| --- | --- |
| Extract the complete admitted package and inspect metadata/member identities | `forge_inspect_hap` |
| Read Panda headers, classes, methods/fields or a legacy resource index | `forge_inspect_abc` |
| Obtain official Ark SDK assembly and independent method/record counts | `forge_disassemble_ark` |
| Inspect a selected method's operands/references or experimental JS | `forge_render_abc_method` |
| Obtain the separate JADX-HAP reconstruction | `forge_decompile_hap` |
| Produce a signed copy using a local profile | `forge_sign_hap` |
| Verify actual signature/profile consistency and retain public evidence | `forge_verify_hap_signature` |
| Page retained metadata, JSONL, text or exact artifact bytes | `forge_read_harmony_result` |

The original inputs remain unchanged. New outputs, logs and full metadata live
under the operator-selected data root. Results include a receipt path and
digest; retain both between calls. Artifact index0 is full metadata,1+ are the
listed outputs. Large artifact lists are previewed, with the complete list
available through the `artifacts` facet. Private signing material is not an
artifact-read target.

## Engines and configuration

The existing explicit `REA_FORGE_STATIC_CONFIG` selects separate
`harmony_packages`, `abcde`, `ark_disasm`, `jadx_hap`, `hap_signing`,
`hap_verification` and `harmony_results` members. Each has absolute
`input_roots` and a version/provenance label. Java families use pinned `java`
and `jar` objects; abcde also pins its reviewed `AbcdeReader.class`. Ark pins
the installed SDK executable. The signing family pins OpenSSL for its local
test-identity generator. No runtime, SDK or model is automatically downloaded.

The abcde/JADX-HAP binary build commits are unknown; source inspection does not
establish those JARs' build provenance. Pins authenticate selected files, not
every transitive dependency. The custom reader source is packaged for review;
the existing independently pinned class is reused.

For production signing, `hap_signing.profiles.<name>` contains pinned
`keystore`, `certificate` and `provisioning_profile` objects, an `alias`, and
operator-selected `password_file`/optional `key_password_file`. Password values
are not tool arguments or Evidence. This vendor accepts transient password
values in child argv, unlike apksigner's file-selector support. Explicit values
are removed from retained sign diagnostics, including native failure paths.
Default `profile=test` creates a self-signed, non-deployment test identity; it
does not grant platform provisioning rights or install a CA.

## Authority, bounds and interpretation

All calls are static. No ABC/HAP, reconstructed JS, arbitrary Java class, GUI or
target VM is executed. Native commands have a shared1–45-second selected
pipeline deadline inside the existing55-second owned helper; Java uses512MiB,
two processors, headless mode and private temporary/home directories. These
application checks are not an OS sandbox against a malicious engine/parser.

ZIP inspection admits at most10,000 entries,64MiB per member and256MiB total
expanded data. It rejects path traversal, case collisions, encrypted members,
symlinks and Windows-ambiguous names before extraction. ABC input is at most
64MiB; raw assembly/artifacts256MiB, full metadata/receipts16MiB. Inline
facets/pages are bounded, with exact retained byte access available.

Panda header parsing does not prove checksum validity or engine compatibility.
RestoolV2 is unsupported by the pinned abcde resource reader. Encoded method and
string references include definitions/literals and are not a resolved dynamic
call graph. Experimental JS rejects unsupported instructions/try-catch and is
not verified equivalent source. JADX-HAP must receive real extracted ABC and
produce source artifacts; resource-only output does not pass as decompilation.
Signature verification reports offline vendor consistency, not trusted issuer,
revocation, deployment authorization or benignness.

Optional assembly/Linux Ark decompilers, ReArk and Hyle retain their separately
recorded prerequisites. They are not silently claimed by these operations.
Current acceptance belongs in the private execution ledger and receipts;
compilation or engine presence alone does not establish real group readiness.
