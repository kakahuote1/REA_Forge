# Saved packets and API documents

REA's existing `inspect_pcap_client`, `inspect_pcap_capture` and
`inspect_web_network_capture` remain the first choices for capture readiness,
PCAP summaries and HAR/SAZ records. Forge adds the missing offline detail:

| Question                                                  | Operation                     |
| --------------------------------------------------------- | ----------------------------- |
| Protocol fields and packet structure                      | `forge_inspect_packet_tree`   |
| Exact named field columns and display filter              | `forge_extract_packet_fields` |
| Conversations, endpoints, hierarchy or expert summary     | `forge_pcap_statistics`       |
| Directional TCP/UDP payload bytes                         | `forge_follow_packet_stream`  |
| HTTP/IMF/SMB/TFTP objects                                 | `forge_export_packet_objects` |
| OpenAPI 3, Swagger 2, Postman collection/environment JSON | `forge_inspect_api_asset`     |
| Structural endpoint changes and variable fingerprints     | `forge_compare_api_assets`    |
| Filtered normalized summary artifact                      | `forge_export_api_asset`      |
| Retained pages, text or exact artifact bytes              | `forge_read_traffic_result`   |

The CLI uses hyphenated operation names and a single JSON argument. CLI and MCP
share the same application service and Evidence contract. No binary session is
needed. These operations do not start a capture, resolve recorded names,
contact endpoints or launch Apipost.

## Configuration

Use the existing explicit `REA_FORGE_STATIC_CONFIG` and `REA_FORGE_DATA_ROOT`.
Add `pcap`, `api_documents` and `traffic` members to the private config. Each
has `input_roots` with admitted absolute local directories. `pcap` also requires
`version` and `tshark: { path, sha256 }`. The installed TShark is supplied by
the operator; this package does not bundle, download or upgrade it. Configure
REA's native `REA_TSHARK_COMMAND` and `REA_CAPINFOS_COMMAND` separately for
its existing summary provider.

Readiness checks presence/configuration only. Calls verify the selected TShark
file digest. A missing TShark does not disable API documents or retained result
readback. A folder label is not version evidence: the workstation acceptance
uses the executable's observed version rather than its enclosing folder name.

## Coverage and retained data

Packet operations scan up to 2048 source frames by default. Set `packet_limit`
to zero to scan the whole saved file within the same budgets. A numeric limit
applies before the display filter. Tree/field views accept display filters;
statistics, stream and object operations intentionally use their fixed semantics.
Scan coverage does not prove that a capture observed all network traffic.

Inputs are limited to 256 MiB per capture and 8 MiB per API document. TShark's
complete output is bounded to 16 MiB; stderr to 256 KiB. Exported objects are
checked after the engine exits, with a 64 MiB/1000-object retained limit.
These monitored bounds are not an OS disk quota or a parser security sandbox.
Pinned executable identity does not authenticate every installed native plugin
or transitive library. Analysis runs in a generated directory with isolated
user-profile/plugin/extcap paths, without changing the user's Wireshark profile.

Engine deadlines are 1–45,000 ms, default 35,000 ms, inside the existing
55-second owned-helper envelope. REA owns and settles the helper process family;
failed cleanup retains its owner for retry. Internal children are hidden.

Complete bounded JSON/native output and exported payloads stay in a private
workspace. Inline results contain at most 100 rows and explicit preview
omissions. Read later pages or byte windows using the returned receipt and
SHA-256; artifact index zero is full result JSON, following indices select
listed files. Byte windows contain Base64, offsets and remaining coverage.
Receipt readback checks hashes without rerunning analysis. It is historical
evidence, not current source freshness or authenticated provenance.

## Explicit TLS keys

An optional `keylog_path` selects an admitted NSS-format file, at most 1 MiB.
It is copied only to the protected command-temporary owner and removed when
that owner settles. Results report the source digest and record count, not
key material. There is no automatic key collection, CA installation, profile
edit or secret reuse on the next call. An incomplete cleanup is a retained
resource, not a claim that temporary keys were removed.

## API interchange scope

The pure document reader supports the selected tools' documented interchange
forms; it is not an Apipost process/plugin bridge. It preserves duplicate
method/path occurrences, reports structural summaries and represents variable
values by SHA-256. It does not evaluate request scripts or fetch remote `$ref`
URLs. Structural comparison is not complete API compatibility validation.
Exports are Forge summaries, not native Apipost projects. Use REA's web-capture
provider for HAR and SAZ so their body-byte/provenance semantics stay unified.

## Verification

`scripts/forge/verify-offline-traffic.mjs` builds a deterministic offline HTTP
capture and API/HAR/SAZ documents. It uses explicitly selected, already installed
public TLS fixtures and tests real MCP/CLI calls, body hashes, no-key/key/wrong-key
isolation, readback, negative inputs, deadlines, cancellation and cleanup. The
script neither downloads assets nor sends requests or captures live interfaces.
Execution receipts remain private; the current result is indexed in
`docs/forge/verification.md` after the group passes.
