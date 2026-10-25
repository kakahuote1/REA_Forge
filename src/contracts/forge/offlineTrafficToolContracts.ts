import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import {
  trafficInputSchemas,
  trafficReportSchema,
  type ForgeTrafficOperation,
} from "../../domain/forge/offlineTraffic.js";
const descriptions: Record<ForgeTrafficOperation, string> = {
  forge_inspect_packet_tree:
    "Inspect a bounded prefix of a saved local PCAP/PCAPNG as TShark protocol trees, optionally applying a display filter and an explicit TLS NSS keylog. Retains complete bounded JSON and returns paged previews. Does not capture interfaces, contact recorded endpoints or change Wireshark profiles; key material is not returned.",
  forge_extract_packet_fields:
    "Extract explicitly named TShark fields from a bounded source-frame prefix of a saved capture with an optional display filter and explicit TLS keylog. Retains occurrence=a vendor field strings and raw TSV; does not invent boundaries between repeated field values. No live capture or endpoint requests.",
  forge_pcap_statistics:
    "Compute one fixed offline TShark statistic on a bounded source-frame prefix: TCP/UDP conversations, IP endpoints, protocol hierarchy or expert observations. Returns a bounded text window and retained full text. Statistics accept no display filter because its semantics differ from ordinary packet display.",
  forge_follow_packet_stream:
    "Follow one TCP/UDP stream in a bounded prefix of a saved capture. Preserves TShark raw output, exact directional payload files and hashes; inline hex is only a declared preview. Read exact byte windows with forge_read_traffic_result. No socket connection or target execution.",
  forge_export_packet_objects:
    "Export HTTP/IMF/SMB/TFTP objects from a bounded prefix of a saved capture using pinned TShark and an optional explicit TLS keylog. Copies only verified regular exports into generated private artifact names; records original names, hashes and sizes. No user-directory overwrite, GUI or live capture.",
  forge_inspect_api_asset:
    "Inspect documented Apipost-compatible OpenAPI 3, Swagger 2, Postman v2.1 collections or Postman environment JSON offline. Page/search/filter endpoint or variable summaries; variable values are SHA-256 only. Does not start Apipost, read profiles, evaluate scripts, resolve remote references or send requests. Use inspect_web_network_capture for HAR/SAZ.",
  forge_compare_api_assets:
    "Compare two local API interchange assets by grouped method/path endpoint summaries and variable fingerprints, preserving duplicate endpoint occurrences. Returns structural added/removed/changed records, not a claim of full API compatibility. Does not start Apipost or send requests.",
  forge_export_api_asset:
    "Export a filtered normalized API interchange summary to a new private artifact and return its digest. Keeps both original bytes and variable values unchanged; exported values remain fingerprints. The export is a Forge summary, not an Apipost native project or an automatically imported GUI asset.",
  forge_read_traffic_result:
    "Read a page/text window or exact bytes from a retained digest-checked offline traffic/API result without rerunning TShark. Artifact index 0 is full result JSON; following indices select listed artifacts. Byte windows are Base64 with offsets and coverage. Historical readback does not establish current source freshness.",
};
const fields = ["frame.number", "http.request.method", "http.response.code"];
const packetCoverage =
  " The default scans up to 2048 source frames; packet_limit 0 selects the whole saved file within the same byte, time and memory bounds.";
const examples = {
  forge_inspect_packet_tree: {
    path: "C:/analysis/session.pcapng",
    display_filter: "http",
  },
  forge_extract_packet_fields: { path: "C:/analysis/session.pcapng", fields },
  forge_pcap_statistics: {
    path: "C:/analysis/session.pcapng",
    statistic: "conv,tcp",
  },
  forge_follow_packet_stream: {
    path: "C:/analysis/session.pcapng",
    protocol: "tcp",
    stream_index: 0,
  },
  forge_export_packet_objects: {
    path: "C:/analysis/session.pcapng",
    protocol: "http",
  },
  forge_inspect_api_asset: {
    path: "C:/analysis/openapi.json",
    view: "endpoints",
  },
  forge_compare_api_assets: {
    path: "C:/analysis/old.json",
    right_path: "C:/analysis/new.json",
  },
  forge_export_api_asset: { path: "C:/analysis/openapi.json", method: "GET" },
  forge_read_traffic_result: {
    receipt_path: "C:/work/traffic/receipt.json",
    receipt_sha256: "0".repeat(64),
    artifact_index: 0,
  },
} as const;
const contract = <Name extends ForgeTrafficOperation>(name: Name) =>
  ({
    name,
    ...toolContractMetadata(name),
    kind: "forge-static-provider",
    description:
      descriptions[name] +
      (name.startsWith("forge_inspect_packet_") ||
      name.startsWith("forge_extract_packet_") ||
      name.startsWith("forge_pcap_") ||
      name.startsWith("forge_follow_packet_") ||
      name.startsWith("forge_export_packet_")
        ? packetCoverage
        : ""),
    inputSchema: trafficInputSchemas[name],
    outputSchema: evidenceResultOf(trafficReportSchema),
    examples: [
      {
        title: "Inspect selected offline data or a returned receipt",
        input: examples[name],
      },
    ],
  }) as const satisfies ToolContract;
export const FORGE_TRAFFIC_TOOL_CONTRACTS = [
  contract("forge_inspect_packet_tree"),
  contract("forge_extract_packet_fields"),
  contract("forge_pcap_statistics"),
  contract("forge_follow_packet_stream"),
  contract("forge_export_packet_objects"),
  contract("forge_inspect_api_asset"),
  contract("forge_compare_api_assets"),
  contract("forge_export_api_asset"),
  contract("forge_read_traffic_result"),
] as const;
