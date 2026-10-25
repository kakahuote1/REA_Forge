import { z } from "zod";
import { absoluteLocalPathStringSchema as path } from "../localPath.js";
import { jsonObjectSchema } from "../jsonValue.js";
import { binaryFileIdentitySchema } from "./binaryEditor.js";

export const FORGE_TRAFFIC_OPERATIONS = [
  "forge_inspect_packet_tree",
  "forge_extract_packet_fields",
  "forge_pcap_statistics",
  "forge_follow_packet_stream",
  "forge_export_packet_objects",
  "forge_inspect_api_asset",
  "forge_compare_api_assets",
  "forge_export_api_asset",
  "forge_read_traffic_result",
] as const;
export type ForgeTrafficOperation = (typeof FORGE_TRAFFIC_OPERATIONS)[number];
export const trafficFamilyFor = {
  forge_inspect_packet_tree: "pcap",
  forge_extract_packet_fields: "pcap",
  forge_pcap_statistics: "pcap",
  forge_follow_packet_stream: "pcap",
  forge_export_packet_objects: "pcap",
  forge_inspect_api_asset: "api_documents",
  forge_compare_api_assets: "api_documents",
  forge_export_api_asset: "api_documents",
  forge_read_traffic_result: "traffic",
} as const;
export type TrafficFamily = (typeof trafficFamilyFor)[ForgeTrafficOperation];
const page = {
  offset: z.int().min(0).max(1_000_000).default(0),
  limit: z.int().min(1).max(100).default(50),
};
const packet = {
  path,
  keylog_path: path.optional(),
  packet_limit: z
    .int()
    .min(0)
    .max(1_000_000)
    .default(2048)
    .describe(
      "Source-frame scan limit; zero scans the whole saved file within fixed byte/time/memory budgets",
    ),
  timeout_ms: z.int().min(1).max(45000).default(35000),
  ...page,
};
const filter = z
  .string()
  .max(512)
  .refine((value) => !/[\0\r\n]/u.test(value))
  .default("");
const method = z
  .enum([
    "",
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "TRACE",
  ])
  .default("");
const api = {
  path,
  query: z.string().max(512).default(""),
  method,
  path_contains: z.string().max(512).default(""),
  ...page,
};
export const trafficInputSchemas = {
  forge_inspect_packet_tree: z.strictObject({
    ...packet,
    display_filter: filter,
  }),
  forge_extract_packet_fields: z.strictObject({
    ...packet,
    display_filter: filter,
    fields: z
      .array(z.string().regex(/^[A-Za-z_][A-Za-z0-9_.]{0,127}$/u))
      .min(1)
      .max(64)
      .refine((values) => new Set(values).size === values.length),
  }),
  forge_pcap_statistics: z.strictObject({
    ...packet,
    statistic: z.enum([
      "conv,tcp",
      "conv,udp",
      "endpoints,ip",
      "io,phs",
      "expert",
    ]),
    text_offset: z.int().min(0).default(0),
    text_limit: z.int().min(1).max(65536).default(4096),
  }),
  forge_follow_packet_stream: z.strictObject({
    ...packet,
    protocol: z.enum(["tcp", "udp"]),
    stream_index: z.int().min(0).max(4095),
  }),
  forge_export_packet_objects: z.strictObject({
    ...packet,
    protocol: z.enum(["http", "imf", "smb", "tftp"]),
  }),
  forge_inspect_api_asset: z.strictObject({
    ...api,
    view: z.enum(["endpoints", "variables"]).default("endpoints"),
  }),
  forge_compare_api_assets: z.strictObject({ path, right_path: path, ...page }),
  forge_export_api_asset: z.strictObject(api),
  forge_read_traffic_result: z.strictObject({
    receipt_path: path,
    receipt_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
    ...page,
    text_offset: z.int().min(0).default(0),
    text_limit: z.int().min(1).max(65536).default(4096),
    artifact_index: z.int().min(0).optional(),
    byte_offset: z.int().min(0).default(0),
    byte_count: z.int().min(1).max(65536).default(4096),
  }),
} as const;
export const trafficReportSchema = z.strictObject({
  operation: z.enum(FORGE_TRAFFIC_OPERATIONS),
  target: binaryFileIdentitySchema.omit({ is_pe: true }),
  result: jsonObjectSchema,
  engine: jsonObjectSchema,
  workspace: path,
  sample_execution: z.literal(false),
  network_used: z.literal(false),
});
export type TrafficReport = z.infer<typeof trafficReportSchema>;
