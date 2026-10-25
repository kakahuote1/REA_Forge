import { z } from "zod";
import { absoluteLocalPathStringSchema as path } from "../localPath.js";
import { jsonObjectSchema } from "../jsonValue.js";
import { binaryFileIdentitySchema } from "./binaryEditor.js";

export const FORGE_ENRICHMENT_OPERATIONS = [
  "forge_analyze_capabilities",
  "forge_recover_strings",
  "forge_list_api_hash_types",
  "forge_lookup_api_hash",
  "forge_read_enrichment_result",
] as const;
export type ForgeEnrichmentOperation =
  (typeof FORGE_ENRICHMENT_OPERATIONS)[number];
export const enrichmentFamilyFor = {
  forge_analyze_capabilities: "capa",
  forge_recover_strings: "floss",
  forge_list_api_hash_types: "api_hashes",
  forge_lookup_api_hash: "api_hashes",
  forge_read_enrichment_result: "enrichment",
} as const;
export type EnrichmentFamily =
  (typeof enrichmentFamilyFor)[ForgeEnrichmentOperation];
const page = {
  offset: z.int().min(0).max(1_000_000).default(0),
  limit: z.int().min(1).max(100).default(50),
};
const kinds = z
  .array(z.enum(["static", "decoded", "stack", "tight"]))
  .min(1)
  .max(4);
export const enrichmentInputSchemas = {
  forge_analyze_capabilities: z.strictObject({
    path,
    format: z.enum(["pe", "elf", "sc32", "sc64"]).default("pe"),
    timeout_ms: z.int().min(1).max(45000).default(45000),
    ...page,
  }),
  forge_recover_strings: z.strictObject({
    path,
    format: z.enum(["auto", "pe", "sc32", "sc64"]).default("auto"),
    string_kinds: kinds.default(["static", "decoded", "stack", "tight"]),
    minimum_length: z.int().min(4).max(128).default(4),
    timeout_ms: z.int().min(1).max(45000).default(45000),
    ...page,
  }),
  forge_list_api_hash_types: z.strictObject(page),
  forge_lookup_api_hash: z.strictObject({
    hash_value: z.union([
      z.int().min(0).max(0xffff_ffff),
      z.string().regex(/^(?:0x)?[0-9a-fA-F]{1,8}$/u),
    ]),
    hash_type: z.int().min(0).optional(),
    ...page,
  }),
  forge_read_enrichment_result: z.strictObject({
    receipt_path: path,
    receipt_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
    ...page,
  }),
} as const;
export const enrichmentReportSchema = z.strictObject({
  operation: z.enum(FORGE_ENRICHMENT_OPERATIONS),
  target: binaryFileIdentitySchema.omit({ is_pe: true }).nullable(),
  result: jsonObjectSchema,
  engine: jsonObjectSchema,
  workspace: path,
  sample_execution: z.literal(false),
  network_used: z.literal(false),
});
export type EnrichmentReport = z.infer<typeof enrichmentReportSchema>;
