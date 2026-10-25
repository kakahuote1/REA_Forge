import { z } from "zod";
import { absoluteLocalPathStringSchema as path } from "../localPath.js";
import { jsonObjectSchema } from "../jsonValue.js";
import { binaryFileIdentitySchema } from "./binaryEditor.js";
export const FORGE_PE_OPERATIONS = [
  "forge_inspect_pe",
  "forge_resolve_pe_dependencies",
  "forge_test_upx",
  "forge_unpack_upx",
  "forge_read_pe_result",
] as const;
export type ForgePeOperation = (typeof FORGE_PE_OPERATIONS)[number];
export const peFamilyFor = {
  forge_inspect_pe: "pe_parser",
  forge_resolve_pe_dependencies: "pe_parser",
  forge_test_upx: "upx",
  forge_unpack_upx: "upx",
  forge_read_pe_result: "pe_results",
} as const;
export type PeStaticFamily = (typeof peFamilyFor)[ForgePeOperation];
const facet = z.enum([
  "summary",
  "headers",
  "sections",
  "imports",
  "delay_imports",
  "bound_imports",
  "exports",
  "resources",
  "security",
  "data_directories",
  "dependencies",
  "engine",
  "upx",
  "artifacts",
]);
const page = {
  facet: facet.default("summary"),
  collection: z
    .enum([
      "nodes",
      "edges",
      "missing",
      "previously_examined_edges",
      "source_manifest_documents",
      "sxs_candidates",
    ])
    .default("nodes"),
  offset: z.int().nonnegative().default(0),
  limit: z.int().min(1).max(100).default(50),
  query: z.string().max(512).default(""),
};
const timed = { timeout_ms: z.int().min(1).max(45000).default(45000) };
export const peStaticInputs = {
  forge_inspect_pe: z.strictObject({ path, ...page }),
  forge_resolve_pe_dependencies: z.strictObject({
    path,
    dependency_roots: z.array(path).max(8).default([]),
    max_depth: z.int().min(0).max(10).default(2),
    max_nodes: z.int().min(1).max(48).default(48),
    ...page,
    facet: facet.default("dependencies"),
  }),
  forge_test_upx: z.strictObject({ path, ...timed }),
  forge_unpack_upx: z.strictObject({ path, ...timed }),
  forge_read_pe_result: z.strictObject({
    receipt_path: path,
    receipt_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
    ...page,
    artifact_index: z.int().nonnegative().optional(),
    byte_offset: z.int().nonnegative().default(0),
    byte_count: z.int().min(1).max(65536).default(4096),
  }),
} as const;
export const peStaticReportSchema = z.strictObject({
  operation: z.enum(FORGE_PE_OPERATIONS),
  target: binaryFileIdentitySchema.omit({ is_pe: true }),
  result: jsonObjectSchema,
  workspace: path,
  sample_execution: z.literal(false),
  network_used: z.literal(false),
});
export type PeStaticReport = z.infer<typeof peStaticReportSchema>;
