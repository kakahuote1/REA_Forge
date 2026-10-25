import { z } from "zod";
import { absoluteLocalPathStringSchema as path } from "../localPath.js";
import { jsonObjectSchema } from "../jsonValue.js";
import { binaryFileIdentitySchema } from "./binaryEditor.js";

export const FORGE_HARMONY_OPERATIONS = [
  "forge_inspect_hap",
  "forge_inspect_abc",
  "forge_disassemble_ark",
  "forge_render_abc_method",
  "forge_decompile_hap",
  "forge_sign_hap",
  "forge_verify_hap_signature",
  "forge_read_harmony_result",
] as const;
export type ForgeHarmonyOperation = (typeof FORGE_HARMONY_OPERATIONS)[number];
export const harmonyFamilyFor = {
  forge_inspect_hap: "harmony_packages",
  forge_inspect_abc: "abcde",
  forge_disassemble_ark: "ark_disasm",
  forge_render_abc_method: "abcde",
  forge_decompile_hap: "jadx_hap",
  forge_sign_hap: "hap_signing",
  forge_verify_hap_signature: "hap_verification",
  forge_read_harmony_result: "harmony_results",
} as const;
export type HarmonyStaticFamily =
  (typeof harmonyFamilyFor)[ForgeHarmonyOperation];
const facet = z.enum([
  "summary",
  "package",
  "entries",
  "metadata",
  "abc",
  "resources",
  "header",
  "analysis",
  "verification",
  "engine",
  "artifacts",
]);
const page = {
  facet: facet.default("summary"),
  offset: z.int().nonnegative().default(0),
  limit: z.int().min(1).max(100).default(50),
  query: z.string().max(512).default(""),
};
const timed = { timeout_ms: z.int().min(1).max(45000).default(45000) };
export const harmonyStaticInputs = {
  forge_inspect_hap: z.strictObject({ path, ...page }),
  forge_inspect_abc: z.strictObject({
    path,
    action: z
      .enum(["header", "classes", "methods", "resources"])
      .default("methods"),
    ...timed,
    ...page,
  }),
  forge_disassemble_ark: z.strictObject({ path, ...timed, ...page }),
  forge_render_abc_method: z.strictObject({
    path,
    method_offset: z.int().min(0).max(2147483647),
    render: z.enum(["disassemble", "decompile"]).default("disassemble"),
    ...timed,
    ...page,
  }),
  forge_decompile_hap: z.strictObject({ path, ...timed, ...page }),
  forge_sign_hap: z.strictObject({
    path,
    profile: z
      .string()
      .regex(/^[A-Za-z0-9_.-]{1,64}$/u)
      .default("test"),
    algorithm: z
      .enum([
        "SHA256withECDSA",
        "SHA384withECDSA",
        "SHA512withECDSA",
        "SHA256withRSA/PSS",
        "SHA384withRSA/PSS",
        "SHA512withRSA/PSS",
        "SHA256withRSAANDMGF1",
        "SHA384withRSAANDMGF1",
        "SHA512withRSAANDMGF1",
      ])
      .default("SHA256withRSA/PSS"),
    ...timed,
    ...page,
  }),
  forge_verify_hap_signature: z.strictObject({ path, ...timed, ...page }),
  forge_read_harmony_result: z.strictObject({
    receipt_path: path,
    receipt_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
    ...page,
    artifact_index: z.int().nonnegative().optional(),
    mode: z.enum(["bytes", "lines", "jsonl"]).default("bytes"),
    byte_offset: z.int().nonnegative().default(0),
    byte_count: z.int().min(1).max(65536).default(4096),
    line_offset: z.int().min(0).max(1000000).default(0),
    line_count: z.int().min(1).max(100).default(50),
  }),
} as const;
export const harmonyStaticReportSchema = z.strictObject({
  operation: z.enum(FORGE_HARMONY_OPERATIONS),
  target: binaryFileIdentitySchema.omit({ is_pe: true }),
  result: jsonObjectSchema,
  workspace: path,
  sample_execution: z.literal(false),
  network_used: z.literal(false),
});
export type HarmonyStaticReport = z.infer<typeof harmonyStaticReportSchema>;
