import { z } from "zod";
import { absoluteLocalPathStringSchema as path } from "../localPath.js";
import { jsonObjectSchema } from "../jsonValue.js";
import { binaryFileIdentitySchema } from "./binaryEditor.js";

export const FORGE_PYTHON_OPERATIONS = [
  "forge_disassemble_python",
  "forge_decompile_legacy_python",
  "forge_decompile_modern_python",
  "forge_read_python_result",
] as const;
export type ForgePythonOperation = (typeof FORGE_PYTHON_OPERATIONS)[number];
export const pythonFamilyFor = {
  forge_disassemble_python: "xdis",
  forge_decompile_legacy_python: "python_legacy",
  forge_decompile_modern_python: "pylingual",
  forge_read_python_result: "python_results",
} as const;
export type PythonBytecodeFamily =
  (typeof pythonFamilyFor)[ForgePythonOperation];
const window = {
  text_offset: z.int().min(0).default(0),
  text_limit: z.int().min(1).max(65536).default(4096),
};
const deadline = { timeout_ms: z.int().min(1).max(35000).default(35000) };
export const pythonBytecodeInputs = {
  forge_disassemble_python: z.strictObject({
    path,
    format: z.enum(["classic", "extended", "xasm"]).default("classic"),
    ...deadline,
    ...window,
  }),
  forge_decompile_legacy_python: z.strictObject({
    path,
    engine: z.enum(["auto", "uncompyle6", "decompyle3"]).default("auto"),
    ...deadline,
    ...window,
  }),
  forge_decompile_modern_python: z.strictObject({
    path,
    timeout_ms: z.int().min(1).max(112000).default(112000),
    ...window,
  }),
  forge_read_python_result: z.strictObject({
    receipt_path: path,
    receipt_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
    ...window,
  }),
} as const;
export const pythonBytecodeReportSchema = z.strictObject({
  operation: z.enum(FORGE_PYTHON_OPERATIONS),
  target: binaryFileIdentitySchema.omit({ is_pe: true }),
  result: jsonObjectSchema,
  workspace: path,
  sample_execution: z.literal(false),
  network_used: z.literal(false),
});
export type PythonBytecodeReport = z.infer<typeof pythonBytecodeReportSchema>;
