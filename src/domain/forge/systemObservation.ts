import { z } from "zod";
import { absoluteLocalPathStringSchema as path } from "../localPath.js";
import { jsonObjectSchema } from "../jsonValue.js";
import { binaryFileIdentitySchema } from "./binaryEditor.js";
export const FORGE_SYSTEM_OPERATIONS = [
  "forge_inspect_system",
  "forge_observe_process",
  "forge_scan_process",
  "forge_compare_process_snapshots",
  "forge_read_system_result",
] as const;
export type ForgeSystemOperation = (typeof FORGE_SYSTEM_OPERATIONS)[number];
export const systemFamilyFor = {
  forge_inspect_system: "system_informer",
  forge_observe_process: "system_informer",
  forge_scan_process: "hollows_hunter",
  forge_compare_process_snapshots: "system_results",
  forge_read_system_result: "system_results",
} as const;
export type SystemObservationFamily =
  (typeof systemFamilyFor)[ForgeSystemOperation];
const pid = z.int().min(5).max(2147483647);
const creation = z.string().regex(/^[1-9][0-9]{0,19}$/u);
const page = {
  offset: z.int().min(0).max(49152).default(0),
  limit: z.int().min(1).max(100).default(50),
  query: z.string().max(512).default(""),
};
const reference = {
  receipt_path: path,
  receipt_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
};
export const systemObservationInputs = {
  forge_inspect_system: z
    .strictObject({
      kind: z
        .enum(["processes", "services", "drivers", "kernel_modules"])
        .default("processes"),
      pid: pid.optional(),
      timeout_ms: z.int().min(1).max(24000).default(24000),
      ...page,
    })
    .refine(
      (input) => input.pid === undefined || input.kind === "processes",
      "only processes admits an explicit PID in system inventory",
    ),
  forge_observe_process: z.strictObject({
    pid,
    created_100ns: creation,
    kind: z.enum([
      "processes",
      "threads",
      "thread_metadata",
      "modules",
      "handles",
      "regions",
      "details",
      "connections",
    ]),
    timeout_ms: z.int().min(1).max(24000).default(24000),
    ...page,
  }),
  forge_scan_process: z.strictObject({
    pid,
    created_100ns: creation,
    timeout_ms: z.int().min(1).max(45000).default(45000),
    ...page,
  }),
  forge_compare_process_snapshots: z.strictObject({
    before: z.strictObject(reference),
    after: z.strictObject(reference),
    ...page,
  }),
  forge_read_system_result: z.strictObject({ ...reference, ...page }),
} as const;
export const systemObservationReportSchema = z.strictObject({
  operation: z.enum(FORGE_SYSTEM_OPERATIONS),
  target: binaryFileIdentitySchema.omit({ is_pe: true }),
  result: jsonObjectSchema,
  workspace: path,
  sample_execution: z.literal(false),
  network_used: z.literal(false),
});
export type SystemObservationReport = z.infer<
  typeof systemObservationReportSchema
>;
