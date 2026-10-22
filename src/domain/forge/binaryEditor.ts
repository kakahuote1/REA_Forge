import { z } from "zod";
import { absoluteLocalPathStringSchema } from "../localPath.js";
import { jsonObjectSchema } from "../jsonValue.js";

export const FORGE_BINARY_EDITOR_OPERATIONS = [
  "forge_inspect_binary_structure",
  "forge_read_binary_bytes",
  "forge_search_binary_bytes",
  "forge_compare_binary_files",
  "forge_edit_binary_copy",
  "forge_edit_binary_in_place",
  "forge_run_binary_script",
  "forge_list_binary_assets",
  "forge_restore_binary_backup",
  "forge_read_binary_template_rows",
] as const;
export type ForgeBinaryEditorOperation =
  (typeof FORGE_BINARY_EDITOR_OPERATIONS)[number];
export const binaryFileIdentitySchema = z.strictObject({
  path: absoluteLocalPathStringSchema,
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  size_bytes: z.int().nonnegative(),
  is_pe: z.boolean(),
});
export const binaryEditorReportSchema = z.strictObject({
  operation: z.enum(FORGE_BINARY_EDITOR_OPERATIONS),
  target: binaryFileIdentitySchema.nullable(),
  result: jsonObjectSchema,
  workspace: absoluteLocalPathStringSchema,
  sample_execution: z.literal(false),
  network_used: z.literal(false),
});
export type BinaryEditorReport = z.infer<typeof binaryEditorReportSchema>;

const path = absoluteLocalPathStringSchema;
const digest = z.string().regex(/^[a-f0-9]{64}$/u);
const hex = z
  .string()
  .regex(/^(?:[a-fA-F0-9]{2})*$/u)
  .max(2 * 1024 * 1024);
const page = {
  offset: z.int().nonnegative().default(0),
  limit: z.int().min(1).max(512).default(256),
  field_name: z.string().max(128).optional(),
};
const patch = {
  path,
  offset: z.int().nonnegative(),
  delete_length: z.int().nonnegative(),
  insert_hex: hex,
};
export const binaryEditorInputSchemas = {
  forge_inspect_binary_structure: z.strictObject({
    path,
    template_path: path,
    ...page,
  }),
  forge_read_binary_bytes: z.strictObject({
    path,
    offset: z.int().nonnegative(),
    length: z
      .int()
      .min(0)
      .max(1024 * 1024),
  }),
  forge_search_binary_bytes: z.strictObject({
    path,
    needle_hex: hex.min(2).max(8192),
  }),
  forge_compare_binary_files: z.strictObject({ path, right_path: path }),
  forge_edit_binary_copy: z.strictObject({
    ...patch,
    output_name: z.string().min(1).max(255).optional(),
  }),
  forge_edit_binary_in_place: z.strictObject({
    ...patch,
    expected_sha256: digest,
  }),
  forge_run_binary_script: z.strictObject({ path, script_path: path }),
  forge_list_binary_assets: z.strictObject({
    kind: z.enum(["template", "script"]),
  }),
  forge_restore_binary_backup: z.strictObject({
    path,
    backup_path: path,
    expected_sha256: digest,
  }),
  forge_read_binary_template_rows: z.strictObject({
    csv_path: path,
    csv_sha256: digest,
    ...page,
  }),
} as const;
