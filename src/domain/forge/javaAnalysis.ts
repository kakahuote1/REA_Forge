import { z } from "zod";
import { absoluteLocalPathStringSchema as path } from "../localPath.js";
import { jsonObjectSchema } from "../jsonValue.js";
import { binaryFileIdentitySchema } from "./binaryEditor.js";

export const FORGE_JAVA_OPERATIONS = [
  "forge_inspect_java",
  "forge_decompile_java",
  "forge_disassemble_java",
  "forge_search_java",
  "forge_java_call_graph",
  "forge_edit_java",
  "forge_compare_java",
] as const;
export type ForgeJavaOperation = (typeof FORGE_JAVA_OPERATIONS)[number];
export const javaReportSchema = z.strictObject({
  operation: z.enum(FORGE_JAVA_OPERATIONS),
  target: binaryFileIdentitySchema.nullable(),
  result: jsonObjectSchema,
  inputs: z.array(binaryFileIdentitySchema),
  native: z.array(jsonObjectSchema),
  engines: jsonObjectSchema,
  workspace: path,
  sample_execution: z.literal(false),
  network_used: z.literal(false),
});
export type JavaReport = z.infer<typeof javaReportSchema>;
const className = z
  .string()
  .regex(/^[A-Za-z_$][A-Za-z0-9_$]*(?:\/[A-Za-z_$][A-Za-z0-9_$]*)*$/u)
  .max(512);
const member = z
  .string()
  .regex(/^[A-Za-z_$][A-Za-z0-9_$]*$/u)
  .max(256);
const descriptor = z.string().min(1).max(1024);
const selected = { path, class_name: className };
const output = {
  output_name: z
    .string()
    .regex(/^[^/\\:]+\.(?:class|jar|war)$/u)
    .max(240),
};
const release = z.union([
  z.literal(8),
  z.literal(11),
  z.literal(17),
  z.literal(21),
  z.literal(25),
]);
const dependencies = z.array(path).max(4).default([]);
const editSchema = z.discriminatedUnion("action", [
  z.strictObject({
    action: z.literal("rename_class"),
    ...selected,
    ...output,
    new_class_name: className,
  }),
  z.strictObject({
    action: z.literal("rename_method"),
    ...selected,
    ...output,
    method_name: member,
    descriptor,
    new_name: member,
  }),
  z.strictObject({
    action: z.literal("rename_field"),
    ...selected,
    ...output,
    field_name: member,
    descriptor,
    new_name: member,
  }),
  z.strictObject({
    action: z.literal("transform"),
    path,
    ...output,
    transformer: z.enum(["dead_code_remove", "duplicate_annotation_remove"]),
  }),
  z.strictObject({ action: z.literal("export_class"), ...selected, ...output }),
  z.strictObject({
    action: z.literal("compile_java"),
    source_path: path,
    class_name: className,
    release,
    ...output,
  }),
  z.strictObject({
    action: z.literal("compile_java_set"),
    source_paths: z.array(path).min(2).max(8),
    dependency_paths: dependencies,
    class_name: className,
    release,
    ...output,
  }),
  z.strictObject({
    action: z.literal("assemble"),
    ...selected,
    ...output,
    assembly_path: path,
  }),
]);
export const javaInputSchemas = {
  forge_inspect_java: z.strictObject({ path }),
  forge_decompile_java: z.strictObject({
    ...selected,
    engine: z.enum([
      "vineflower",
      "cfr",
      "bcv_procyon",
      "bcv_jd_core",
      "recaf_cfr",
      "recaf_vineflower",
    ]),
    dependency_paths: dependencies,
  }),
  forge_disassemble_java: z.strictObject({
    ...selected,
    engine: z.enum(["javap", "recaf_asm", "bcv_asm_textifier", "bcv_asmifier"]),
  }),
  forge_search_java: z.strictObject({
    path,
    query: z.string().min(1).max(256),
    kind: z
      .enum([
        "any",
        "class_name",
        "member_name",
        "string_constant",
        "reference",
      ])
      .default("any"),
  }),
  forge_java_call_graph: z.strictObject({
    ...selected,
    method_name: member,
    descriptor,
  }),
  forge_compare_java: z.strictObject({ path, right_path: path }),
  forge_edit_java: editSchema,
} as const;
