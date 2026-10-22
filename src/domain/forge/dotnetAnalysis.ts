import { z } from "zod";
import { absoluteLocalPathStringSchema as path } from "../localPath.js";
import { jsonObjectSchema, type JsonValue } from "../jsonValue.js";
import { binaryFileIdentitySchema } from "./binaryEditor.js";

export const FORGE_DOTNET_OPERATIONS = [
  "forge_inspect_dotnet",
  "forge_decompile_dotnet",
  "forge_read_dotnet_resource",
  "forge_edit_dotnet",
  "forge_compile_dotnet",
] as const;
export type ForgeDotnetOperation = (typeof FORGE_DOTNET_OPERATIONS)[number];
export const dotnetReportSchema = z.strictObject({
  operation: z.enum(FORGE_DOTNET_OPERATIONS),
  target: binaryFileIdentitySchema,
  result: jsonObjectSchema,
  inputs: z.array(binaryFileIdentitySchema),
  native: z.array(jsonObjectSchema),
  engines: jsonObjectSchema,
  workspace: path,
  sample_execution: z.literal(false),
  network_used: z.literal(false),
});
export type DotnetReport = z.infer<typeof dotnetReportSchema>;
const token = z.number().int().min(1).max(0xffffffff);
const identifier = z
  .string()
  .min(1)
  .max(512)
  .regex(/^[^/\\\r\n\0]+$/u);
const text = z
  .string()
  .max(4096)
  .regex(/^[^\r\n\0]*$/u);
const resource = z
  .string()
  .min(1)
  .max(512)
  .regex(/^[^\r\n\0]+$/u);
const base64 = z
  .string()
  .max(5592408)
  .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u);
const primitive = z.enum([
  "void",
  "bool",
  "char",
  "int8",
  "uint8",
  "int16",
  "uint16",
  "int32",
  "uint32",
  "int64",
  "uint64",
  "float32",
  "float64",
  "string",
  "object",
  "nativeint",
  "nativeuint",
]);
const existing = z.strictObject({
  kind: z.literal("existing_type"),
  full_name: z
    .string()
    .min(1)
    .max(1024)
    .regex(/^[^\r\n\0]+$/u),
  is_value_type: z.boolean().default(false),
});
// Finite-depth schemas keep both protocol conversion and signature parsing bounded.
const signature = (depth: number): z.ZodType<JsonValue> =>
  depth === 0
    ? z.union([primitive, existing])
    : z.union([
        primitive,
        existing,
        z.strictObject({
          kind: z.enum(["szarray", "byref", "pointer"]),
          element: signature(depth - 1),
        }),
        z.strictObject({
          kind: z.literal("array"),
          element: signature(depth - 1),
          rank: z.number().int().min(2).max(8),
        }),
        z.strictObject({
          kind: z.literal("generic_instance"),
          generic_type: existing,
          arguments: z
            .array(signature(depth - 1))
            .min(1)
            .max(8),
        }),
      ]);
const type = signature(3);
const selected = { path, type_token: token };
const output = {
  output_name: z
    .string()
    .max(124)
    .regex(/^[A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:exe|dll|netmodule)$/u),
};
const method = { ...selected, method_token: token };
const instruction = z.discriminatedUnion("opcode", [
  z.strictObject({
    opcode: z.enum([
      "nop",
      "endfinally",
      "ret",
      "throw",
      "ldnull",
      "dup",
      "pop",
      "add",
      "sub",
      "mul",
      "div",
      "rem",
      "neg",
      "and",
      "or",
      "xor",
      "not",
      "ceq",
      "cgt",
      "clt",
      "conv.i4",
      "conv.i8",
      "ldarg.0",
      "ldarg.1",
      "ldarg.2",
      "ldarg.3",
    ]),
  }),
  z.strictObject({
    opcode: z.literal("ldc.i4"),
    value: z.number().int().min(-2147483648).max(2147483647),
  }),
  z.strictObject({
    opcode: z.literal("ldc.i8"),
    value: z
      .number()
      .int()
      .min(Number.MIN_SAFE_INTEGER)
      .max(Number.MAX_SAFE_INTEGER),
  }),
  z.strictObject({ opcode: z.literal("ldstr"), value: text }),
  z.strictObject({
    opcode: z.enum(["call", "callvirt", "newobj"]),
    method_token: token,
  }),
  z.strictObject({
    opcode: z.enum(["ldfld", "ldsfld", "stfld", "stsfld"]),
    field_token: token,
  }),
  z.strictObject({
    opcode: z.enum(["box", "unbox.any", "castclass", "isinst", "newarr"]),
    type: existing,
  }),
  z.strictObject({
    opcode: z.enum([
      "br",
      "brtrue",
      "brfalse",
      "beq",
      "bne.un",
      "bgt",
      "bge",
      "blt",
      "ble",
      "leave",
    ]),
    target: z.number().int().min(0).max(511),
  }),
  z.strictObject({
    opcode: z.enum(["ldloc", "stloc", "ldloca"]),
    local_index: z.number().int().min(0).max(63),
  }),
]);
const boundary = z.number().int().min(0).max(511);
const ranges = {
  try_start: boundary,
  try_end: boundary,
  handler_start: boundary,
  handler_end: boundary,
};
const handler = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("catch"), ...ranges, catch_type: existing }),
  z.strictObject({ kind: z.literal("finally"), ...ranges }),
]);
const edit = z.discriminatedUnion("action", [
  z.strictObject({
    action: z.literal("rename_type"),
    ...selected,
    ...output,
    new_name: identifier,
  }),
  z.strictObject({
    action: z.literal("rename_method"),
    ...method,
    ...output,
    new_name: identifier,
  }),
  z.strictObject({
    action: z.literal("rename_field"),
    ...selected,
    ...output,
    field_token: token,
    new_name: identifier,
  }),
  z.strictObject({
    action: z.literal("rename_property"),
    ...selected,
    ...output,
    property_token: token,
    new_name: identifier,
  }),
  z.strictObject({
    action: z.literal("rename_event"),
    ...selected,
    ...output,
    event_token: token,
    new_name: identifier,
  }),
  z.strictObject({
    action: z.literal("set_method_signature"),
    ...method,
    ...output,
    return_type: type,
    parameter_types: z.array(type).max(64),
  }),
  z.strictObject({
    action: z.literal("set_field_type"),
    ...selected,
    ...output,
    field_token: token,
    field_type: type,
  }),
  z.strictObject({
    action: z.literal("set_property_type"),
    ...selected,
    ...output,
    property_token: token,
    property_type: type,
  }),
  z.strictObject({
    action: z.literal("replace_custom_attributes"),
    ...selected,
    ...output,
    target_kind: z.enum(["type", "method", "field", "property", "event"]),
    member_token: token.optional(),
    attributes: z
      .array(
        z.strictObject({
          constructor_token: token,
          arguments: z
            .array(
              z.union([
                text,
                z.boolean(),
                z
                  .number()
                  .int()
                  .min(Number.MIN_SAFE_INTEGER)
                  .max(Number.MAX_SAFE_INTEGER),
              ]),
            )
            .max(8)
            .default([]),
        }),
      )
      .max(16),
  }),
  z.strictObject({
    action: z.literal("replace_embedded_resource"),
    path,
    ...output,
    resource_name: resource,
    content_base64: base64,
  }),
  z.strictObject({
    action: z.literal("set_assembly_identity"),
    path,
    ...output,
    assembly_name: identifier,
    assembly_version: z.string().regex(/^\d{1,5}(?:\.\d{1,5}){3}$/u),
  }),
  z.strictObject({
    action: z.literal("patch_instruction_to_nop"),
    ...method,
    ...output,
    instruction_index: z.number().int().min(0),
  }),
  z.strictObject({
    action: z.literal("replace_method_body"),
    ...method,
    ...output,
    instructions: z.array(instruction).min(1).max(512),
    locals: z.array(type).max(64).default([]),
    exception_handlers: z.array(handler).max(16).default([]),
    max_stack: z.number().int().min(1).max(64).default(8),
  }),
]);
export const dotnetInputSchemas = {
  forge_inspect_dotnet: z.strictObject({
    path,
    view: z
      .enum(["types", "metadata", "resources", "capabilities"])
      .default("types"),
    offset: z.number().int().min(0).default(0),
    limit: z.number().int().min(1).max(64).default(16),
    details: z.boolean().default(true),
  }),
  forge_decompile_dotnet: z.strictObject({
    ...selected,
    language: z.enum(["C#", "Visual Basic", "IL"]).default("C#"),
  }),
  forge_read_dotnet_resource: z.strictObject({ path, resource_name: resource }),
  forge_edit_dotnet: edit,
  forge_compile_dotnet: z.strictObject({
    source_path: path,
    ...output,
    output_kind: z.enum(["library", "console"]).default("library"),
    embedded_resource_name: resource.optional(),
    embedded_resource_content_base64: base64.optional(),
  }),
} as const;
