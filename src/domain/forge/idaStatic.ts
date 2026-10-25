import { z } from "zod";
import { absoluteLocalPathStringSchema as path } from "../localPath.js";
import { jsonObjectSchema } from "../jsonValue.js";
import { binaryFileIdentitySchema } from "./binaryEditor.js";

export const FORGE_IDA_OPERATIONS = [
  "forge_edit_ida_database",
  "forge_run_ida_safe_python",
  "forge_scan_ida_crypto",
  "forge_ida_enum",
  "forge_ida_struct_typer",
  "forge_snapshot_ida_database",
  "forge_export_ida_data",
  "forge_assemble_ida",
  "forge_compare_ida_snapshots",
  "forge_restore_ida_database",
  "forge_read_ida_result",
] as const;
export type ForgeIdaOperation = (typeof FORGE_IDA_OPERATIONS)[number];
export const idaFamilyFor = {
  forge_edit_ida_database: "ida_host",
  forge_run_ida_safe_python: "ida_host",
  forge_scan_ida_crypto: "ida_host",
  forge_ida_enum: "ida_host",
  forge_ida_struct_typer: "ida_host",
  forge_snapshot_ida_database: "ida_host",
  forge_export_ida_data: "ida_host",
  forge_assemble_ida: "ida_assembly",
  forge_compare_ida_snapshots: "ida_exchange",
  forge_restore_ida_database: "ida_results",
  forge_read_ida_result: "ida_results",
} as const;
export type IdaStaticFamily = (typeof idaFamilyFor)[ForgeIdaOperation];
const digest = z.string().regex(/^[a-f0-9]{64}$/u);
const address = z
  .string()
  .max(256)
  .regex(/^(?:0x[0-9a-fA-F]+|[0-9]+|[A-Za-z_.$?@][A-Za-z0-9_.$?@:<>~-]*)$/u);
const identifier = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/u);
const hex = z
  .string()
  .min(2)
  .max(8192)
  .regex(/^(?:[0-9a-fA-F]{2})+$/u);
const declaration = z
  .string()
  .min(1)
  .max(4096)
  .refine(
    (value) => !value.includes("#") && !value.includes("\0"),
    "preprocessor directives/external includes are not admitted",
  );
const arch = z.enum([
  "x16",
  "x32",
  "x64",
  "x16att",
  "x32att",
  "x64att",
  "x16nasm",
  "x32nasm",
  "x64nasm",
  "arm",
  "armbe",
  "thumb",
  "thumbbe",
  "armv8",
  "armv8be",
  "thumbv8",
  "thumbv8be",
  "arm64",
  "hexagon",
  "mips",
  "mipsbe",
  "mips64",
  "mips64be",
  "ppc32be",
  "ppc64",
  "ppc64be",
  "sparc",
  "sparcbe",
  "sparc64be",
  "systemz",
  "evm",
]);
const origin = z
  .string()
  .regex(/^(?:0x[0-9a-fA-F]{1,16}|[0-9]{1,20})$/u)
  .default("0x0");
const page = {
  facet: z
    .enum([
      "summary",
      "analysis",
      "profile",
      "database",
      "before_database",
      "artifacts",
    ])
    .default("summary"),
  offset: z.int().nonnegative().default(0),
  limit: z.int().min(1).max(100).default(50),
};
const timed = { timeout_ms: z.int().min(1).max(45000).default(45000) };
const source = {
  path,
  expected_sha256: digest.optional(),
  inspect_types: z.array(identifier).max(32).default([]),
  ...page,
  ...timed,
};
const reference = { receipt_path: path, receipt_sha256: digest };
export const idaEditSchema = z.discriminatedUnion("action", [
  z.strictObject({ action: z.literal("rename"), address, name: identifier }),
  z.strictObject({
    action: z.literal("comment"),
    address,
    text: z.string().max(1024),
  }),
  z.strictObject({
    action: z.literal("prototype"),
    address,
    prototype: declaration.pipe(z.string().max(512)),
  }),
  z.strictObject({ action: z.literal("declaration"), declaration }),
  z.strictObject({
    action: z.literal("enum"),
    name: identifier,
    bitfield: z.boolean().default(false),
    members: z
      .array(
        z.strictObject({
          name: identifier,
          value: z.union([
            z.int(),
            z.string().regex(/^-?(?:0x[0-9a-fA-F]{1,16}|[0-9]{1,20})$/u),
          ]),
        }),
      )
      .min(1)
      .max(64),
  }),
  z.strictObject({
    action: z.literal("patch"),
    address,
    expected_before_hex: hex,
    data_hex: hex,
  }),
  z.strictObject({
    action: z.literal("assemble_patch"),
    address,
    architecture: arch,
    assembly: z.string().min(1).max(4096),
    expected_before_hex: hex,
    fill_to_size: z.int().min(0).max(4096).default(0),
  }),
  z.strictObject({
    action: z.literal("undefine"),
    address,
    size: z.int().min(1).max(4096),
  }),
  z.strictObject({ action: z.literal("define_code"), address }),
  z.strictObject({
    action: z.literal("make_data"),
    address,
    width: z.union([z.literal(1), z.literal(2), z.literal(4), z.literal(8)]),
  }),
]);
export const idaStaticInputs = {
  forge_edit_ida_database: z.strictObject({
    ...source,
    edits: z.array(idaEditSchema).min(1).max(32),
  }),
  forge_run_ida_safe_python: z.strictObject({
    ...source,
    code: z.string().min(1).max(12000),
  }),
  forge_scan_ida_crypto: z.strictObject({
    ...source,
    max_results: z.int().min(1).max(1000).default(100),
    max_xrefs: z.int().min(1).max(100).default(20),
    include_decompile_review: z.boolean().default(false),
    max_decompile_reviews: z.int().min(1).max(20).default(5),
  }),
  forge_ida_enum: z.strictObject({
    ...source,
    platform: z.enum(["windows", "linux"]),
    function_names: z
      .array(z.string().min(1).max(256))
      .min(1)
      .max(32)
      .optional(),
    enum_names: z.array(z.string().min(1).max(256)).max(8).default([]),
  }),
  forge_ida_struct_typer: z.strictObject({
    ...source,
    struct_name: identifier,
    member_names: z.array(identifier).max(8).default([]),
  }),
  forge_snapshot_ida_database: z.strictObject({
    ...source,
    max_functions: z.int().min(1).max(512).default(512),
  }),
  forge_export_ida_data: z.strictObject({
    ...source,
    address,
    length: z.int().min(1).max(4096),
    data_kind: z.enum(["u8", "u16", "u32", "u64", "string", "raw_hex"]),
    render: z.enum(["text", "c", "python"]),
    endian: z.enum(["little", "big"]).default("little"),
  }),
  forge_assemble_ida: z.strictObject({
    architecture: arch,
    assembly: z.string().min(1).max(4096),
    address: origin,
    ...page,
    ...timed,
  }),
  forge_compare_ida_snapshots: z.strictObject({
    before: z.strictObject(reference),
    after: z.strictObject(reference),
    ...page,
  }),
  forge_restore_ida_database: z.strictObject({
    ...reference,
    expected_database_sha256: digest,
    ...page,
  }),
  forge_read_ida_result: z.strictObject({
    ...reference,
    ...page,
    artifact_index: z.int().nonnegative().optional(),
    byte_offset: z.int().nonnegative().default(0),
    byte_count: z.int().min(1).max(65536).default(4096),
  }),
} as const;
export const idaStaticReportSchema = z.strictObject({
  operation: z.enum(FORGE_IDA_OPERATIONS),
  target: binaryFileIdentitySchema.omit({ is_pe: true }),
  result: jsonObjectSchema,
  workspace: path,
  sample_execution: z.literal(false),
  network_used: z.literal(false),
});
export type IdaStaticReport = z.infer<typeof idaStaticReportSchema>;
