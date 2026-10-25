import { z } from "zod";
import { absoluteLocalPathStringSchema as path } from "../localPath.js";
import { jsonObjectSchema } from "../jsonValue.js";

export const FORGE_ANDROID_BUILD_OPERATIONS = [
  "forge_prepare_android_project",
  "forge_build_android_project",
  "forge_disassemble_dex",
  "forge_assemble_dex",
  "forge_sign_apk",
  "forge_verify_apk",
  "forge_read_android_result",
] as const;
export type ForgeAndroidBuildOperation =
  (typeof FORGE_ANDROID_BUILD_OPERATIONS)[number];
export const androidBuildFamilyFor = {
  forge_prepare_android_project: "apk_workspace",
  forge_build_android_project: "apk_workspace",
  forge_disassemble_dex: "smali",
  forge_assemble_dex: "smali",
  forge_sign_apk: "apk_signing",
  forge_verify_apk: "apk_signing",
  forge_read_android_result: "android_results",
} as const;
export type AndroidBuildFamily =
  (typeof androidBuildFamilyFor)[ForgeAndroidBuildOperation];
const digest = z.string().regex(/^[a-f0-9]{64}$/u);
const reference = { receipt_path: path, receipt_sha256: digest };
const native = { timeout_ms: z.int().min(1).max(45000).default(45000) };
const relative = z
  .string()
  .min(1)
  .max(1024)
  .refine(
    (value) =>
      !value.startsWith("/") &&
      !/[\\:\0<>"|?*]/u.test(value) &&
      value
        .split("/")
        .every(
          (part) =>
            part !== "" &&
            part !== "." &&
            part !== ".." &&
            !/[. ]$/u.test(part),
        ),
    "requires one canonical relative project path",
  );
const change = z
  .strictObject({
    relative_path: relative,
    expected_sha256: digest,
    old_text: z.string().min(1).max(65536),
    new_text: z.string().max(65536),
  })
  .refine(
    (value) => value.old_text !== value.new_text,
    "change must modify the text",
  );
const changes = z
  .array(change)
  .max(64)
  .default([])
  .refine(
    (value) => Buffer.byteLength(JSON.stringify(value), "utf8") <= 1024 * 1024,
    "the complete text change set must fit 1 MiB UTF-8 JSON",
  );
export const androidBuildInputs = {
  forge_prepare_android_project: z.strictObject({ path, ...native }),
  forge_build_android_project: z.strictObject({
    ...reference,
    changes,
    ...native,
  }),
  forge_disassemble_dex: z.strictObject({
    path,
    dex_entry: z
      .string()
      .regex(/^classes(?:[2-9]|[1-9][0-9]+)?\.dex$/u)
      .default("classes.dex"),
    ...native,
  }),
  forge_assemble_dex: z.union([
    z.strictObject({
      ...reference,
      changes,
      smali_root: relative.optional(),
      api_level: z.int().min(1).max(35).default(28),
      ...native,
    }),
    z.strictObject({
      source_directory: path,
      changes,
      smali_root: relative.optional(),
      api_level: z.int().min(1).max(35).default(28),
      ...native,
    }),
  ]),
  forge_sign_apk: z
    .strictObject({
      path,
      profile: z
        .string()
        .regex(/^[A-Za-z0-9_.-]{1,64}$/u)
        .default("test"),
      key_receipt_path: path.optional(),
      key_receipt_sha256: digest.optional(),
      ...native,
    })
    .refine(
      (value) =>
        (value.key_receipt_path === undefined) ===
          (value.key_receipt_sha256 === undefined) &&
        (value.profile === "test" || value.key_receipt_path === undefined),
      "supply both owned test-key receipt fields or one configured profile",
    ),
  forge_verify_apk: z.strictObject({ path, ...native }),
  forge_read_android_result: z
    .strictObject({
      ...reference,
      offset: z.int().min(0).default(0),
      limit: z.int().min(1).max(100).default(50),
      query: z.string().max(512).default(""),
      relative_path: relative.optional(),
      artifact_index: z.int().min(0).optional(),
      byte_offset: z.int().min(0).default(0),
      byte_count: z.int().min(1).max(65536).default(4096),
    })
    .refine(
      (value) =>
        value.relative_path === undefined || value.artifact_index === undefined,
      "select a project file or an artifact, not both",
    ),
} as const;
export const androidBuildReportSchema = z.strictObject({
  operation: z.enum(FORGE_ANDROID_BUILD_OPERATIONS),
  target: z.strictObject({
    path,
    sha256: digest,
    size_bytes: z.int().nonnegative(),
    kind: z.enum(["file", "tree"]),
  }),
  result: jsonObjectSchema,
  workspace: path,
  sample_execution: z.literal(false),
  network_used: z.literal(false),
});
export type AndroidBuildReport = z.infer<typeof androidBuildReportSchema>;
