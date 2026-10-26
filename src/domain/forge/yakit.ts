import { z } from "zod";
import { absoluteLocalPathStringSchema as path } from "../localPath.js";
import { jsonObjectSchema } from "../jsonValue.js";
import { binaryFileIdentitySchema } from "./binaryEditor.js";

export const FORGE_YAKIT_OPERATIONS = [
  "forge_yakit_request",
  "forge_yakit_flows",
  "forge_read_yakit_result",
] as const;
export type ForgeYakitOperation = (typeof FORGE_YAKIT_OPERATIONS)[number];
export const yakitFamilyFor = {
  forge_yakit_request: "yakit",
  forge_yakit_flows: "yakit",
  forge_read_yakit_result: "yakit_results",
} as const;
export type YakitFamily = (typeof yakitFamilyFor)[ForgeYakitOperation];
const profile = z
  .string()
  .regex(/^[a-zA-Z0-9_-]{1,48}$/u)
  .default("research");
const page = {
  facet: z
    .enum(["summary", "data", "upstream", "artifacts"])
    .default("summary"),
  offset: z.int().nonnegative().default(0),
  limit: z.int().min(1).max(100).default(20),
};
const timed = { timeout_ms: z.int().min(1).max(30000).default(30000) };
const url = z
  .url()
  .max(8192)
  .refine((value) => {
    const parsed = new URL(value);
    return (
      ["http:", "https:"].includes(parsed.protocol) &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.hash === "" &&
      !/[\u0000-\u0020\u007f]/u.test(value)
    );
  }, "explicit HTTP(S) URL without credentials, fragment or whitespace required");
const header = z.strictObject({
  name: z
    .string()
    .regex(/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/u)
    .refine(
      (value) =>
        !["host", "content-length", "transfer-encoding", "connection"].includes(
          value.toLowerCase(),
        ),
      "wire authority/framing headers are owned by the fixed request builder",
    ),
  value: z
    .string()
    .max(8192)
    .refine(
      (value) => !/[\r\n\0]/u.test(value),
      "header line injection is not admitted",
    ),
});
export const yakitInputs = {
  forge_yakit_request: z.strictObject({
    profile,
    url,
    method: z
      .enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
      .default("GET"),
    headers: z.array(header).max(80).default([]),
    body: z.string().max(65536).default(""),
    request_timeout_seconds: z.int().min(1).max(15).default(5),
    ...page,
    ...timed,
  }),
  forge_yakit_flows: z.strictObject({
    profile,
    keyword: z.string().max(512).default(""),
    page: z.int().min(1).max(100000).default(1),
    count: z.int().min(1).max(100).default(20),
    ...page,
    ...timed,
  }),
  forge_read_yakit_result: z.strictObject({
    receipt_path: path,
    receipt_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
    ...page,
    artifact_index: z.int().nonnegative().optional(),
    byte_offset: z.int().nonnegative().default(0),
    byte_count: z.int().min(1).max(65536).default(4096),
  }),
} as const;
export const yakitReportSchema = z.strictObject({
  operation: z.enum(FORGE_YAKIT_OPERATIONS),
  target: binaryFileIdentitySchema.omit({ is_pe: true }),
  result: jsonObjectSchema,
  workspace: path,
  sample_execution: z.literal(false),
  network_used: z.boolean(),
});
export type YakitReport = z.infer<typeof yakitReportSchema>;
