import { z } from "zod";
import { absoluteLocalPathStringSchema as path } from "../localPath.js";
import { jsonObjectSchema, jsonValueSchema } from "../jsonValue.js";
import { binaryFileIdentitySchema } from "./binaryEditor.js";
export const CYBERCHEF_RECIPE_OPERATIONS = [
  "From Base64",
  "To Base64",
  "From Hex",
  "To Hex",
  "URL Decode",
  "URL Encode",
  "Encode text",
  "Decode text",
  "Gzip",
  "Gunzip",
  "Zlib Deflate",
  "Zlib Inflate",
  "SHA2",
  "HMAC",
  "CRC Checksum",
  "XOR",
  "AES Encrypt",
  "AES Decrypt",
  "JSON Beautify",
  "JSON Minify",
] as const;
export const FORGE_CYBERCHEF_OPERATIONS = [
  "forge_list_cyberchef_operations",
  "forge_validate_cyberchef_recipe",
  "forge_run_cyberchef_recipe",
  "forge_replay_cyberchef_recipe",
  "forge_suggest_cyberchef_steps",
] as const;
export type ForgeCyberChefOperation =
  (typeof FORGE_CYBERCHEF_OPERATIONS)[number];
export const cyberChefReportSchema = z.strictObject({
  operation: z.enum(FORGE_CYBERCHEF_OPERATIONS),
  target: binaryFileIdentitySchema.omit({ is_pe: true }).nullable(),
  result: jsonObjectSchema,
  engine: jsonObjectSchema,
  workspace: path,
  sample_execution: z.literal(false),
  network_used: z.literal(false),
});
export type CyberChefReport = z.infer<typeof cyberChefReportSchema>;
const recipe = z
  .array(
    z.strictObject({
      op: z.enum(CYBERCHEF_RECIPE_OPERATIONS),
      args: z.array(jsonValueSchema).max(32).optional(),
    }),
  )
  .min(1)
  .max(16);
export const cyberChefInputSchemas = {
  forge_list_cyberchef_operations: z.strictObject({}),
  forge_validate_cyberchef_recipe: z.strictObject({ recipe }),
  forge_run_cyberchef_recipe: z.strictObject({ path, recipe }),
  forge_replay_cyberchef_recipe: z.strictObject({
    path,
    receipt_path: path,
    receipt_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  }),
  forge_suggest_cyberchef_steps: z.strictObject({ path }),
} as const;
