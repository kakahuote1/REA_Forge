import { z } from "zod";
import { binaryFileIdentitySchema } from "./binaryEditor.js";
import { jsonObjectSchema } from "../jsonValue.js";
import { absoluteLocalPathStringSchema } from "../localPath.js";
export const LDPLAYER_OBSERVATION_OPERATIONS = [
  "forge_observe_ldplayer_list",
  "forge_observe_ldplayer_instance",
] as const;
export type LdPlayerObservationOperation =
  (typeof LDPLAYER_OBSERVATION_OPERATIONS)[number];
const processId = z.int().positive().nullable();
const processStart = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .nullable();
export const ldplayerInstanceObservationSchema = z.strictObject({
  index: z.int().min(1).max(9999),
  name: z.string().min(1).max(256),
  physicalGeneration: z.string().regex(/^[a-f0-9]{64}$/u),
  machineUuid: z
    .string()
    .regex(
      /^\{[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}$/u,
    ),
  androidStarted: z.boolean(),
  runtime: z.strictObject({
    playerPid: processId,
    playerStartTicks: processStart,
    vmPid: processId,
    vmStartTicks: processStart,
  }),
  identityEvidence: jsonObjectSchema,
});
export const ldplayerObservationReportSchema = z.strictObject({
  operation: z.enum(LDPLAYER_OBSERVATION_OPERATIONS),
  target: binaryFileIdentitySchema.omit({ is_pe: true }),
  result: z.strictObject({
    instances: z.array(ldplayerInstanceObservationSchema).max(64),
    listEncoding: z.string(),
    timing: jsonObjectSchema,
  }),
  workspace: absoluteLocalPathStringSchema,
  sample_execution: z.literal(false),
  network_used: z.literal(false),
});
export type LdPlayerObservationReport = z.infer<
  typeof ldplayerObservationReportSchema
>;
