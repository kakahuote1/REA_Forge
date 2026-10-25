import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { err, type Result } from "../../domain/result.js";
import {
  FORGE_HARMONY_OPERATIONS,
  harmonyFamilyFor,
  harmonyStaticInputs,
  type HarmonyStaticFamily,
  type HarmonyStaticReport,
  type ForgeHarmonyOperation,
} from "../../domain/forge/harmonyStatic.js";
import type { ForgeStaticAnalysisPort } from "./ForgeStaticAnalysisPort.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
export const FORGE_HARMONY_PROVIDER = {
  id: "forge-harmony-static",
  name: "REA Forge / Harmony static workbench",
  version: "1",
} as const;
export class HarmonyStaticService {
  constructor(
    readonly adapters: Readonly<
      Record<
        HarmonyStaticFamily,
        ForgeStaticAnalysisPort<ForgeHarmonyOperation, HarmonyStaticReport>
      >
    >,
  ) {}
  async inspectAvailability(signal?: AbortSignal) {
    const values = Object.fromEntries(
      await Promise.all(
        Object.entries(this.adapters).map(
          async ([family, adapter]) =>
            [family, await adapter.inspectAvailability(signal)] as const,
        ),
      ),
    );
    return Object.fromEntries(
      FORGE_HARMONY_OPERATIONS.map((name) => [
        name,
        values[harmonyFamilyFor[name]]!,
      ]),
    );
  }
  async close(): Promise<void> {
    const outcomes = await Promise.allSettled(
      Object.values(this.adapters).map((adapter) => adapter.close()),
    );
    const failures = outcomes.filter(
      (outcome) => outcome.status === "rejected",
    );
    if (failures.length)
      throw new AggregateError(
        failures.map((failure) => failure.reason),
        "Harmony workbench retains incomplete cleanup owners",
      );
  }
  async execute(
    operation: ForgeHarmonyOperation,
    raw: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(operation, { cause: options.signal.reason }),
      );
    const input = harmonyStaticInputs[operation].safeParse(raw);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(operation, input.error.issues, raw),
      );
    const parameters = jsonObjectSchema.parse(input.data);
    const result = await this.adapters[harmonyFamilyFor[operation]].execute(
      operation,
      parameters,
      options,
    );
    if (!result.ok) return result;
    const target = result.value.target;
    return completeProviderEvidence(
      createEvidence(
        { path: target.path, sha256: target.sha256, format: "file" },
        FORGE_HARMONY_PROVIDER,
        {
          operation,
          parameters,
          result: result.value,
          authority: "historical-reference",
          confidence: "derived",
          limitations: [
            "Archive/header facts and fixed static engine outputs have explicit format/resource bounds. No HAP, ABC, reconstructed source or target VM is executed; no GUI is started.",
            "ABC references include encoded definitions and literals, not a proven dynamic call graph. Experimental JS/JADX reconstruction is not original source or verified semantic equivalence; unsupported formats/opcodes fail explicitly.",
            "Signature verification is offline vendor consistency, not issuer trust, revocation, deployability or benignness. Test identities are self-signed non-deployment fixtures; private material is not an artifact-read target.",
            "Retained result digests authenticate historical bytes, not current source freshness. Pins do not authenticate every transitive dependency or establish an OS sandbox. Optional missing Ark engines remain separately reported.",
          ],
        },
      ),
      options?.signal,
    );
  }
}
