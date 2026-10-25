import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { err, type Result } from "../../domain/result.js";
import {
  FORGE_SYSTEM_OPERATIONS,
  systemFamilyFor,
  systemObservationInputs,
  type SystemObservationFamily,
  type SystemObservationReport,
  type ForgeSystemOperation,
} from "../../domain/forge/systemObservation.js";
import type { ForgeStaticAnalysisPort } from "./ForgeStaticAnalysisPort.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
export const FORGE_SYSTEM_PROVIDER = {
  id: "forge-system-observation",
  name: "REA Forge / System observation",
  version: "1",
} as const;
export class SystemObservationService {
  constructor(
    readonly adapters: Readonly<
      Record<
        SystemObservationFamily,
        ForgeStaticAnalysisPort<ForgeSystemOperation, SystemObservationReport>
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
      FORGE_SYSTEM_OPERATIONS.map((name) => [
        name,
        values[systemFamilyFor[name]]!,
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
        "System observation retains incomplete cleanup owners",
      );
  }
  async execute(
    operation: ForgeSystemOperation,
    raw: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(operation, { cause: options.signal.reason }),
      );
    const input = systemObservationInputs[operation].safeParse(raw);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(operation, input.error.issues, raw),
      );
    const parameters = jsonObjectSchema.parse(input.data);
    const result = await this.adapters[systemFamilyFor[operation]].execute(
      operation,
      parameters,
      options,
    );
    if (!result.ok) return result;
    const target = result.value.target;
    return completeProviderEvidence(
      createEvidence(
        { path: target.path, sha256: target.sha256, format: "file" },
        FORGE_SYSTEM_PROVIDER,
        {
          operation,
          parameters,
          result: result.value,
          authority: "historical-reference",
          confidence: "derived",
          limitations: [
            "Read-only live process observations retain exact FILETIME identities and a query-only handle across each call. Unreadable/exited/stale targets fail; queries are not atomic snapshots.",
            "System Informer uses its pinned phlib helper; IP Helper connections are explicitly separate table observations. Drivers means SCM status, not loaded kernel modules. No driver or privilege adjustment is performed.",
            "Hollows Hunter uses the fixed no-dump path. Suspicious objects are candidates; negative scans do not prove benignness or absence of a rootkit. No target code is launched or injected.",
            "Retained hashes authenticate historical bytes, not current process state. Thread/handle/address reuse between observations cannot be excluded. Optional command-line fields may carry caller-selected sensitive data.",
          ],
        },
      ),
      options?.signal,
    );
  }
}
