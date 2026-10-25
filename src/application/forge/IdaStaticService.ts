import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { err, type Result } from "../../domain/result.js";
import {
  FORGE_IDA_OPERATIONS,
  idaFamilyFor,
  idaStaticInputs,
  type IdaStaticFamily,
  type IdaStaticReport,
  type ForgeIdaOperation,
} from "../../domain/forge/idaStatic.js";
import type { ForgeStaticAnalysisPort } from "./ForgeStaticAnalysisPort.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
export const FORGE_IDA_PROVIDER = {
  id: "forge-ida-static",
  name: "REA Forge / IDA static workbench",
  version: "1",
} as const;
export class IdaStaticService {
  constructor(
    readonly adapters: Readonly<
      Record<
        IdaStaticFamily,
        ForgeStaticAnalysisPort<ForgeIdaOperation, IdaStaticReport>
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
      FORGE_IDA_OPERATIONS.map((name) => [name, values[idaFamilyFor[name]]!]),
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
        "IDA static workbench retains incomplete cleanup owners",
      );
  }
  async execute(
    operation: ForgeIdaOperation,
    raw: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(operation, { cause: options.signal.reason }),
      );
    const input = idaStaticInputs[operation].safeParse(raw);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(operation, input.error.issues, raw),
      );
    const parameters = jsonObjectSchema.parse(input.data);
    const result = await this.adapters[idaFamilyFor[operation]].execute(
      operation,
      parameters,
      options,
    );
    if (!result.ok) return result;
    const target = result.value.target;
    return completeProviderEvidence(
      createEvidence(
        { path: target.path, sha256: target.sha256, format: "file" },
        FORGE_IDA_PROVIDER,
        {
          operation,
          parameters,
          result: result.value,
          authority: "historical-reference",
          confidence: "derived",
          limitations: [
            "This is a static work-IDB copy, never a borrowed human GUI database. Original inputs are not patched. Before/after databases are retained for independent reopening and exact snapshot recovery.",
            "The host Python endpoint is only the existing bounded JSON/db facade, not raw IDAPython. Raw scripts, target execution, debugging and original third-party plugins remain selected-guest capabilities.",
            "Task-owned IDAUSR shadows unapproved installed plugin stems using official precedence; approved offline components are explicitly pinned. This is an application profile, not an OS/network sandbox or proof of all past module execution.",
            "Crypto/enum/type/difference results retain candidate and coverage limits. Historical file hashes do not establish current input freshness or semantic equivalence. Full results remain digest-bound and readable.",
          ],
        },
      ),
      options?.signal,
    );
  }
}
