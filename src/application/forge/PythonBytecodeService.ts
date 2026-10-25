import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  FORGE_PYTHON_OPERATIONS,
  pythonBytecodeInputs,
  pythonFamilyFor,
  type ForgePythonOperation,
  type PythonBytecodeFamily,
  type PythonBytecodeReport,
} from "../../domain/forge/pythonBytecode.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { err, type Result } from "../../domain/result.js";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";
import type { ForgeStaticAnalysisPort } from "./ForgeStaticAnalysisPort.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";

export const FORGE_PYTHON_PROVIDER = {
  id: "forge-python-bytecode",
  name: "REA Forge / version-qualified Python bytecode",
  version: "1",
} as const;
export class PythonBytecodeService {
  constructor(
    readonly adapters: Readonly<
      Record<
        PythonBytecodeFamily,
        ForgeStaticAnalysisPort<ForgePythonOperation, PythonBytecodeReport>
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
      FORGE_PYTHON_OPERATIONS.map((name) => [
        name,
        values[pythonFamilyFor[name]]!,
      ]),
    );
  }
  async close(): Promise<void> {
    const results = await Promise.allSettled(
      Object.values(this.adapters).map((adapter) => adapter.close()),
    );
    const failures = results.filter((result) => result.status === "rejected");
    if (failures.length)
      throw new AggregateError(
        failures.map((result) => result.reason),
        "Python analysis retains incomplete cleanup owners",
      );
  }
  async execute(
    operation: ForgePythonOperation,
    raw: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(operation, { cause: options.signal.reason }),
      );
    const input = pythonBytecodeInputs[operation].safeParse(raw);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(operation, input.error.issues, raw),
      );
    const parameters = jsonObjectSchema.parse(input.data);
    const result = await this.adapters[pythonFamilyFor[operation]].execute(
      operation,
      parameters,
      options,
    );
    if (!result.ok) return result;
    const target = result.value.target;
    return completeProviderEvidence(
      createEvidence(
        { path: target.path, sha256: target.sha256, format: "file" },
        FORGE_PYTHON_PROVIDER,
        {
          operation,
          parameters,
          result: result.value,
          confidence: "derived",
          authority: "historical-reference",
          limitations: [
            "xdis version/implementation facts select a decompiler; unsupported versions and parser failures are explicit results, not recovered source or a reason to execute target bytecode.",
            "Legacy source is unverified reconstruction. Model equivalence is the engine's bytecode comparison result, not proof of program semantics or safe execution.",
            "No target import/execute, CLI source fallback, network downloads or runtime bootstrap. Model verification compiles generated text with a fixed matching interpreter but never runs it.",
            "Operator-supplied package/model pins and owned process budgets are not a hostile-parser operating-system sandbox or complete transitive-dependency attestation.",
            "Retained JSON/text is digest-bound; inline text is a declared window. Readback does not establish current source freshness.",
          ],
        },
      ),
      options?.signal,
    );
  }
}
