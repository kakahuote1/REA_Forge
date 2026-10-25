import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  dotnetInputSchemas,
  type DotnetReport,
  type ForgeDotnetOperation,
} from "../../domain/forge/dotnetAnalysis.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { err, type Result } from "../../domain/result.js";
import type { ForgeStaticAnalysisPort } from "./ForgeStaticAnalysisPort.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";

export const FORGE_DOTNET_PROVIDER = {
  id: "forge-dotnet",
  name: "REA Forge / Dotnet",
  version: "1",
} as const;
export class DotnetAnalysisService {
  constructor(
    readonly adapter: ForgeStaticAnalysisPort<
      ForgeDotnetOperation,
      DotnetReport
    >,
  ) {}
  inspectAvailability(signal?: AbortSignal) {
    return this.adapter.inspectAvailability(signal);
  }
  close(): Promise<void> {
    return this.adapter.close();
  }
  async execute(
    operation: ForgeDotnetOperation,
    raw: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const parsed = dotnetInputSchemas[operation].safeParse(raw);
    if (!parsed.success)
      return err(
        analysisInputErrorFromIssues(operation, parsed.error.issues, raw),
      );
    const parameters = jsonObjectSchema.parse(parsed.data);
    const result = await this.adapter.execute(operation, parameters, options);
    if (!result.ok) return result;
    const target = result.value.target;
    const evidence = createEvidence(
      target === null
        ? undefined
        : { path: target.path, sha256: target.sha256, format: "file" },
      FORGE_DOTNET_PROVIDER,
      {
        operation,
        parameters,
        result: result.value,
        confidence: "observed",
        ...(target === null
          ? { subjectUnavailableReason: "No original input was selected." }
          : {}),
        limitations: [
          "Static worker restrictions are not an operating-system sandbox.",
          "Decompiled source is an engine rendering, not original source or proof of semantic equivalence.",
          "Derived metadata and IL edits do not guarantee valid runtime behavior or retained strong-name signatures.",
        ],
      },
    );
    return completeProviderEvidence(evidence, options?.signal);
  }
}
