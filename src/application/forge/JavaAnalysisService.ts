import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  javaInputSchemas,
  type ForgeJavaOperation,
} from "../../domain/forge/javaAnalysis.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { err, type Result } from "../../domain/result.js";
import type { JavaAdapter } from "../../forge/java/JavaAdapter.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";

export const FORGE_JAVA_PROVIDER = {
  id: "forge-java",
  name: "REA Forge / Java",
  version: "1",
} as const;
export class JavaAnalysisService {
  constructor(readonly adapter: JavaAdapter) {}
  close(): Promise<void> {
    return this.adapter.close();
  }
  async execute(
    operation: ForgeJavaOperation,
    raw: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const parsed = javaInputSchemas[operation].safeParse(raw);
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
      FORGE_JAVA_PROVIDER,
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
          "Static calls do not resolve all reflection or runtime dispatch.",
        ],
      },
    );
    return completeProviderEvidence(evidence, options?.signal);
  }
}
