import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  binaryEditorInputSchemas,
  type BinaryEditorReport,
  type ForgeBinaryEditorOperation,
} from "../../domain/forge/binaryEditor.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { ForgeStaticAnalysisPort } from "./ForgeStaticAnalysisPort.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";

export const FORGE_BINARY_EDITOR_PROVIDER = {
  id: "forge-010editor",
  name: "REA Forge / 010 Editor",
  version: "1",
} as const;

/** Strict public arguments and canonical Evidence, shared by CLI and MCP. */
export class BinaryEditorService {
  constructor(
    readonly adapter: ForgeStaticAnalysisPort<
      ForgeBinaryEditorOperation,
      BinaryEditorReport
    >,
  ) {}
  inspectAvailability(signal?: AbortSignal) {
    return this.adapter.inspectAvailability(signal);
  }
  close(): Promise<void> {
    return this.adapter.close();
  }

  async execute(
    operation: ForgeBinaryEditorOperation,
    raw: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const parsed = binaryEditorInputSchemas[operation].safeParse(raw);
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
        : {
            path: target.path,
            sha256: target.sha256,
            format: target.is_pe ? "pe" : "file",
          },
      FORGE_BINARY_EDITOR_PROVIDER,
      {
        operation,
        parameters,
        result: result.value,
        confidence: "observed",
        ...(target === null
          ? {
              subjectUnavailableReason:
                "This operation identifies an asset collection or retained CSV, not a selected original binary.",
            }
          : {}),
        limitations: [
          "Static helper isolation is not an operating-system sandbox.",
          "Native template parse extent is not proof of semantic correctness.",
          "Reviewed 010 assets are required; arbitrary external APIs are not admitted.",
        ],
      },
    );
    const completed = completeProviderEvidence(evidence, options?.signal);
    return completed.ok ? ok(completed.value) : completed;
  }
}
