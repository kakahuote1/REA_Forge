import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  cyberChefInputSchemas,
  type ForgeCyberChefOperation,
} from "../../domain/forge/cyberChef.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { err, type Result } from "../../domain/result.js";
import type { CyberChefAdapter } from "../../forge/cyberchef/CyberChefAdapter.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
export const FORGE_CYBERCHEF_PROVIDER = {
  id: "forge-cyberchef",
  name: "REA Forge / CyberChef",
  version: "1",
} as const;
export class CyberChefService {
  constructor(readonly adapter: CyberChefAdapter) {}
  close(): Promise<void> {
    return this.adapter.close();
  }
  async execute(
    operation: ForgeCyberChefOperation,
    raw: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const parsed = cyberChefInputSchemas[operation].safeParse(raw);
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
      FORGE_CYBERCHEF_PROVIDER,
      {
        operation,
        parameters,
        result: result.value,
        confidence: "observed",
        ...(target === null
          ? {
              subjectUnavailableReason:
                "Catalog or validation operation has no selected input file.",
            }
          : {}),
        limitations: [
          "Only twenty reviewed offline CyberChef operations are exposed.",
          "Pinned entry sources and lockfile do not authenticate every installed transitive dependency.",
          "Static helper restrictions are not an operating-system sandbox; candidate labels are not algorithm proof.",
        ],
      },
    );
    return completeProviderEvidence(evidence, options?.signal);
  }
}
