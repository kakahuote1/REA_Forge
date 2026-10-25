import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  enrichmentInputSchemas,
  enrichmentFamilyFor,
  FORGE_ENRICHMENT_OPERATIONS,
  type EnrichmentReport,
  type ForgeEnrichmentOperation,
  type EnrichmentFamily,
} from "../../domain/forge/nativeEnrichment.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { err, type Result } from "../../domain/result.js";
import type { ForgeStaticAnalysisPort } from "./ForgeStaticAnalysisPort.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";

export const FORGE_ENRICHMENT_PROVIDER = {
  id: "forge-native-enrichment",
  name: "REA Forge / capa, FLOSS and API hashes",
  version: "1",
} as const;
export class NativeEnrichmentService {
  constructor(
    readonly adapters: Readonly<
      Record<
        EnrichmentFamily,
        ForgeStaticAnalysisPort<ForgeEnrichmentOperation, EnrichmentReport>
      >
    >,
  ) {}
  async inspectAvailability(signal?: AbortSignal) {
    const entries = await Promise.all(
      Object.entries(this.adapters).map(
        async ([family, adapter]) =>
          [family, await adapter.inspectAvailability(signal)] as const,
      ),
    );
    const availability = Object.fromEntries(entries);
    return Object.fromEntries(
      FORGE_ENRICHMENT_OPERATIONS.map((name) => [
        name,
        availability[enrichmentFamilyFor[name]]!,
      ]),
    );
  }
  async close(): Promise<void> {
    const outcomes = await Promise.allSettled(
      Object.values(this.adapters).map((adapter) => adapter.close()),
    );
    const failures = outcomes.filter((value) => value.status === "rejected");
    if (failures.length > 0)
      throw new AggregateError(
        failures.map((value) => value.reason),
        "Enrichment owners retain incomplete cleanup",
      );
  }
  async execute(
    operation: ForgeEnrichmentOperation,
    raw: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const parsed = enrichmentInputSchemas[operation].safeParse(raw);
    if (!parsed.success)
      return err(
        analysisInputErrorFromIssues(operation, parsed.error.issues, raw),
      );
    const parameters = jsonObjectSchema.parse(parsed.data);
    const result = await this.adapters[enrichmentFamilyFor[operation]].execute(
      operation,
      parameters,
      options,
    );
    if (!result.ok) return result;
    const target = result.value.target;
    return completeProviderEvidence(
      createEvidence(
        target === null
          ? undefined
          : { path: target.path, sha256: target.sha256, format: "file" },
        FORGE_ENRICHMENT_PROVIDER,
        {
          operation,
          parameters,
          result: result.value,
          confidence: "observed",
          ...(target === null
            ? {
                subjectUnavailableReason:
                  "Hash database query has no selected executable.",
              }
            : {}),
          limitations: [
            "Rule matches, recovered strings and hash collisions are engine observations or candidates, not conclusions about intent or unique algorithm identity.",
            "Static emulation is not execution of the target as an operating-system process; correlate addresses and candidate strings with disassembly.",
            "The retained digest-checked JSON is complete within the engine output bound; inline rows are explicitly paged or truncated. Retained readback does not re-run the engine or establish current original-file state.",
            "Engine pins identify selected files, not every transitive native dependency; this is not an operating-system sandbox.",
          ],
        },
      ),
      options?.signal,
    );
  }
}
