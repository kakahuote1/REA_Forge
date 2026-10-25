import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  trafficInputSchemas,
  trafficFamilyFor,
  FORGE_TRAFFIC_OPERATIONS,
  type TrafficReport,
  type ForgeTrafficOperation,
  type TrafficFamily,
} from "../../domain/forge/offlineTraffic.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { err, type Result } from "../../domain/result.js";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";
import type { ForgeStaticAnalysisPort } from "./ForgeStaticAnalysisPort.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";

export const FORGE_TRAFFIC_PROVIDER = {
  id: "forge-offline-traffic",
  name: "REA Forge / saved packets and API documents",
  version: "1",
} as const;
export class OfflineTrafficService {
  constructor(
    readonly adapters: Readonly<
      Record<
        TrafficFamily,
        ForgeStaticAnalysisPort<ForgeTrafficOperation, TrafficReport>
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
      FORGE_TRAFFIC_OPERATIONS.map((name) => [
        name,
        availability[trafficFamilyFor[name]]!,
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
        "Offline traffic owners retain incomplete cleanup",
      );
  }
  async execute(
    operation: ForgeTrafficOperation,
    raw: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(operation, { cause: options.signal.reason }),
      );
    const parsed = trafficInputSchemas[operation].safeParse(raw);
    if (!parsed.success)
      return err(
        analysisInputErrorFromIssues(operation, parsed.error.issues, raw),
      );
    const parameters = jsonObjectSchema.parse(parsed.data);
    const result = await this.adapters[trafficFamilyFor[operation]].execute(
      operation,
      parameters,
      options,
    );
    if (!result.ok) return result;
    const target = result.value.target;
    return completeProviderEvidence(
      createEvidence(
        { path: target.path, sha256: target.sha256, format: "file" },
        FORGE_TRAFFIC_PROVIDER,
        {
          operation,
          parameters,
          result: result.value,
          confidence: "derived",
          authority: "historical-reference",
          limitations: [
            "Packet inspection defaults to a source-frame prefix; packet_limit zero scans the whole saved file within fixed byte/time/memory budgets. Source scan coverage is not proof of complete network observation. Display filters are supported only for packet trees and fields.",
            "Original full JSON/native output and exported bytes remain digest-bound; inline rows, previews and byte windows state their bounds. Historical readback does not re-run tools or prove current input freshness.",
            "TLS keylogs are explicitly selected inputs: no automatic key collection, returned key material or host trust/profile changes. Failed cleanup may retain the protected temporary owner until release is verified.",
            "API interchange is structural inspection, not complete specification validation or an Apipost GUI/profile/request API. Variable values are represented by SHA-256 only; HAR/SAZ use REA's existing web-capture parser.",
            "Pinned TShark identity is not full transitive-dependency authentication or an operating-system sandbox.",
          ],
        },
      ),
      options?.signal,
    );
  }
}
