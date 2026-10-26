import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { err, type Result } from "../../domain/result.js";
import {
  FORGE_YAKIT_OPERATIONS,
  yakitFamilyFor,
  yakitInputs,
  type YakitFamily,
  type YakitReport,
  type ForgeYakitOperation,
} from "../../domain/forge/yakit.js";
import type { ForgeStaticAnalysisPort } from "./ForgeStaticAnalysisPort.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
export const FORGE_YAKIT_PROVIDER = {
  id: "forge-yakit",
  name: "REA Forge / Yakit requests and history",
  version: "1",
} as const;
export class YakitService {
  readonly #profiles = new Map<string, Promise<void>>();
  constructor(
    readonly adapters: Readonly<
      Record<
        YakitFamily,
        ForgeStaticAnalysisPort<ForgeYakitOperation, YakitReport>
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
      FORGE_YAKIT_OPERATIONS.map((name) => [
        name,
        values[yakitFamilyFor[name]]!,
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
        "Yakit adapter retains incomplete cleanup owners",
      );
  }
  async execute(
    operation: ForgeYakitOperation,
    raw: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(operation, { cause: options.signal.reason }),
      );
    const input = yakitInputs[operation].safeParse(raw);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(operation, input.error.issues, raw),
      );
    const parameters = jsonObjectSchema.parse(input.data);
    const invoke = () =>
      this.adapters[yakitFamilyFor[operation]].execute(
        operation,
        parameters,
        options,
      );
    const profile =
      operation === "forge_read_yakit_result"
        ? undefined
        : String(parameters.profile);
    const pending =
      profile === undefined
        ? invoke()
        : (this.#profiles.get(profile) ?? Promise.resolve()).then(invoke);
    if (profile !== undefined) {
      const settled = pending.then(
        () => {},
        () => {},
      );
      this.#profiles.set(profile, settled);
      void settled.then(() => {
        if (this.#profiles.get(profile) === settled)
          this.#profiles.delete(profile);
      });
    }
    const result = await pending;
    if (!result.ok) return result;
    const target = result.value.target;
    return completeProviderEvidence(
      createEvidence(
        { path: target.path, sha256: target.sha256, format: "file" },
        FORGE_YAKIT_PROVIDER,
        {
          operation,
          parameters,
          result: result.value,
          authority:
            operation === "forge_read_yakit_result"
              ? "historical-reference"
              : "external-service",
          confidence: "derived",
          limitations: [
            "The Evidence digest binds a retained request/query descriptor, not a live HTTP service or current database. Each request can affect its explicitly chosen target.",
            "This uses official Yak MCP in a Forge-owned private profile. It does not adopt a human Yakit GUI, change system proxies/trust stores or expose deletion, scripts, plugins, scans or dynamic fuzztags.",
            "Requests are single, bounded and have dynamic tags, system proxy and redirects disabled. Upstream UTF8/Go-quoted strings are retained as reported, not claimed to recover arbitrary original wire bytes.",
            "The installed query tool advertises a script-filter schema by mistake; this adapter uses only common keyword/page/limit fields. Query totals/order/atomicity and unreturned flow bodies remain unknown.",
          ],
        },
      ),
      options?.signal,
    );
  }
}
