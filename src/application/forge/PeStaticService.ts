import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { err, type Result } from "../../domain/result.js";
import {
  FORGE_PE_OPERATIONS,
  peFamilyFor,
  peStaticInputs,
  type PeStaticFamily,
  type PeStaticReport,
  type ForgePeOperation,
} from "../../domain/forge/peStatic.js";
import type { ForgeStaticAnalysisPort } from "./ForgeStaticAnalysisPort.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
export const FORGE_PE_PROVIDER = {
  id: "forge-pe-static",
  name: "REA Forge / PE static workbench",
  version: "1",
} as const;
export class PeStaticService {
  constructor(
    readonly adapters: Readonly<
      Record<
        PeStaticFamily,
        ForgeStaticAnalysisPort<ForgePeOperation, PeStaticReport>
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
      FORGE_PE_OPERATIONS.map((name) => [name, values[peFamilyFor[name]]!]),
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
        "PE workbench retains incomplete cleanup owners",
      );
  }
  async execute(
    operation: ForgePeOperation,
    raw: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(operation, { cause: options.signal.reason }),
      );
    const input = peStaticInputs[operation].safeParse(raw);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(operation, input.error.issues, raw),
      );
    const parameters = jsonObjectSchema.parse(input.data);
    const result = await this.adapters[peFamilyFor[operation]].execute(
      operation,
      parameters,
      options,
    );
    if (!result.ok) return result;
    const target = result.value.target;
    return completeProviderEvidence(
      createEvidence(
        { path: target.path, sha256: target.sha256, format: "file" },
        FORGE_PE_PROVIDER,
        {
          operation,
          parameters,
          result: result.value,
          authority: "historical-reference",
          confidence: "derived",
          limitations: [
            "PE facts are bounded pefile parser observations. Use native inspect_pe_resources, inspect_pe_certificates and inspect_native_exports for their independent exact-format contracts. No PE, DLL or dependency is loaded or executed.",
            "Dependency edges identify static candidates, not actual Windows loader resolution. APISet, KnownDLL and bounded name-only SxS snapshots describe this host; architecture, activation contexts and search-order runtime choices remain unverified.",
            "Previously examined edges are not proof of directed cycles. Per-table/node/depth/edge and parser bounds constrain coverage. Missing candidates do not establish runtime absence.",
            "UPX -t success is tool verification for this selected file, not a benignness proof. Unpacking creates a new file and does not prove runtime equivalence or unpack other protectors.",
            "DiE rule evaluation, Unipacker emulation and dynamic dumping are not this host static surface; their required execution-domain integrations remain separately tracked. Parser pins do not authenticate every transitive runtime dependency or establish an OS sandbox.",
            "Retained result digests authenticate readback bytes, not current source freshness. Original inputs remain unchanged; source/dependency changes during reads are reported rather than treated as stable observations.",
          ],
        },
      ),
      options?.signal,
    );
  }
}
