import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { err, type Result } from "../../domain/result.js";
import {
  FORGE_ANDROID_BUILD_OPERATIONS,
  androidBuildFamilyFor,
  androidBuildInputs,
  type AndroidBuildFamily,
  type AndroidBuildReport,
  type ForgeAndroidBuildOperation,
} from "../../domain/forge/androidBuild.js";
import type { ForgeStaticAnalysisPort } from "./ForgeStaticAnalysisPort.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
export const FORGE_ANDROID_BUILD_PROVIDER = {
  id: "forge-android-build",
  name: "REA Forge / Android working artifacts",
  version: "1",
} as const;
export class AndroidBuildService {
  constructor(
    readonly adapters: Readonly<
      Record<
        AndroidBuildFamily,
        ForgeStaticAnalysisPort<ForgeAndroidBuildOperation, AndroidBuildReport>
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
      FORGE_ANDROID_BUILD_OPERATIONS.map((name) => [
        name,
        values[androidBuildFamilyFor[name]]!,
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
        "Android build retains incomplete cleanup owners",
      );
  }
  async execute(
    operation: ForgeAndroidBuildOperation,
    raw: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(operation, { cause: options.signal.reason }),
      );
    const input = androidBuildInputs[operation].safeParse(raw);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(operation, input.error.issues, raw),
      );
    const parameters = jsonObjectSchema.parse(input.data);
    const result = await this.adapters[
      androidBuildFamilyFor[operation]
    ].execute(operation, parameters, options);
    if (!result.ok) return result;
    const target = result.value.target;
    return completeProviderEvidence(
      createEvidence(
        {
          path: target.path,
          sha256: target.sha256,
          format: target.kind === "tree" ? "directory" : "file",
        },
        FORGE_ANDROID_BUILD_PROVIDER,
        {
          operation,
          parameters,
          result: result.value,
          authority: "historical-reference",
          confidence: "derived",
          limitations: [
            "Native JADX remains the code/manifest/reference reader. This provider retains copied apktool/Smali projects and derived APK/DEX artifacts; it does not install or execute Android code.",
            "Original APKs, imported source projects and borrowed keys are not edited. Changes apply to a fresh copied snapshot. External edits invalidate a receipt; explicitly import the edited project to establish a new snapshot.",
            "Directory identities hash sorted relative directories and regular-file identities, not a file byte stream. Project and archive bounds apply before interpretation; unknown/OEM framework dependencies remain explicit failures.",
            "A public-password generated test identity is not a production signing identity. Configured profiles reference operator-owned keystores/password files; passwords are not tool arguments or returned evidence.",
            "Cryptographic verification is reported only from successful apksigner verification; REA's native inspect_apk_signature reports declarations separately. Successful signing does not prove an APK is benign or installable on every Android release.",
            "Pinned engines, path admission and resource budgets are not an OS parser sandbox. Historical readback validates retained identities, not current source freshness or program equivalence.",
          ],
        },
      ),
      options?.signal,
    );
  }
}
