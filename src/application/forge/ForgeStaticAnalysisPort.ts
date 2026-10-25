import type {
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import type { Result } from "../../domain/result.js";

/** Narrow engine port shared by the existing static workflows. */
export interface ForgeStaticAnalysisPort<Operation extends string, Report> {
  execute(
    operation: Operation,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
  ): Promise<Result<Report, AnalysisError>>;
  inspectAvailability(signal?: AbortSignal): Promise<ProviderAvailability>;
  close(): Promise<void>;
}
