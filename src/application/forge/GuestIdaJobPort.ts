import type { GuestCaseBinding } from "./GuestRuntimeBinding.js";
import type { GuestStagedFile } from "./GuestCaseFilesPort.js";
import type { JsonValue } from "../../domain/jsonValue.js";

export interface GuestIdaJob {
  readonly jobId: string;
  readonly caseId: string;
  readonly root: string;
}
export interface GuestIdaJobObservation {
  readonly jobId: string;
  readonly state: "starting" | "running" | "finishing" | "completed" | "failed" | "timed_out" | "stopped";
  readonly cleanupConfirmed: boolean;
  readonly facts: Readonly<Record<string, JsonValue>>;
}
export interface GuestIdaJobPort {
  submit(binding: GuestCaseBinding, input: GuestStagedFile, source: string, timeoutSeconds: number, signal?: AbortSignal): Promise<GuestIdaJob>;
  inspect(binding: GuestCaseBinding, jobId: string, signal?: AbortSignal): Promise<GuestIdaJobObservation>;
  stop(binding: GuestCaseBinding, jobId: string, signal?: AbortSignal): Promise<GuestIdaJobObservation>;
  close(): Promise<void>;
}
