import { randomUUID } from "node:crypto";
import type {
  GuestRuntimeObservation,
  GuestHealthPort,
} from "./GuestRuntimePort.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
} from "../../domain/analysisErrorCore.js";

export interface GuestRuntimeIdentity {
  readonly guestId: string;
  readonly computerName: string;
  readonly bridgeInstanceId: string;
  readonly bridgeProcessId: number;
  readonly bridgeProcessStartTicks: string;
}
export interface GuestCaseBinding {
  readonly caseId: string;
  readonly runtime: GuestRuntimeIdentity;
}

/** Identity must come from the authenticated transport, never request fields. */
export class GuestRuntimeBinding {
  readonly #cases = new Map<string, GuestCaseBinding>();
  #closed = false;
  constructor(
    readonly guestId: string,
    private readonly transport: GuestHealthPort,
  ) {}

  async inspect(signal?: AbortSignal): Promise<GuestRuntimeIdentity> {
    if (this.#closed) throw unavailable("Runtime binding is closed");
    const observed = await this.transport.inspect(signal);
    if (signal?.aborted)
      throw new AnalysisCancelledError("guest_case_binding", {
        cause: signal.reason,
      });
    if (this.#closed)
      throw unavailable("Runtime binding closed during observation");
    return identity(this.guestId, observed);
  }

  async openCase(signal?: AbortSignal): Promise<GuestCaseBinding> {
    const runtime = await this.inspect(signal);
    const binding = Object.freeze({
      caseId: randomUUID(),
      runtime: Object.freeze(runtime),
    });
    this.#cases.set(binding.caseId, binding);
    return binding;
  }

  async requireCase(
    caseId: string,
    signal?: AbortSignal,
  ): Promise<GuestCaseBinding> {
    const selected = this.#cases.get(caseId);
    if (selected === undefined)
      throw unavailable("The case is unknown or closed in this runtime owner");
    const current = await this.inspect(signal);
    if (this.#cases.get(caseId) !== selected)
      throw unavailable("The case closed during runtime observation");
    if (JSON.stringify(current) !== JSON.stringify(selected.runtime))
      throw unavailable(
        "Guest runtime generation changed; the old case cannot authorize new work",
      );
    return selected;
  }

  closeCase(caseId: string): void {
    this.#cases.delete(caseId);
  }
  async close(): Promise<void> {
    this.#closed = true;
    this.#cases.clear();
    await this.transport.close();
  }
}

const unavailable = (reason: string) =>
  new AnalysisCapabilityUnavailableError(
    "forge-guest",
    "guest_case_binding",
    reason,
  );
const identity = (
  guestId: string,
  health: GuestRuntimeObservation,
): GuestRuntimeIdentity => {
  if (
    health.bridgeInstanceId === undefined ||
    health.bridgeProcessId === undefined ||
    health.bridgeProcessStartTicks === undefined
  )
    throw unavailable(
      "The existing guest bridge does not report its instance and process creation identity; runtime authority remains unavailable",
    );
  return {
    guestId,
    computerName: health.computerName,
    bridgeInstanceId: health.bridgeInstanceId,
    bridgeProcessId: health.bridgeProcessId,
    bridgeProcessStartTicks: health.bridgeProcessStartTicks,
  };
};
