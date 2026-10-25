import { randomUUID } from "node:crypto";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
} from "../../domain/analysisErrorCore.js";
import type {
  LdPlayerInstanceObservation,
  LdPlayerObservationPort,
} from "./LdPlayerRuntimePort.js";

export interface LdPlayerCase {
  readonly caseId: string;
  readonly instanceIndex: number;
  readonly physicalGeneration: string;
}

/** An instance case is not a lease to signal a PID or assume an Android boot generation. */
export class LdPlayerCaseBinding {
  readonly #cases = new Map<string, LdPlayerCase>();
  #closed = false;
  constructor(private readonly transport: LdPlayerObservationPort) {}

  async openCase(
    index: number,
    signal?: AbortSignal,
  ): Promise<{
    binding: LdPlayerCase;
    observation: LdPlayerInstanceObservation;
  }> {
    this.#active(signal);
    if (!Number.isSafeInteger(index) || index <= 0)
      throw unavailable(
        "Select one existing nonzero LDPlayer instance; instance0 is not in scope",
      );
    const observation = await this.transport.inspect(index, signal);
    this.#active(signal);
    if (
      observation.index !== index ||
      !/^[a-f0-9]{64}$/u.test(observation.physicalGeneration)
    )
      throw unavailable(
        "Transport did not establish the exact instance's physical identity",
      );
    const binding = Object.freeze({
      caseId: randomUUID(),
      instanceIndex: index,
      physicalGeneration: observation.physicalGeneration,
    });
    this.#cases.set(binding.caseId, binding);
    return { binding, observation };
  }

  async requireCase(
    caseId: string,
    signal?: AbortSignal,
  ): Promise<{
    binding: LdPlayerCase;
    observation: LdPlayerInstanceObservation;
  }> {
    this.#active(signal);
    const binding = this.#cases.get(caseId);
    if (!binding)
      throw unavailable("The LDPlayer case is unknown or closed in this owner");
    const observation = await this.transport.inspect(
      binding.instanceIndex,
      signal,
    );
    this.#active(signal);
    if (this.#cases.get(caseId) !== binding)
      throw unavailable("The LDPlayer case closed during observation");
    if (
      observation.index !== binding.instanceIndex ||
      observation.physicalGeneration !== binding.physicalGeneration
    )
      throw unavailable(
        "LDPlayer instance was replaced; old case authority is invalid",
      );
    return { binding, observation };
  }

  closeCase(caseId: string): void {
    this.#cases.delete(caseId);
  }
  invalidateInstance(index: number): void {
    for (const [key, value] of this.#cases)
      if (value.instanceIndex === index) this.#cases.delete(key);
  }
  async close(): Promise<void> {
    this.#closed = true;
    this.#cases.clear();
    await this.transport.close();
  }
  #active(signal?: AbortSignal): void {
    if (signal?.aborted)
      throw new AnalysisCancelledError("forge_ldplayer_case_binding", {
        cause: signal.reason,
      });
    if (this.#closed) throw unavailable("The LDPlayer case owner is closed");
  }
}
const unavailable = (message: string) =>
  new AnalysisCapabilityUnavailableError(
    "forge-ldplayer",
    "forge_ldplayer_case_binding",
    message,
  );
