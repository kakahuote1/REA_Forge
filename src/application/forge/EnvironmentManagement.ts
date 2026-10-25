import { randomUUID } from "node:crypto";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
} from "../../domain/analysisErrorCore.js";
import type { JsonValue } from "../../domain/jsonValue.js";
type JsonObject = Record<string, JsonValue>;

export type EnvironmentManagementOperation =
  | "create_snapshot"
  | "revert_snapshot"
  | "delete_snapshot"
  | "delete_instance"
  | "reset_instance"
  | "restore_instance";
export interface EnvironmentManagementIntent {
  readonly operation: EnvironmentManagementOperation;
  readonly targetId: string;
  readonly objectName: string;
  readonly purpose:
    | "before_risky_change"
    | "before_untrusted_execution"
    | "before_toolchain_change"
    | "recovery_checkpoint"
    | "rollback_recovery"
    | "explicit_cleanup";
  readonly necessity: string;
}
export interface ManagementPreflight {
  readonly targetId: string;
  readonly objectName: string;
  /** Observed physical/runtime/chain generation, not caller-supplied identities. */
  readonly generation: string;
  readonly protected: boolean;
  readonly ready: boolean;
  readonly facts: JsonObject;
}
export interface PreparedEnvironmentManagement {
  readonly proposalId: string;
  readonly intent: EnvironmentManagementIntent;
  readonly preflight: ManagementPreflight;
  readonly expiresAt: number;
  readonly requiresConfirmation: boolean;
}
/** Implementations own OS-level serialization and durable pending/incident journals. */
export interface EnvironmentManagementPort {
  inspect(
    intent: EnvironmentManagementIntent,
    signal?: AbortSignal,
  ): Promise<ManagementPreflight>;
  applyOne(
    intent: EnvironmentManagementIntent,
    preflight: ManagementPreflight,
    signal?: AbortSignal,
  ): Promise<JsonObject>;
  close(): Promise<void>;
}
/** Supplied by a trusted client-input/TTY adapter, never constructed from tool arguments. */
export interface ManagementConfirmationPort {
  confirm(
    proposal: PreparedEnvironmentManagement,
    signal?: AbortSignal,
  ): Promise<{
    readonly action: "accept" | "decline" | "cancel";
    readonly typedTarget?: string;
  }>;
}
const NEEDS_CONFIRMATION = new Set<EnvironmentManagementOperation>([
  "delete_snapshot",
  "delete_instance",
  "reset_instance",
  "restore_instance",
]);
const PURPOSES = new Set([
  "before_risky_change",
  "before_untrusted_execution",
  "before_toolchain_change",
  "recovery_checkpoint",
  "rollback_recovery",
  "explicit_cleanup",
]);
const OPERATIONS = new Set<EnvironmentManagementOperation>([
  "create_snapshot",
  "revert_snapshot",
  ...NEEDS_CONFIRMATION,
]);

/** Shared application boundary for one-shot confirmed, serialized management. */
export class EnvironmentManagement {
  readonly #proposals = new Map<string, PreparedEnvironmentManagement>();
  #turn: Promise<void> = Promise.resolve();
  #closed = false;
  #incident = false;
  constructor(
    private readonly transport: EnvironmentManagementPort,
    private readonly now: () => number = Date.now,
  ) {}

  async prepare(
    intent: EnvironmentManagementIntent,
    signal?: AbortSignal,
  ): Promise<PreparedEnvironmentManagement> {
    this.#active(signal);
    if (
      !OPERATIONS.has(intent.operation) ||
      !PURPOSES.has(intent.purpose) ||
      !intent.targetId ||
      !intent.objectName ||
      intent.necessity.trim().length < 16
    )
      throw unavailable(
        "Management needs one exact target/object, an allowed purpose and a substantive necessity record",
      );
    if (
      (intent.operation === "create_snapshot" ||
        intent.operation === "revert_snapshot") &&
      (intent.purpose === "explicit_cleanup" ||
        /\b(?:routine|convenience|just in case)\b|随便|例行/iu.test(
          intent.necessity,
        ))
    )
      throw unavailable(
        "Snapshot creation/revert cannot be routine; the task must make the necessity substantive",
      );
    for (const [id, proposal] of this.#proposals)
      if (proposal.expiresAt <= this.now()) this.#proposals.delete(id);
    if (this.#proposals.size >= 64)
      throw unavailable(
        "Too many pending management proposals; close or expire existing proposals",
      );
    const preflight = await this.transport.inspect(intent, signal);
    this.#active(signal);
    this.#admit(intent, preflight);
    const proposal = Object.freeze({
      proposalId: randomUUID(),
      intent: Object.freeze(structuredClone(intent)),
      preflight: Object.freeze(structuredClone(preflight)),
      expiresAt: this.now() + 10 * 60 * 1000,
      requiresConfirmation: NEEDS_CONFIRMATION.has(intent.operation),
    });
    this.#proposals.set(proposal.proposalId, proposal);
    return proposal;
  }

  async execute(
    proposalId: string,
    confirmation?: ManagementConfirmationPort,
    signal?: AbortSignal,
  ): Promise<JsonObject> {
    this.#active(signal);
    const proposal = this.#proposals.get(proposalId);
    if (!proposal || proposal.expiresAt <= this.now())
      throw unavailable("Management proposal is unknown, consumed or expired");
    // Consume before awaiting UI or a queue: cancellation/replay never reuses approval.
    this.#proposals.delete(proposalId);
    if (proposal.requiresConfirmation) {
      if (!confirmation)
        throw unavailable(
          "A separate trusted client-input confirmation is required; tool parameters cannot supply it",
        );
      const response = await confirmation.confirm(proposal, signal);
      this.#active(signal);
      if (
        response.action !== "accept" ||
        response.typedTarget !== proposal.preflight.objectName
      )
        throw unavailable(
          "The exact preflighted object was not separately confirmed by the user",
        );
    }
    const previous = this.#turn;
    let release!: () => void;
    this.#turn = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      this.#active(signal);
      if (proposal.expiresAt <= this.now())
        throw unavailable(
          "Management proposal expired while awaiting its turn",
        );
      const current = await this.transport.inspect(proposal.intent, signal);
      this.#active(signal);
      this.#admit(proposal.intent, current);
      if (current.generation !== proposal.preflight.generation)
        throw unavailable(
          "Target or snapshot/disk chain changed after preflight; the old confirmation is invalid",
        );
      try {
        // The port rechecks under its OS lock, journals pending before mutation,
        // performs exactly one command, and verifies the actual postflight.
        return await this.transport.applyOne(proposal.intent, current, signal);
      } catch (cause) {
        this.#incident = true;
        this.#proposals.clear();
        throw cause; // No automatic retry; the durable port journal survives reconnect.
      }
    } finally {
      release();
    }
  }

  discard(proposalId: string): void {
    this.#proposals.delete(proposalId);
  }
  async close(): Promise<void> {
    this.#closed = true;
    this.#proposals.clear();
    await this.#turn;
    await this.transport.close();
  }
  #active(signal?: AbortSignal): void {
    if (signal?.aborted)
      throw new AnalysisCancelledError("forge_environment_management", {
        cause: signal.reason,
      });
    if (this.#closed || this.#incident)
      throw unavailable(
        "Management owner is closed or latched after an unresolved incident",
      );
  }
  #admit(
    intent: EnvironmentManagementIntent,
    observed: ManagementPreflight,
  ): void {
    if (
      !observed.ready ||
      observed.targetId !== intent.targetId ||
      observed.objectName !== intent.objectName ||
      !/^[a-f0-9]{64}$/u.test(observed.generation)
    )
      throw unavailable(
        "Preflight did not establish the exact stable target/object and generation",
      );
    if (
      observed.protected &&
      (intent.operation === "delete_snapshot" ||
        intent.operation === "delete_instance" ||
        intent.operation === "reset_instance" ||
        intent.operation === "restore_instance")
    )
      throw unavailable(
        "The protected baseline or instance is never a destructive candidate",
      );
  }
}
const unavailable = (message: string) =>
  new AnalysisCapabilityUnavailableError(
    "forge-environment-management",
    "forge_environment_management",
    message,
  );
