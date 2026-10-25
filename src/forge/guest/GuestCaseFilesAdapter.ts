import { createHash } from "node:crypto";
import { z } from "zod";
import type { GuestCaseBinding } from "../../application/forge/GuestRuntimeBinding.js";
import type {
  GuestCaseFilesPort,
  GuestStagedFile,
} from "../../application/forge/GuestCaseFilesPort.js";
import type { GuestBridgeClient } from "./GuestBridgeClient.js";
import {
  allocateCaseProgram,
  casePath,
  CHUNK_BYTES,
  chunkPath,
  clearReadProgram,
  finishTransferProgram,
  MAX_TRANSFER_BYTES,
  newTransfer,
  prepareReadProgram,
  prepareTransferProgram,
  releaseCaseProgram,
} from "./guestCasePrograms.js";

type ExistingTransport = Pick<
  GuestBridgeClient,
  "writeSmallFile" | "readSmallFile" | "runCaseProgram"
>;
/** Borrows the existing bridge; all generated paths/programs come from case ownership. */
export class GuestCaseFilesAdapter implements GuestCaseFilesPort {
  readonly #owned = new Map<string, GuestCaseBinding>();
  readonly #active = new Set<Promise<unknown>>();
  readonly #turns = new Map<string, Promise<void>>();
  readonly #uncertain = new Set<string>();
  readonly #closing = new Set<string>();
  #closed = false;
  constructor(private readonly transport: ExistingTransport) {}

  allocate(binding: GuestCaseBinding, signal?: AbortSignal): Promise<string> {
    return this.#serial(binding, async () => {
      this.#activeOwner(signal);
      if (this.#owned.has(binding.caseId)) throw new Error("Guest case allocation is already owned or pending");
      // Retain a possible late/partial allocation before sending any mutating request.
      this.#owned.set(binding.caseId, binding);
      await this.#program(
        binding,
        allocateCaseProgram(binding),
        z.object({
          caseId: z.literal(binding.caseId),
          allocated: z.literal(true),
          path: z.literal(casePath(binding)),
        }),
        signal,
      );
      return casePath(binding);
    });
  }

  stage(
    binding: GuestCaseBinding,
    bytes: Uint8Array,
    signal?: AbortSignal,
  ): Promise<GuestStagedFile> {
    return this.#serial(binding, async () => {
      this.#require(binding, signal);
      if (bytes.byteLength > MAX_TRANSFER_BYTES)
        throw new Error("Guest staging exceeds16MiB per file");
      const digest = createHash("sha256").update(bytes).digest("hex");
      const file = newTransfer(binding, bytes.byteLength, digest);
      const deadline = AbortSignal.timeout(90000);
      const selected = signal ? AbortSignal.any([signal, deadline]) : deadline;
      await this.#program(
        binding,
        prepareTransferProgram(binding, file),
        transferPrepared(file),
        selected,
      );
      await boundedChunks(
        Math.ceil(bytes.byteLength / CHUNK_BYTES),
        async (index) => {
          this.#require(binding, selected);
          try { await this.transport.writeSmallFile(
            chunkPath(binding, file, index),
            bytes.subarray(index * CHUNK_BYTES, (index + 1) * CHUNK_BYTES),
            undefined,
          ); } catch (cause) { this.#uncertain.add(binding.caseId); throw cause; }
        },
      );
      const completed = await this.#program(
        binding,
        finishTransferProgram(binding, file),
        z.object({
          transferId: z.literal(file.transferId),
          path: z.literal(file.path),
          bytes: z.literal(file.bytes),
          sha256: z.literal(file.sha256),
        }),
        selected,
      );
      // Caller-owned bytes may be mutable: never assert a stable source after transfer without rechecking.
      if (createHash("sha256").update(bytes).digest("hex") !== digest)
        throw new Error("Host staging bytes changed during transfer");
      return completed;
    });
  }

  read(
    binding: GuestCaseBinding,
    file: GuestStagedFile,
    signal?: AbortSignal,
  ): Promise<Uint8Array> {
    return this.#serial(binding, async () => {
      this.#require(binding, signal);
      const deadline = AbortSignal.timeout(90000);
      const selected = signal ? AbortSignal.any([signal, deadline]) : deadline;
      await this.#program(
        binding,
        prepareReadProgram(binding, file),
        transferPrepared(file),
        selected,
      );
      const chunks: Uint8Array[] = [];
      await boundedChunks(
        Math.ceil(file.bytes / CHUNK_BYTES),
        async (index) => {
          this.#require(binding, selected);
          const path = `${casePath(binding)}\\${file.transferId}.read\\${index.toString().padStart(6, "0")}.part`;
          const expected = Math.min(
            CHUNK_BYTES,
            file.bytes - index * CHUNK_BYTES,
          );
          const bytes = await this.transport.readSmallFile(
            path,
            expected,
            selected,
          );
          if (bytes.length !== expected)
            throw new Error("Guest readback chunk is incomplete");
          chunks[index] = bytes;
        },
      );
      const result = Buffer.concat(chunks);
      if (
        result.length !== file.bytes ||
        createHash("sha256").update(result).digest("hex") !== file.sha256
      )
        throw new Error("Guest readback digest differs");
      await this.#program(
        binding,
        clearReadProgram(binding, file),
        z.object({
          transferId: z.literal(file.transferId),
          cleared: z.literal(true),
        }),
        selected,
      );
      return result;
    });
  }

  release(binding: GuestCaseBinding, signal?: AbortSignal): Promise<void> {
    this.#closing.add(binding.caseId);
    return this.#serial(binding, async () => {
      if (this.#owned.get(binding.caseId) !== binding)
        throw new Error("Guest case does not belong to this file owner");
      if (this.#uncertain.has(binding.caseId)) throw new Error(`Guest operation settlement is unknown; retaining ${casePath(binding)} without automatic deletion`);
      await this.#program(
        binding,
        releaseCaseProgram(binding),
        z.object({
          caseId: z.literal(binding.caseId),
          released: z.literal(true),
        }),
        signal,
      );
      this.#owned.delete(binding.caseId);
    });
  }

  #require(binding: GuestCaseBinding, signal?: AbortSignal): void {
    this.#activeOwner(signal);
    if (this.#owned.get(binding.caseId) !== binding)
      throw new Error("Guest case does not belong to this file owner");
    if (this.#closing.has(binding.caseId) || this.#uncertain.has(binding.caseId)) throw new Error("Guest case is closing or has an unresolved physical operation");
  }
  #activeOwner(signal?: AbortSignal): void {
    signal?.throwIfAborted();
    if (this.#closed) throw new Error("Guest file owner is closed");
  }
  #track<Value>(operation: () => Promise<Value>): Promise<Value> {
    const result = operation();
    this.#active.add(result);
    void result
      .finally(() => this.#active.delete(result))
      .catch(() => undefined);
    return result;
  }
  #serial<Value>(binding: GuestCaseBinding, operation: () => Promise<Value>): Promise<Value> {
    const previous = this.#turns.get(binding.caseId) ?? Promise.resolve();
    const pending = this.#track(async () => { await previous; return operation(); });
    const tail = pending.then(() => undefined, () => undefined);
    this.#turns.set(binding.caseId, tail);
    void tail.then(() => { if (this.#turns.get(binding.caseId) === tail) this.#turns.delete(binding.caseId); });
    return pending;
  }
  async #program<Value>(
    binding: GuestCaseBinding,
    source: string,
    schema: z.ZodType<Value>,
    signal?: AbortSignal,
  ): Promise<Value> {
    signal?.throwIfAborted();
    const result = await this.transport.runCaseProgram(
      { source, cwd: "C:\\CodexBridge", timeoutMs: 15000 },
      undefined,
    ).catch((cause: unknown) => { this.#uncertain.add(binding.caseId); throw cause; });
    if (result.timedOut) this.#uncertain.add(binding.caseId);
    if (result.exitCode !== 0 || result.timedOut || result.stderr !== "")
      throw new Error(
        "Fixed guest file operation did not complete; owned case retained for cleanup",
      );
    try {
      return schema.parse(JSON.parse(result.stdout));
    } catch {
      throw new Error(
        "Fixed guest file operation returned invalid facts; owned case retained for cleanup",
      );
    }
  }
  async close(): Promise<void> {
    this.#closed = true;
    await Promise.allSettled([...this.#active]);
    const failures: unknown[] = [];
    for (const binding of [...this.#owned.values()]) {
      try {
        await this.release(binding, AbortSignal.timeout(25000));
      } catch (cause) {
        failures.push(cause);
      }
    }
    if (failures.length)
      throw new AggregateError(
        failures,
        "Guest case cleanup remains unresolved; exact owners retained",
      );
  }
}
const transferPrepared = (file: GuestStagedFile) =>
  z.object({
    transferId: z.literal(file.transferId),
    prepared: z.literal(true),
  });
/** At most four in-flight existing HTTP requests; settle siblings before returning failure. */
async function boundedChunks(
  count: number,
  operation: (index: number) => Promise<void>,
): Promise<void> {
  let next = 0;
  let failed = false;
  let failure: unknown;
  await Promise.all(
    Array.from({ length: Math.min(4, count) }, async () => {
      while (!failed && next < count) {
        const index = next++;
        try {
          await operation(index);
        } catch (cause) {
          failed = true;
          failure ??= cause;
        }
      }
    }),
  );
  if (failed) throw failure;
}
