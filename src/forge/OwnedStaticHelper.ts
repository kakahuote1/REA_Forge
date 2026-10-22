import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  ArtifactResourceScope,
  ArtifactResourceRetryFailure,
} from "../artifacts/ArtifactResourceScope.js";
import {
  AnalysisCleanupLease,
  AnalysisCleanupLeaseGroup,
} from "../artifacts/AnalysisCleanupLease.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import {
  AnalysisError,
  type AnalysisPartialObservation,
} from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../process/OwnedCommand.js";
import { PrivateRuntimeRoot } from "../process/PrivateRuntimeRoot.js";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const DEADLINE_MS = 55_000;

/** One-shot helper protocol; process and directory ownership stay with REA primitives. */
export class OwnedStaticHelper<
  Operation extends string,
  Report extends AnalysisPartialObservation & { readonly operation: Operation },
> {
  readonly #resources = new ArtifactResourceScope();

  constructor(
    readonly provider: string,
    readonly helper: string,
    readonly reportSchema: z.ZodType<Report>,
  ) {}

  close(): Promise<void> {
    return this.#resources.close();
  }

  async execute(
    operation: Operation,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
  ): Promise<Result<Report, AnalysisError>> {
    try {
      return await this.#resources.run(() =>
        this.#execute(operation, parameters, options),
      );
    } catch (cause) {
      return err(this.#failure(operation, cause));
    }
  }

  async #execute(
    operation: Operation,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
  ): Promise<Result<Report, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(operation, { cause: options.signal.reason }),
      );
    let python: string;
    try {
      const configuration = JSON.parse(
        await readFile(join(ROOT, ".forge-local/config/tools.json"), "utf8"),
      ) as unknown;
      python = z
        .object({ python_executable: z.string().min(1) })
        .parse(configuration).python_executable;
      if (!isAbsolute(python)) throw new Error("Python path must be absolute");
    } catch (cause) {
      return err(
        new AnalysisCapabilityUnavailableError(
          this.provider,
          operation,
          "Configure the operator-owned .forge-local/config/tools.json and absolute Python executable first.",
          { cause },
        ),
      );
    }
    await mkdir(join(ROOT, ".forge-local/tmp"), { recursive: true });
    const runtime = await PrivateRuntimeRoot.create({
      parent: join(ROOT, ".forge-local/tmp"),
      prefix: `${this.provider}-request-`,
    });
    let commandFailure: OwnedCommandFailure | undefined;
    const lease = new AnalysisCleanupLease(async () => {
      if (
        commandFailure !== undefined &&
        (commandFailure.cleanupOwner !== undefined ||
          commandFailure.cleanupFailure !== null)
      ) {
        if (commandFailure.cleanupOwner === undefined)
          throw new ArtifactReaderFailure(
            "unavailable",
            "Command cleanup ownership is unresolved",
            {
              cleanup: {
                reason:
                  commandFailure.cleanupFailure ?? "Unknown process ownership",
                resources: commandFailure.resources,
              },
            },
          );
        const stopped = await commandFailure.cleanupOwner.stop();
        if (stopped.status === "incomplete")
          throw new ArtifactReaderFailure("unavailable", stopped.reason, {
            cleanup: {
              reason: stopped.reason,
              resources: commandFailure.resources,
            },
          });
      }
      await runtime.close();
    }, [runtime.path]);
    const owner = { kind: "lease" as const, resource: runtime.path, lease };
    let outcome: Result<Report, AnalysisError>;
    try {
      const request = join(runtime.path, "request.json");
      await writeFile(
        request,
        JSON.stringify({ operation, arguments: parameters }),
        { flag: "wx" },
      );
      const snapshot = await runOwnedCommand(
        {
          command: python,
          arguments: [
            "-I",
            "-S",
            "-X",
            "utf8",
            join(ROOT, this.helper),
            request,
          ],
          expectedCommand: null,
          runId: randomUUID(),
          cwd: ROOT,
        },
        {
          timeoutMs: DEADLINE_MS,
          diagnosticBytes: 8 * 1024 * 1024,
          acceptNonZeroExit: true,
        },
        { signal: options?.signal },
      );
      if (snapshot.diagnosticTruncated || snapshot.outputIncomplete)
        throw new AnalysisOutputError(
          operation,
          "Static helper output is incomplete; no success is inferred",
        );
      const replySchema = z.discriminatedUnion("ok", [
        z.strictObject({ ok: z.literal(true), value: this.reportSchema }),
        z.strictObject({
          ok: z.literal(false),
          error: z.strictObject({ kind: z.string(), message: z.string() }),
        }),
      ]);
      const decoded = replySchema.safeParse(JSON.parse(snapshot.stdout.text));
      if (!decoded.success)
        throw new AnalysisOutputError(
          operation,
          "Malformed static helper reply",
          { cause: decoded.error },
        );
      if (!decoded.data.ok) {
        const failure = decoded.data.error;
        outcome = err(
          ["ValueError", "EditorAdmissionError", "PolicyViolation"].includes(
            failure.kind,
          )
            ? new AnalysisInputError(operation, {
                userMessage: failure.message,
              })
            : new AnalysisCapabilityUnavailableError(
                this.provider,
                operation,
                failure.message,
              ),
        );
      } else if (
        snapshot.exitCode !== 0 ||
        decoded.data.value.operation !== operation
      ) {
        outcome = err(
          new AnalysisOutputError(
            operation,
            "Static helper result identity or exit outcome mismatched",
          ),
        );
      } else {
        outcome = ok(decoded.data.value);
      }
    } catch (cause) {
      if (cause instanceof OwnedCommandFailure) commandFailure = cause;
      outcome = err(this.#failure(operation, cause));
    }
    const released = await this.#resources.release(owner);
    if (released.kind === "failed") {
      const cleanup = new ProviderCleanupError(
        this.provider,
        [runtime.path],
        { reason: "Owned static command or request directory did not settle" },
        { operation, cause: released.cause },
      );
      if (outcome.ok) cleanup.retainPartialObservation(outcome.value);
      new AnalysisCleanupLeaseGroup(cleanup, [lease]);
      return err(
        outcome.ok
          ? cleanup
          : analysisErrorWithCleanupFailure(outcome.error, cleanup, operation),
      );
    }
    return outcome;
  }

  #failure(operation: string, cause: unknown): AnalysisError {
    if (cause instanceof AnalysisError) return cause;
    if (cause instanceof ArtifactResourceRetryFailure) {
      const cleanup = new ProviderCleanupError(
        this.provider,
        cause.failedOwners.map((owner) => owner.resource),
        { reason: cause.message },
        { operation, cause },
      );
      new AnalysisCleanupLeaseGroup(cleanup, cause.cleanupLeases);
      return cleanup;
    }
    if (cause instanceof OwnedCommandFailure) {
      if (cause.reason === "cancelled")
        return new AnalysisCancelledError(operation, {
          cause: cause.cancellation?.reason ?? cause,
        });
      if (cause.reason === "timeout")
        return new AnalysisTimeoutError(operation, DEADLINE_MS, { cause });
    }
    return new AnalysisOutputError(
      operation,
      cause instanceof Error ? cause.message : String(cause),
      { cause },
    );
  }
}
