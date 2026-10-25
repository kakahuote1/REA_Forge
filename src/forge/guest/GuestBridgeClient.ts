import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
import { z } from "zod";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { readRegularFileText } from "../../application/RegularFileRead.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
} from "../../domain/analysisErrorCore.js";
import type { GuestHealthPort } from "../../application/forge/GuestRuntimePort.js";
import { requestGuestJson } from "./GuestBridgeProtocol.js";
import { GUEST_METADATA_PROBE } from "./guestMetadataProbe.js";

const absolutePath = z.string().min(1).refine(isAbsolute);
export const guestBridgeConfigurationSchema = z.strictObject({
  id: z.string().regex(/^[a-zA-Z0-9_-]+$/u),
  vmx_path: absolutePath,
  base_url: z.string().refine((value) => {
    try {
      const url = new URL(value);
      return (
        url.protocol === "http:" &&
        url.username === "" &&
        url.password === "" &&
        url.pathname === "/" &&
        url.search === "" &&
        url.hash === "" &&
        /^192\.168\.2\.(?:[2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$/u.test(
          url.hostname,
        ) &&
        url.port === "8765"
      );
    } catch {
      return false;
    }
  }, "requires the explicitly selected existing host-only guest bridge"),
  token_file: absolutePath,
  expected_computer_name: z.string().min(1).max(128),
});
export type GuestBridgeConfiguration = z.infer<
  typeof guestBridgeConfigurationSchema
>;

export const guestHealthSchema = z.object({
  ok: z.literal(true),
  version: z.string(),
  computerName: z.string().min(1),
});
const metadataSchema = guestHealthSchema.pick({ computerName: true }).extend({
  bridgeProcessId: z.int().positive(),
  bridgeProcessStartTicks: z.string().regex(/^[1-9][0-9]{0,18}$/u),
});
export type GuestBridgeHealth = z.infer<typeof guestHealthSchema> &
  z.infer<typeof metadataSchema> & { readonly bridgeInstanceId: string };
const runSchema = z.object({
  ok: z.literal(true),
  exitCode: z.literal(0),
  timedOut: z.literal(false),
  stdout: z.string().max(8192),
  stderr: z.literal(""),
});

/** Existing authenticated guest protocol; no discovery, target launch or host changes. */
export class GuestBridgeClient implements GuestHealthPort {
  readonly #configuration: GuestBridgeConfiguration;
  readonly #resources = new ArtifactResourceScope();
  readonly #active = new Set<Promise<unknown>>();
  #closed = false;

  constructor(configuration: GuestBridgeConfiguration) {
    this.#configuration = guestBridgeConfigurationSchema.parse(configuration);
  }

  inspect(signal?: AbortSignal): Promise<GuestBridgeHealth> {
    if (this.#closed)
      return Promise.reject(new Error("Guest bridge client is closed"));
    return this.#track(this.#inspect(signal));
  }

  #track<Value>(operation: Promise<Value>): Promise<Value> {
    this.#active.add(operation);
    void operation
      .finally(() => this.#active.delete(operation))
      .catch(() => undefined);
    return operation;
  }

  async #readToken(signal?: AbortSignal): Promise<string> {
    this.#assertActive(signal);
    const token = (
      await readRegularFileText(this.#configuration.token_file, {
        signal,
        resources: this.#resources,
        symlinks: "reject",
        admit: ({ size }) => {
          if (size < 1 || size > 4096)
            throw new Error("Guest authentication material is unavailable");
        },
        cancellationFailure: (reason) =>
          new AnalysisCancelledError("inspect_guest_runtime", {
            cause: reason,
          }),
      })
    ).trim();
    if (token.length === 0)
      throw new Error("Guest authentication material is unavailable");
    this.#assertActive(signal);
    return token;
  }

  async #inspect(signal?: AbortSignal): Promise<GuestBridgeHealth> {
    const token = await this.#readToken(signal);
    const value = await requestGuestJson(
      new URL("health", this.#configuration.base_url),
      token,
      signal,
    );
    const health = guestHealthSchema.parse(value);
    this.#assertActive(signal);
    if (health.computerName !== this.#configuration.expected_computer_name)
      throw new AnalysisCapabilityUnavailableError(
        "forge-guest",
        "inspect_guest_runtime",
        "Authenticated guest machine identity differs from the selected configuration",
      );
    // Parent attribution is valid for the reviewed direct Process.Start protocol.
    // Unknown bridge versions must be reviewed instead of silently guessing it.
    if (health.version !== "2.0.0")
      throw new AnalysisCapabilityUnavailableError(
        "forge-guest",
        "inspect_guest_runtime",
        "Guest bridge protocol version has not been reviewed for process attribution",
      );
    const run = runSchema.safeParse(
      await requestGuestJson(
        new URL("run", this.#configuration.base_url),
        token,
        signal,
        {
          shell: "powershell",
          command: GUEST_METADATA_PROBE,
          timeoutMs: 5000,
          maxOutputBytes: 8192,
        },
      ),
    );
    if (!run.success)
      throw new Error(
        "Fixed guest identity probe did not complete successfully; remote output withheld",
      );
    let metadata: z.infer<typeof metadataSchema>;
    try {
      metadata = metadataSchema.parse(JSON.parse(run.data.stdout));
    } catch {
      throw new Error(
        "Fixed guest identity probe returned invalid metadata; remote output withheld",
      );
    }
    if (metadata.computerName !== health.computerName)
      throw new Error("Guest machine changed during identity observation");
    const bridgeInstanceId = createHash("sha256")
      .update(JSON.stringify(metadata))
      .digest("hex")
      .slice(0, 32);
    this.#assertActive(signal);
    return { ...health, ...metadata, bridgeInstanceId };
  }

  /** Internal existing protocol only. Application case owners select every path/program. */
  writeSmallFile(
    path: string,
    bytes: Uint8Array,
    signal?: AbortSignal,
  ): Promise<void> {
    return this.#track(
      (async () => {
        this.#assertActive(signal);
        if (bytes.byteLength > 40 * 1024)
          throw new Error("Guest transfer chunk exceeds40KiB");
        const response = z
          .object({
            ok: z.literal(true),
            path: z.literal(path),
            bytes: z.literal(bytes.byteLength),
          })
          .safeParse(
            await requestGuestJson(
              new URL("write-file", this.#configuration.base_url),
              await this.#readToken(signal),
              // Once dispatched, drain this bounded physical write. Caller
              // cancellation cannot prove that the guest did not write it.
              undefined,
              {
                path,
                contentBase64: Buffer.from(bytes).toString("base64"),
                createParent: true,
              },
              { timeoutMs: 10000, responseBytes: 8192 },
            ),
          );
        if (!response.success)
          throw new Error(
            "Guest chunk write did not return the expected path/extent; remote body withheld",
          );
      })(),
    );
  }

  readSmallFile(
    path: string,
    maximum: number,
    signal?: AbortSignal,
  ): Promise<Uint8Array> {
    return this.#track(
      (async () => {
        this.#assertActive(signal);
        if (
          !Number.isSafeInteger(maximum) ||
          maximum < 1 ||
          maximum > 40 * 1024
        )
          throw new Error("Guest read extent must be1..40KiB");
        const response = z
          .object({
            ok: z.literal(true),
            path: z.literal(path),
            bytes: z.int().min(0).max(maximum),
            contentBase64: z.string().max(4 * Math.ceil(maximum / 3)),
          })
          .safeParse(
            await requestGuestJson(
              new URL("read-file", this.#configuration.base_url),
              await this.#readToken(signal),
              signal,
              { path, maxBytes: maximum },
              { timeoutMs: 10000, responseBytes: 64 * 1024 },
            ),
          );
        if (!response.success)
          throw new Error(
            "Guest bounded read did not return the expected extent; remote body withheld",
          );
        const decoded = Buffer.from(response.data.contentBase64, "base64");
        if (
          decoded.length !== response.data.bytes ||
          decoded.toString("base64") !== response.data.contentBase64
        )
          throw new Error("Guest file bytes are not canonical bounded Base64");
        this.#assertActive(signal);
        return decoded;
      })(),
    );
  }

  /** No MCP remote-shell endpoint: only application-generated case programs use this port. */
  runCaseProgram(
    program: {
      readonly source: string;
      readonly timeoutMs: number;
      readonly cwd: string;
    },
    signal?: AbortSignal,
  ): Promise<{
    readonly exitCode: number;
    readonly timedOut: boolean;
    readonly stdout: string;
    readonly stderr: string;
  }> {
    return this.#track(
      (async () => {
        this.#assertActive(signal);
        if (
          Buffer.byteLength(program.source, "utf8") > 40 * 1024 ||
          !Number.isSafeInteger(program.timeoutMs) ||
          program.timeoutMs < 1 ||
          program.timeoutMs > 60000
        )
          throw new Error(
            "Guest generated program exceeds existing protocol bounds",
          );
        const result = z
          .object({
            ok: z.literal(true),
            exitCode: z.int(),
            timedOut: z.boolean(),
            stdout: z.string().max(64 * 1024),
            stderr: z.string().max(64 * 1024),
          })
          .safeParse(
            await requestGuestJson(
              new URL("run", this.#configuration.base_url),
              await this.#readToken(signal),
              // The existing server owns the child deadline. Do not abandon
              // its completion response merely because the caller cancelled.
              undefined,
              {
                shell: "powershell",
                command: program.source,
                cwd: program.cwd,
                timeoutMs: program.timeoutMs,
                maxOutputBytes: 16384,
              },
              {
                timeoutMs: program.timeoutMs + 15000,
                responseBytes: 256 * 1024,
              },
            ),
          );
        if (!result.success)
          throw new Error(
            "Generated guest program did not return the reviewed result shape; remote body withheld",
          );
        // A completed physical outcome is retained even if cancellation/close arrived
        // during finalization. The application owner records it before projecting cancellation.
        return result.data;
      })(),
    );
  }

  #assertActive(signal?: AbortSignal): void {
    if (signal?.aborted)
      throw new AnalysisCancelledError("inspect_guest_runtime", {
        cause: signal.reason,
      });
    if (this.#closed)
      throw new AnalysisCapabilityUnavailableError(
        "forge-guest",
        "inspect_guest_runtime",
        "Guest bridge owner is closed",
      );
  }

  async close(): Promise<void> {
    this.#closed = true;
    await Promise.allSettled([...this.#active]);
    await this.#resources.close();
  }
}
