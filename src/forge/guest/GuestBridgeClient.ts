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
  readonly #active = new Set<Promise<GuestBridgeHealth>>();
  #closed = false;

  constructor(configuration: GuestBridgeConfiguration) {
    this.#configuration = guestBridgeConfigurationSchema.parse(configuration);
  }

  inspect(signal?: AbortSignal): Promise<GuestBridgeHealth> {
    if (this.#closed)
      return Promise.reject(new Error("Guest bridge client is closed"));
    const operation = this.#inspect(signal);
    this.#active.add(operation);
    void operation
      .finally(() => this.#active.delete(operation))
      .catch(() => undefined);
    return operation;
  }

  async #inspect(signal?: AbortSignal): Promise<GuestBridgeHealth> {
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
