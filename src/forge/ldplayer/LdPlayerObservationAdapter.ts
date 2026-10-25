import type {
  LdPlayerObservationPort,
  LdPlayerInstanceObservation,
} from "../../application/forge/LdPlayerRuntimePort.js";
import { AnalysisCapabilityUnavailableError } from "../../domain/analysisErrorCore.js";
import {
  ldplayerObservationReportSchema,
  type LdPlayerObservationOperation,
  type LdPlayerObservationReport,
} from "../../domain/forge/ldplayerObservation.js";
import { OwnedStaticHelper } from "../OwnedStaticHelper.js";

/** Reuses the native owned helper; closes only its query children, never LDPlayer. */
export class LdPlayerObservationAdapter implements LdPlayerObservationPort {
  readonly #helper: OwnedStaticHelper<
    LdPlayerObservationOperation,
    LdPlayerObservationReport
  >;
  constructor(environment: Readonly<NodeJS.ProcessEnv> = process.env) {
    this.#helper = new OwnedStaticHelper(
      "forge-ldplayer-observation",
      "bridge/forge/ldplayer/observe.py",
      ldplayerObservationReportSchema,
      "ldplayer",
      environment,
      { deadlineMs: 15000, memoryLimitBytes: 256 * 1024 * 1024 },
    );
  }
  inspectAvailability(signal?: AbortSignal) {
    return this.#helper.inspectAvailability(signal);
  }
  async list(
    signal?: AbortSignal,
  ): Promise<readonly LdPlayerInstanceObservation[]> {
    const observed = await this.#helper.execute(
      "forge_observe_ldplayer_list",
      {},
      signal === undefined ? undefined : { signal },
    );
    if (!observed.ok) throw observed.error;
    return observed.value.result.instances;
  }
  async inspect(
    index: number,
    signal?: AbortSignal,
  ): Promise<LdPlayerInstanceObservation> {
    if (!Number.isSafeInteger(index) || index <= 0 || index > 9999)
      throw new AnalysisCapabilityUnavailableError(
        "forge-ldplayer",
        "inspect_ldplayer_instance",
        "Select an exact nonzero instance index",
      );
    const observed = await this.#helper.execute(
      "forge_observe_ldplayer_instance",
      { index },
      signal === undefined ? undefined : { signal },
    );
    if (!observed.ok) throw observed.error;
    const instances = observed.value.result.instances;
    if (instances.length !== 1 || instances[0]?.index !== index)
      throw new AnalysisCapabilityUnavailableError(
        "forge-ldplayer",
        "inspect_ldplayer_instance",
        "LDPlayer observation did not match the selected instance",
      );
    return instances[0];
  }
  close(): Promise<void> {
    return this.#helper.close();
  }
}
