import { SystemObservationService } from "../application/forge/SystemObservationService.js";
import { SystemObservationAdapter } from "../forge/system/SystemObservationAdapter.js";
export const createForgeSystemObservationService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): SystemObservationService =>
  new SystemObservationService({
    system_informer: new SystemObservationAdapter(
      "system_informer",
      environment,
    ),
    hollows_hunter: new SystemObservationAdapter("hollows_hunter", environment),
    system_results: new SystemObservationAdapter("system_results", environment),
  });
