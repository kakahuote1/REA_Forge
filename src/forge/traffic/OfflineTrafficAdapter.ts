import { OwnedStaticHelper } from "../OwnedStaticHelper.js";
import {
  trafficReportSchema,
  type TrafficReport,
  type ForgeTrafficOperation,
  type TrafficFamily,
} from "../../domain/forge/offlineTraffic.js";
export class OfflineTrafficAdapter extends OwnedStaticHelper<
  ForgeTrafficOperation,
  TrafficReport
> {
  constructor(
    family: TrafficFamily,
    environment: Readonly<NodeJS.ProcessEnv> = process.env,
  ) {
    super(
      `forge-${family}`,
      "bridge/forge/traffic/worker.py",
      trafficReportSchema,
      family,
      environment,
    );
  }
}
