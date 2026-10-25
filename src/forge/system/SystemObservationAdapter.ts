import { OwnedStaticHelper } from "../OwnedStaticHelper.js";
import {
  systemObservationReportSchema,
  type ForgeSystemOperation,
  type SystemObservationFamily,
  type SystemObservationReport,
} from "../../domain/forge/systemObservation.js";
export class SystemObservationAdapter extends OwnedStaticHelper<
  ForgeSystemOperation,
  SystemObservationReport
> {
  constructor(
    family: SystemObservationFamily,
    environment: Readonly<NodeJS.ProcessEnv> = process.env,
  ) {
    super(
      `forge-${family}`,
      "bridge/forge/system/worker.py",
      systemObservationReportSchema,
      family,
      environment,
    );
  }
}
