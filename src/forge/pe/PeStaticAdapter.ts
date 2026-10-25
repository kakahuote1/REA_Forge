import { OwnedStaticHelper } from "../OwnedStaticHelper.js";
import {
  peStaticReportSchema,
  type ForgePeOperation,
  type PeStaticFamily,
  type PeStaticReport,
} from "../../domain/forge/peStatic.js";
export class PeStaticAdapter extends OwnedStaticHelper<
  ForgePeOperation,
  PeStaticReport
> {
  constructor(
    family: PeStaticFamily,
    environment: Readonly<NodeJS.ProcessEnv> = process.env,
  ) {
    super(
      `forge-${family}`,
      "bridge/forge/pe/worker.py",
      peStaticReportSchema,
      family,
      environment,
    );
  }
}
