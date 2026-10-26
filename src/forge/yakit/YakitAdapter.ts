import { OwnedStaticHelper } from "../OwnedStaticHelper.js";
import {
  yakitReportSchema,
  type ForgeYakitOperation,
  type YakitFamily,
  type YakitReport,
} from "../../domain/forge/yakit.js";
export class YakitAdapter extends OwnedStaticHelper<
  ForgeYakitOperation,
  YakitReport
> {
  constructor(
    family: YakitFamily,
    environment: Readonly<NodeJS.ProcessEnv> = process.env,
  ) {
    super(
      "forge-" + family,
      "bridge/forge/yakit/worker.py",
      yakitReportSchema,
      family,
      environment,
    );
  }
}
