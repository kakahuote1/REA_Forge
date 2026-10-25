import { OwnedStaticHelper } from "../OwnedStaticHelper.js";
import {
  harmonyStaticReportSchema,
  type ForgeHarmonyOperation,
  type HarmonyStaticFamily,
  type HarmonyStaticReport,
} from "../../domain/forge/harmonyStatic.js";
export class HarmonyStaticAdapter extends OwnedStaticHelper<
  ForgeHarmonyOperation,
  HarmonyStaticReport
> {
  constructor(
    family: HarmonyStaticFamily,
    environment: Readonly<NodeJS.ProcessEnv> = process.env,
  ) {
    super(
      `forge-${family}`,
      "bridge/forge/harmony/worker.py",
      harmonyStaticReportSchema,
      family,
      environment,
    );
  }
}
