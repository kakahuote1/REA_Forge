import { OwnedStaticHelper } from "../OwnedStaticHelper.js";
import {
  androidBuildReportSchema,
  type AndroidBuildFamily,
  type AndroidBuildReport,
  type ForgeAndroidBuildOperation,
} from "../../domain/forge/androidBuild.js";
export class AndroidBuildAdapter extends OwnedStaticHelper<
  ForgeAndroidBuildOperation,
  AndroidBuildReport
> {
  constructor(
    family: AndroidBuildFamily,
    environment: Readonly<NodeJS.ProcessEnv> = process.env,
  ) {
    super(
      `forge-${family}`,
      "bridge/forge/android_build/worker.py",
      androidBuildReportSchema,
      family,
      environment,
    );
  }
}
