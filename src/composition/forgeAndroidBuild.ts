import { AndroidBuildService } from "../application/forge/AndroidBuildService.js";
import { AndroidBuildAdapter } from "../forge/android/AndroidBuildAdapter.js";
export const createForgeAndroidBuildService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
) =>
  new AndroidBuildService({
    apk_workspace: new AndroidBuildAdapter("apk_workspace", environment),
    smali: new AndroidBuildAdapter("smali", environment),
    apk_signing: new AndroidBuildAdapter("apk_signing", environment),
    android_results: new AndroidBuildAdapter("android_results", environment),
  });
