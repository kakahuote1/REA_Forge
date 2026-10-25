import { HarmonyStaticService } from "../application/forge/HarmonyStaticService.js";
import { HarmonyStaticAdapter } from "../forge/harmony/HarmonyStaticAdapter.js";
export const createForgeHarmonyStaticService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): HarmonyStaticService =>
  new HarmonyStaticService({
    harmony_packages: new HarmonyStaticAdapter("harmony_packages", environment),
    abcde: new HarmonyStaticAdapter("abcde", environment),
    ark_disasm: new HarmonyStaticAdapter("ark_disasm", environment),
    jadx_hap: new HarmonyStaticAdapter("jadx_hap", environment),
    hap_signing: new HarmonyStaticAdapter("hap_signing", environment),
    hap_verification: new HarmonyStaticAdapter("hap_verification", environment),
    harmony_results: new HarmonyStaticAdapter("harmony_results", environment),
  });
