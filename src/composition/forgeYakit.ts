import { YakitService } from "../application/forge/YakitService.js";
import { YakitAdapter } from "../forge/yakit/YakitAdapter.js";
export const createForgeYakitService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): YakitService =>
  new YakitService({
    yakit: new YakitAdapter("yakit", environment),
    yakit_results: new YakitAdapter("yakit_results", environment),
  });
