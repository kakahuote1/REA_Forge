import { PeStaticService } from "../application/forge/PeStaticService.js";
import { PeStaticAdapter } from "../forge/pe/PeStaticAdapter.js";
export const createForgePeStaticService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): PeStaticService =>
  new PeStaticService({
    pe_parser: new PeStaticAdapter("pe_parser", environment),
    upx: new PeStaticAdapter("upx", environment),
    pe_results: new PeStaticAdapter("pe_results", environment),
  });
