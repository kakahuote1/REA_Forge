import { DotnetAnalysisService } from "../application/forge/DotnetAnalysisService.js";
import { DotnetAdapter } from "../forge/dotnet/DotnetAdapter.js";
export const createForgeDotnetService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): DotnetAnalysisService =>
  new DotnetAnalysisService(new DotnetAdapter(environment));
