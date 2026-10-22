import { DotnetAnalysisService } from "../application/forge/DotnetAnalysisService.js";
import { DotnetAdapter } from "../forge/dotnet/DotnetAdapter.js";
export const createForgeDotnetService = (): DotnetAnalysisService =>
  new DotnetAnalysisService(new DotnetAdapter());
