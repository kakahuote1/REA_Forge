import { JavaAnalysisService } from "../application/forge/JavaAnalysisService.js";
import { JavaAdapter } from "../forge/java/JavaAdapter.js";
export const createForgeJavaService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): JavaAnalysisService => new JavaAnalysisService(new JavaAdapter(environment));
