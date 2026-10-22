import { JavaAnalysisService } from "../application/forge/JavaAnalysisService.js";
import { JavaAdapter } from "../forge/java/JavaAdapter.js";
export const createForgeJavaService = (): JavaAnalysisService =>
  new JavaAnalysisService(new JavaAdapter());
