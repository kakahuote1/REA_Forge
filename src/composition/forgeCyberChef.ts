import { CyberChefService } from "../application/forge/CyberChefService.js";
import { CyberChefAdapter } from "../forge/cyberchef/CyberChefAdapter.js";
export const createForgeCyberChefService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): CyberChefService => new CyberChefService(new CyberChefAdapter(environment));
