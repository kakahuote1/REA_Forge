import { CyberChefService } from "../application/forge/CyberChefService.js";
import { CyberChefAdapter } from "../forge/cyberchef/CyberChefAdapter.js";
export const createForgeCyberChefService = (): CyberChefService =>
  new CyberChefService(new CyberChefAdapter());
