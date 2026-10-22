import type { Logger } from "pino";
import type { CyberChefService } from "../application/forge/CyberChefService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { FORGE_CYBERCHEF_TOOL_CONTRACTS } from "../contracts/forge/cyberChefToolContracts.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { createContractToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
export const registerForgeCyberChefTools = (
  server: EvidenceMcpServer,
  service: CyberChefService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const handler = createContractToolHandler(
    server,
    service,
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  for (const contract of FORGE_CYBERCHEF_TOOL_CONTRACTS)
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
};
