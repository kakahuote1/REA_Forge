import type { Logger } from "pino";
import type { OfflineTrafficService } from "../application/forge/OfflineTrafficService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { FORGE_TRAFFIC_TOOL_CONTRACTS } from "../contracts/forge/offlineTrafficToolContracts.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { createContractToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
export const registerForgeOfflineTrafficTools = (
  server: EvidenceMcpServer,
  service: OfflineTrafficService,
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
  for (const contract of FORGE_TRAFFIC_TOOL_CONTRACTS)
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
};
