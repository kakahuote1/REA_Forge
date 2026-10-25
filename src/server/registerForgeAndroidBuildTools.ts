import type { Logger } from "pino";
import type { AndroidBuildService } from "../application/forge/AndroidBuildService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { FORGE_ANDROID_BUILD_TOOL_CONTRACTS } from "../contracts/forge/androidBuildToolContracts.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { createContractToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
export const registerForgeAndroidBuildTools = (
  server: EvidenceMcpServer,
  service: AndroidBuildService,
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
  for (const contract of FORGE_ANDROID_BUILD_TOOL_CONTRACTS)
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
};
