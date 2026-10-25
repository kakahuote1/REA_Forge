import { z } from "incur";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { FORGE_ENRICHMENT_TOOL_CONTRACTS } from "../contracts/forge/nativeEnrichmentToolContracts.js";
import { createForgeNativeEnrichmentService } from "../composition/forgeNativeEnrichment.js";
import { FORGE_ENRICHMENT_PROVIDER } from "../application/forge/NativeEnrichmentService.js";
import { safeParseJson } from "../domain/safeJson.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import { logCliCommand } from "../cliLogging.js";
import { withCommandCancellation } from "./commandCancellation.js";
export const registerForgeNativeEnrichmentCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): void => {
  for (const contract of FORGE_ENRICHMENT_TOOL_CONTRACTS) {
    const command = contract.name.replaceAll("_", "-");
    cli.command(command, {
      description: contract.description,
      args: z.object({
        input: z.string().describe(`JSON arguments matching ${contract.name}`),
      }),
      run: ({ args }) =>
        withCommandCancellation((signal) =>
          logCliCommand(logger, command, async () => {
            const decoded = safeParseJson(args.input);
            if (!decoded.ok)
              return projectAnalysisError(
                new AnalysisInputError(contract.name, {
                  cause: decoded.cause,
                  userMessage:
                    "input must match this static enrichment operation",
                }),
              );
            const service = createForgeNativeEnrichmentService(environment);
            return finishAnalysisCommand(
              () => service.execute(contract.name, decoded.value, { signal }),
              service,
              FORGE_ENRICHMENT_PROVIDER.id,
              contract.name,
              signal,
            );
          }),
        ),
    });
  }
};
