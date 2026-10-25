import { z } from "incur";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { FORGE_DOTNET_TOOL_CONTRACTS } from "../contracts/forge/dotnetToolContracts.js";
import { createForgeDotnetService } from "../composition/forgeDotnet.js";
import { FORGE_DOTNET_PROVIDER } from "../application/forge/DotnetAnalysisService.js";
import { safeParseJson } from "../domain/safeJson.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import { logCliCommand } from "../cliLogging.js";
import { withCommandCancellation } from "./commandCancellation.js";
export const registerForgeDotnetCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): void => {
  for (const contract of FORGE_DOTNET_TOOL_CONTRACTS) {
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
                  userMessage: "input must match this typed Dotnet operation",
                }),
              );
            const service = createForgeDotnetService(environment);
            return finishAnalysisCommand(
              () => service.execute(contract.name, decoded.value, { signal }),
              service,
              FORGE_DOTNET_PROVIDER.id,
              contract.name,
              signal,
            );
          }),
        ),
    });
  }
};
