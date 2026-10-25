import { z } from "incur";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { FORGE_ANDROID_BUILD_TOOL_CONTRACTS } from "../contracts/forge/androidBuildToolContracts.js";
import { createForgeAndroidBuildService } from "../composition/forgeAndroidBuild.js";
import { FORGE_ANDROID_BUILD_PROVIDER } from "../application/forge/AndroidBuildService.js";
import { safeParseJson } from "../domain/safeJson.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import { logCliCommand } from "../cliLogging.js";
import { withCommandCancellation } from "./commandCancellation.js";
export const registerForgeAndroidBuildCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): void => {
  for (const contract of FORGE_ANDROID_BUILD_TOOL_CONTRACTS) {
    const command = contract.name.replaceAll("_", "-");
    cli.command(command, {
      description: contract.description,
      args: z.object({
        input: z.string().describe(`JSON arguments matching ${contract.name}`),
      }),
      run: ({ args }) =>
        withCommandCancellation((signal) =>
          logCliCommand(logger, command, async () => {
            const input = safeParseJson(args.input);
            if (!input.ok)
              return projectAnalysisError(
                new AnalysisInputError(contract.name, {
                  cause: input.cause,
                  userMessage: "input must match this Android build operation",
                }),
              );
            const service = createForgeAndroidBuildService(environment);
            return finishAnalysisCommand(
              () => service.execute(contract.name, input.value, { signal }),
              service,
              FORGE_ANDROID_BUILD_PROVIDER.id,
              contract.name,
              signal,
            );
          }),
        ),
    });
  }
};
