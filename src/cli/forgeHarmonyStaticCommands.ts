import { z } from "incur";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { FORGE_HARMONY_TOOL_CONTRACTS } from "../contracts/forge/harmonyStaticToolContracts.js";
import { createForgeHarmonyStaticService } from "../composition/forgeHarmonyStatic.js";
import { FORGE_HARMONY_PROVIDER } from "../application/forge/HarmonyStaticService.js";
import { safeParseJson } from "../domain/safeJson.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import { logCliCommand } from "../cliLogging.js";
import { withCommandCancellation } from "./commandCancellation.js";
export const registerForgeHarmonyStaticCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): void => {
  for (const contract of FORGE_HARMONY_TOOL_CONTRACTS) {
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
                  userMessage: "input must match this Harmony static operation",
                }),
              );
            const service = createForgeHarmonyStaticService(environment);
            return finishAnalysisCommand(
              () => service.execute(contract.name, input.value, { signal }),
              service,
              FORGE_HARMONY_PROVIDER.id,
              contract.name,
              signal,
            );
          }),
        ),
    });
  }
};
