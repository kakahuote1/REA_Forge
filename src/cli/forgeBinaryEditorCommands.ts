import { z } from "incur";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { FORGE_BINARY_EDITOR_TOOL_CONTRACTS } from "../contracts/forge/binaryEditorToolContracts.js";
import { createForgeBinaryEditorService } from "../composition/forgeBinaryEditor.js";
import { FORGE_BINARY_EDITOR_PROVIDER } from "../application/forge/BinaryEditorService.js";
import { safeParseJson } from "../domain/safeJson.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import { logCliCommand } from "../cliLogging.js";

/** Each CLI command accepts the exact JSON argument object advertised by its MCP tool. */
export const registerForgeBinaryEditorCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  for (const contract of FORGE_BINARY_EDITOR_TOOL_CONTRACTS) {
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
                    "input must be a JSON object matching this tool's arguments",
                }),
              );
            const service = createForgeBinaryEditorService();
            return finishAnalysisCommand(
              () => service.execute(contract.name, decoded.value, { signal }),
              service,
              FORGE_BINARY_EDITOR_PROVIDER.id,
              contract.name,
              signal,
            );
          }),
        ),
    });
  }
};
