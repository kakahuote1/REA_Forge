import { hostExecutionRefusal } from "../application/ExecutionDomainAdmission.js";
import { CLI_COMMAND_TOOL_ALIASES } from "../cliCommandNames.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { CliInstance } from "./types.js";
import { visitRegisteredCommands } from "./visitRegisteredCommands.js";

/** Bind the same execution admission used by MCP before any command body runs. */
export const applyHostExecutionAdmission = (cli: CliInstance): void => {
  const aliases: Readonly<Record<string, readonly string[]>> =
    CLI_COMMAND_TOOL_ALIASES;
  visitRegisteredCommands(cli, (command, path) => {
    const operations = aliases[path] ?? [path.replaceAll("-", "_")];
    const run = command.run;
    command.run = (context) => {
      for (const operation of operations) {
        const refusal = hostExecutionRefusal(operation);
        if (refusal !== undefined) {
          process.exitCode = 1;
          return projectAnalysisError(refusal);
        }
      }
      return run(context);
    };
  });
};
