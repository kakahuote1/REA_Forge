import { TOOL_EFFECTS } from "../contracts/toolEffects.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";

// Cleanup may release only resources already owned by the existing session.
// Blocking it after policy changes would strand those owners.
const RELEASE_OPERATIONS: ReadonlySet<string> = new Set([
  "close_gdb_session",
  "close_rizin_debug_session",
  "close_frida_session",
  "unload_frida_script",
]);

/** Admission for this host's public operations; never trusts request/env claims of guest authority. */
export const hostExecutionRefusal = (
  operation: string,
): AnalysisCapabilityUnavailableError | undefined => {
  const effects = TOOL_EFFECTS[operation];
  if (effects === undefined || RELEASE_OPERATIONS.has(operation))
    return undefined;
  // This named endpoint runs only the existing statically constrained 010 recipe
  // on a private non-PE copy. Its producing worker still validates every script.
  // It is not an arbitrary Python/script sandbox or a general allow-by-name API.
  if (operation === "forge_run_binary_script") return undefined;
  if (!effects.executesForeignCode && !effects.mutatesDevice) return undefined;
  return new AnalysisCapabilityUnavailableError(
    "forge-host-static",
    operation,
    "This operation requires an explicitly selected, identity-verified guest or device runtime; it cannot run through the host-static entrypoint.",
    {
      remediationAction:
        "Use the configured guest/device operation with its observed target identity. Do not retry on the host, change an environment variable, or bypass this boundary with a shell command.",
    },
  );
};
