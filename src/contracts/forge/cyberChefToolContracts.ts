import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import {
  cyberChefInputSchemas,
  cyberChefReportSchema,
  type ForgeCyberChefOperation,
} from "../../domain/forge/cyberChef.js";
const descriptions: Record<ForgeCyberChefOperation, string> = {
  forge_list_cyberchef_operations:
    "List the twenty configured offline CyberChef operations, exact argument defaults/types and known-parameter requirements. This is a reviewed subset, not the complete CyberChef catalog; no browser, listener or network requests.",
  forge_validate_cyberchef_recipe:
    "Validate and normalize a 1–16 step offline CyberChef recipe in exported {op,args} format using the installed operation APIs. Returns canonical recipe and digest without transforming an input file.",
  forge_run_cyberchef_recipe:
    "Apply a typed offline CyberChef recipe to a selected file: encoding, compression, hash, known-key AES/HMAC/XOR and JSON formatting. Keeps the original unchanged; returns a bounded preview, retained binary output/digest and replayable recipe receipt. No unknown-key recovery or external operations.",
  forge_replay_cyberchef_recipe:
    "Replay one digest-checked retained recipe receipt on a selected input. Revalidates all recipe steps, retains a new output and reports exact identities. Rejects changed or out-of-workspace receipts.",
  forge_suggest_cyberchef_steps:
    "Suggest bounded local encoding/compression/container labels from bytes. Candidates are heuristics only: no recipe is applied, no unknown key is recovered and no algorithm identification is proved.",
};
const recipe = [{ op: "From Base64" }];
const examples = {
  forge_list_cyberchef_operations: {},
  forge_validate_cyberchef_recipe: { recipe },
  forge_run_cyberchef_recipe: { path: "C:/analysis/encoded.txt", recipe },
  forge_replay_cyberchef_recipe: {
    path: "C:/analysis/encoded.txt",
    receipt_path: "C:/work/recipe.json",
    receipt_sha256: "0".repeat(64),
  },
  forge_suggest_cyberchef_steps: { path: "C:/analysis/encoded.txt" },
} as const;
const contract = <Name extends ForgeCyberChefOperation>(name: Name) =>
  ({
    name,
    ...toolContractMetadata(name),
    kind: "artifact-provider",
    description: descriptions[name],
    inputSchema: cyberChefInputSchemas[name],
    outputSchema: evidenceResultOf(cyberChefReportSchema),
    examples: [
      {
        title:
          "Use local files and operation arguments from the configured catalog",
        input: examples[name],
      },
    ],
  }) as const satisfies ToolContract;
export const FORGE_CYBERCHEF_TOOL_CONTRACTS = [
  contract("forge_list_cyberchef_operations"),
  contract("forge_validate_cyberchef_recipe"),
  contract("forge_run_cyberchef_recipe"),
  contract("forge_replay_cyberchef_recipe"),
  contract("forge_suggest_cyberchef_steps"),
] as const;
