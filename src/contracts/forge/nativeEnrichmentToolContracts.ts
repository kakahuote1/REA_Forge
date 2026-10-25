import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import {
  enrichmentInputSchemas,
  enrichmentReportSchema,
  type ForgeEnrichmentOperation,
} from "../../domain/forge/nativeEnrichment.js";
const descriptions: Record<ForgeEnrichmentOperation, string> = {
  forge_analyze_capabilities:
    "Analyze a selected local PE/ELF/shellcode with the configured pinned capa Vivisect backend and bundled rules. Returns candidate capability names, ATT&CK/MBC metadata and match address kinds/values, with a digest-checked full JSON receipt. No IDA backend, custom rules, online sandbox or target process execution.",
  forge_recover_strings:
    "Recover selected static/decoded/stack/tight strings from a selected file using pinned FLOSS static analysis/emulation. Returns paged candidate strings with offsets/function context and full retained JSON. No target execution or IDA script loading; decoded values still need corroboration.",
  forge_list_api_hash_types:
    "List exact hash type IDs, widths and names in the configured read-only pinned FLARE-IDA database. Results describe the database, not proof that an executable uses those algorithms.",
  forge_lookup_api_hash:
    "Look up one 32-bit integer/hex API hash in the pinned read-only FLARE database, optionally selecting a numeric hash type. Returns all candidate collisions through paging, with library/symbol names and provenance. Accepts no SQL, custom database, code execution or IDA annotations.",
  forge_read_enrichment_result:
    "Read a page of a retained digest-checked capa/FLOSS/API-hash result without re-running analysis. Requires the receipt path and SHA-256 returned by an earlier operation; verifies the full result identity within the retained workspace. This is historical readback, not fresh execution or an authentication claim.",
};
const stringKinds = ["static", "decoded", "stack", "tight"];
const examples = {
  forge_analyze_capabilities: { path: "C:/analysis/example.exe", format: "pe" },
  forge_recover_strings: {
    path: "C:/analysis/example.exe",
    string_kinds: stringKinds,
  },
  forge_list_api_hash_types: {},
  forge_lookup_api_hash: { hash_value: "0x12345678" },
  forge_read_enrichment_result: {
    receipt_path: "C:/work/enrichment/receipt.json",
    receipt_sha256: "0".repeat(64),
    offset: 50,
  },
} as const;
const contract = <Name extends ForgeEnrichmentOperation>(name: Name) =>
  ({
    name,
    ...toolContractMetadata(name),
    kind: "forge-static-provider",
    description: descriptions[name],
    inputSchema: enrichmentInputSchemas[name],
    outputSchema: evidenceResultOf(enrichmentReportSchema),
    examples: [
      {
        title: "Use selected local analysis input or a returned receipt",
        input: examples[name],
      },
    ],
  }) as const satisfies ToolContract;
export const FORGE_ENRICHMENT_TOOL_CONTRACTS = [
  contract("forge_analyze_capabilities"),
  contract("forge_recover_strings"),
  contract("forge_list_api_hash_types"),
  contract("forge_lookup_api_hash"),
  contract("forge_read_enrichment_result"),
] as const;
