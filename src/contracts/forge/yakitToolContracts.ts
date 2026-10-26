import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";
import {
  yakitInputs,
  yakitReportSchema,
  type ForgeYakitOperation,
} from "../../domain/forge/yakit.js";
const descriptions = {
  forge_yakit_request:
    "Send one explicit HTTP(S) request using installed official Yak MCP in a private Forge-owned profile. Fixed single concurrency, literal body/tags, no system proxy, redirects, scripts, plugins or batch targets. Headers/body can affect the selected target. Retain vendor request/response text and errors; does not control the human Yakit GUI or change host network/CA settings.",
  forge_yakit_flows:
    "Query official Yakit HTTPFlow metadata from a named Forge-owned private engine profile using keyword and bounded pagination. No GUI database adoption or network request. Retain original Go-quoted fields; total/order and omitted bodies remain unknown. Uses only common fields because the installed vendor schema advertises unrelated advanced script filters.",
  forge_read_yakit_result:
    "Authenticate a retained Yakit receipt, page source response/history data or export bounded exact artifact-file bytes. This is historical Evidence, not a new request or current database. Does not initialize Yakit; byte export authenticates retained JSON/log files, not arbitrary original network octets.",
} as const;
const examples = {
  forge_yakit_request: { url: "http://127.0.0.1:8080/fixture", method: "GET" },
  forge_yakit_flows: {
    profile: "research",
    keyword: "fixture",
    page: 1,
    count: 20,
  },
  forge_read_yakit_result: {
    receipt_path: "/work/receipt.json",
    receipt_sha256: "a".repeat(64),
    facet: "data",
  },
} as const;
const contract = <Name extends ForgeYakitOperation>(name: Name) =>
  ({
    name,
    ...toolContractMetadata(name),
    kind: "forge-static-provider" as const,
    description: descriptions[name],
    inputSchema: yakitInputs[name],
    outputSchema: evidenceResultOf(yakitReportSchema),
    examples: [
      {
        title: "Use an explicit private profile or retained receipt",
        input: examples[name],
      },
    ],
  }) as const satisfies ToolContract;
export const FORGE_YAKIT_TOOL_CONTRACTS = [
  contract("forge_yakit_request"),
  contract("forge_yakit_flows"),
  contract("forge_read_yakit_result"),
] as const;
