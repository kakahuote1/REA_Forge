import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";
import {
  type ForgePeOperation,
  peStaticInputs,
  peStaticReportSchema,
} from "../../domain/forge/peStatic.js";
const contract = <Name extends ForgePeOperation>(name: Name) =>
  ({
    name,
    ...toolContractMetadata(name),
    kind: "forge-static-provider" as const,
    description: {
      forge_inspect_pe:
        "Read bounded PE32/PE32+ headers, sections, entropy, normal/delay/bound imports, exports/forwarders, resources, mitigation flags, TLS/CLR/exception/version facts through the copied static workbench. Select a facet/page; retain complete output. Does not load or execute the file. Certificate presence is not verification. Native exact resource/certificate/export readers remain available independently.",
      forge_resolve_pe_dependencies:
        "Build a bounded static PE dependency candidate graph from explicit local roots and this host's APISet/KnownDLL/SxS snapshots without loading DLLs. Defaults to the nodes collection; select edges/missing or retained metadata. Static candidate order and revisited edges do not establish loader behavior or directed cycles; source/parser and node/depth/edge bounds remain explicit.",
      forge_test_upx:
        "Use the pinned UPX -t operation against a copied file with an owned 1–45 second deadline. Success verifies that selected UPX input; any other supported exit is not_verified, not proof no packer exists. Does not execute or edit the original file.",
      forge_unpack_upx:
        "Require UPX -t success, then use fixed UPX -d to produce a fresh retained PE copy under the same selected deadline. Preserves original hashes and output identity; does not run the executable, emulate target instructions or unpack other protectors. Read output facts separately.",
      forge_read_pe_result:
        "Verify a retained PE receipt/full-result identity, then page a selected facts/dependency facet or read exact bytes from artifact_index0(full JSON) or1+(derived outputs), up to64KiB. Readback does not re-analyze the original file or establish current source freshness.",
    }[name],
    inputSchema: peStaticInputs[name],
    outputSchema: evidenceResultOf(peStaticReportSchema),
    examples: [
      {
        title: "Inspect explicit PE input or retained receipt",
        input:
          name === "forge_read_pe_result"
            ? {
                receipt_path: "/work/receipt.json",
                receipt_sha256: "a".repeat(64),
              }
            : { path: "/targets/program.exe" },
      },
    ],
  }) as const satisfies ToolContract;
export const FORGE_PE_TOOL_CONTRACTS = [
  contract("forge_inspect_pe"),
  contract("forge_resolve_pe_dependencies"),
  contract("forge_test_upx"),
  contract("forge_unpack_upx"),
  contract("forge_read_pe_result"),
] as const;
