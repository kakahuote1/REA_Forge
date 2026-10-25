import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";
import {
  type ForgeHarmonyOperation,
  harmonyStaticInputs,
  harmonyStaticReportSchema,
} from "../../domain/forge/harmonyStatic.js";
const descriptions = {
  forge_inspect_hap:
    "Inspect and extract a bounded HAP/APP/HSP ZIP into fresh retained artifacts, with exact member hashes, metadata declarations and ABC/resource occurrences. Reuse native inspect_artifact/extract_artifact and project_harmony_application_graph for the authenticated content-addressed application view. No target execution; JSON5 that is not strict JSON remains raw rather than guessed.",
  forge_inspect_abc:
    "Read Panda header facts or fixed abcde classes/methods/legacy resource-index results. Methods include classes/fields/code extents and offsets; exact full JSONL remains readable with forge_read_harmony_result. Defaults to methods. RestoolV2 is explicitly unsupported. Does not execute ABC, open Compose GUI, resolve runtime calls or guarantee source semantics.",
  forge_disassemble_ark:
    "Use pinned official Ark SDK6.0.0.47 --verbose to produce byte-exact assembly, method/record/line counts and a bounded preview. No assembler or target VM execution. Read retained lines with invalid UTF-8 escaped, or exact bytes. Bytecode version is observed, not an assertion every version/opcode works.",
  forge_render_abc_method:
    "Select an exact decimal method_offset from abcde inventory and render instructions/encoded method-string references or experimental JS. References include definitions/literals, not a resolved call graph. JS is unverified reconstruction; unsupported instructions and try/catch fail explicitly and partial output is not a successful result.",
  forge_decompile_hap:
    "Extract admitted ABC members and pass them, not the HAP alone, to pinned headless JADX-HAP. Require actual source artifacts; resource-only output cannot pass as decompilation. Preserve full outputs/hashes. No Java class/plugin selection, target execution or GUI; reconstructed code is not original or verified equivalent source.",
  forge_sign_hap:
    "Sign a copied HAP with a configured local-JKS operator profile, then perform actual vendor signature verification. Default test creates a self-signed non-deployment identity, not a platform provisioning profile or trusted CA. Passwords are read only from operator-selected files, never tool arguments; this vendor requires transient argv values and retained sign logs redact them. No trust-store or device changes.",
  forge_verify_hap_signature:
    "Verify a copied HAP through the pinned offline vendor tool and retain actual certificate/profile/proof outputs when produced. Non-success is not_verified rather than an unsupported claim of invalidity. Cryptographic/profile consistency does not establish trusted issuer, revocation, deployability or benignness.",
  forge_read_harmony_result:
    "Verify a retained Harmony receipt/full-result and page selected facets, exact artifact bytes(up to64KiB), text lines or ABC JSONL. artifact_index0 is full metadata JSON,1+ are listed outputs; private signing material is not listed. Historical byte integrity is not current input freshness. Large/unsupported display rows retain raw byte access.",
} as const;
const contract = <Name extends ForgeHarmonyOperation>(name: Name) =>
  ({
    name,
    ...toolContractMetadata(name),
    kind: "forge-static-provider" as const,
    description: descriptions[name],
    inputSchema: harmonyStaticInputs[name],
    outputSchema: evidenceResultOf(harmonyStaticReportSchema),
    examples: [
      {
        title: "Inspect an explicit Harmony input or retained receipt",
        input:
          name === "forge_read_harmony_result"
            ? {
                receipt_path: "/work/receipt.json",
                receipt_sha256: "a".repeat(64),
              }
            : name === "forge_render_abc_method"
              ? { path: "/targets/modules.abc", method_offset: 123 }
              : {
                  path:
                    name === "forge_inspect_abc" ||
                    name === "forge_disassemble_ark"
                      ? "/targets/modules.abc"
                      : "/targets/application.hap",
                },
      },
    ],
  }) as const satisfies ToolContract;
export const FORGE_HARMONY_TOOL_CONTRACTS = [
  contract("forge_inspect_hap"),
  contract("forge_inspect_abc"),
  contract("forge_disassemble_ark"),
  contract("forge_render_abc_method"),
  contract("forge_decompile_hap"),
  contract("forge_sign_hap"),
  contract("forge_verify_hap_signature"),
  contract("forge_read_harmony_result"),
] as const;
