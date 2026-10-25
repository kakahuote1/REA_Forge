import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import {
  pythonBytecodeInputs,
  pythonBytecodeReportSchema,
  type ForgePythonOperation,
} from "../../domain/forge/pythonBytecode.js";
const descriptions = {
  forge_disassemble_python:
    "Disassemble explicit local PYC bytes using pinned xdis direct library APIs. Returns actual version/implementation facts and bounded classic/extended/xasm text, retaining full bounded output. Supports known xdis versions beyond REA's native CPython header reader. Never imports or executes the target, compiles a source fallback or starts a CLI.",
  forge_decompile_legacy_python:
    "Recover unverified source from a local PYC using pinned uncompyle6 (through 3.6) or decompyle3 (3.7–3.8), selected from actual xdis facts. An explicit engine choice is honored or refused, never silently replaced. Unsupported versions and parser failures remain explicit; no target execution or source-CLI fallback. Use the modern tool for qualified CPython 3.9–3.12 models.",
  forge_decompile_modern_python:
    "Recover source from qualified CPython 3.9–3.12 PYC using existing local version-matched PyLingual models. Verifies selected model/source/interpreter identities, uses no downloads or target execution, and compiles only generated text for the engine's bytecode comparison. This bounded CPU operation may take up to 112 seconds plus owned setup/cleanup; set the client timeout above 135 seconds. Other magics return unsupported, not guessed source.",
  forge_read_python_result:
    "Read a text window from a retained digest-checked Python analysis result without importing target code or rerunning a decompiler. Complete bounded source/disassembly stays in the full-result JSON. Historical readback is not current source freshness.",
};
const example = {
  forge_disassemble_python: {
    path: "C:/analysis/module.pyc",
    format: "classic",
  },
  forge_decompile_legacy_python: {
    path: "C:/analysis/python38.pyc",
    engine: "auto",
  },
  forge_decompile_modern_python: { path: "C:/analysis/python311.pyc" },
  forge_read_python_result: {
    receipt_path: "C:/work/python/receipt.json",
    receipt_sha256: "0".repeat(64),
    text_offset: 4096,
  },
} as const;
const contract = <Name extends ForgePythonOperation>(name: Name) =>
  ({
    name,
    ...toolContractMetadata(name),
    kind: "forge-static-provider",
    description: descriptions[name],
    inputSchema: pythonBytecodeInputs[name],
    outputSchema: evidenceResultOf(pythonBytecodeReportSchema),
    examples: [
      {
        title: "Inspect selected bytecode or retained text",
        input: example[name],
      },
    ],
  }) as const satisfies ToolContract;
export const FORGE_PYTHON_TOOL_CONTRACTS = [
  contract("forge_disassemble_python"),
  contract("forge_decompile_legacy_python"),
  contract("forge_decompile_modern_python"),
  contract("forge_read_python_result"),
] as const;
