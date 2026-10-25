import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import {
  javaInputSchemas,
  javaReportSchema,
  type ForgeJavaOperation,
} from "../../domain/forge/javaAnalysis.js";

const descriptions: Record<ForgeJavaOperation, string> = {
  forge_inspect_java:
    "Inspect JVM classes/members and classfile facts using Recaf core APIs. Accepts one local class/JAR/WAR, preserves original identity and never runs its classes.",
  forge_decompile_java:
    "Render one selected JVM class with an explicit engine: standalone Vineflower/CFR, Bytecode Viewer Procyon/JD-Core, or Recaf's CFR/Vineflower. Returns source text, exact engine/input identities and retained output. Different engines are alternatives, not consensus or proof of source equivalence.",
  forge_disassemble_java:
    "Read bytecode facts with javap verbose/code/private/signatures/constants, Recaf ASM, or Bytecode Viewer textifier/ASMifier. This does not execute the selected target class.",
  forge_search_java:
    "Search bounded Recaf class/member names, string constants and references. Returns observed matches; not runtime reachability.",
  forge_java_call_graph:
    "Inspect bytecode call references for one exact class/method/descriptor with Recaf. Static references are not a complete reflection/dynamic dispatch graph.",
  forge_edit_java:
    "Create one derived Java artifact with a typed Recaf action: rename class/method/field, remove dead code/duplicate annotations, export class, compile single/multiple Java sources, or assemble a selected class. Never overwrites originals. Compilation disables annotation processing and never runs compiled classes; output is re-read by the engine.",
  forge_compare_java:
    "Compare two selected JVM artifacts through Recaf class/member/bytecode facts, retaining both exact input identities without modifying originals.",
};
const path = "C:/analysis/input.jar";
const examples = {
  forge_inspect_java: { path },
  forge_decompile_java: {
    path,
    class_name: "example/Main",
    engine: "vineflower",
  },
  forge_disassemble_java: { path, class_name: "example/Main", engine: "javap" },
  forge_search_java: { path, query: "Main", kind: "class_name" },
  forge_java_call_graph: {
    path,
    class_name: "example/Main",
    method_name: "main",
    descriptor: "([Ljava/lang/String;)V",
  },
  forge_edit_java: {
    path,
    action: "rename_class",
    class_name: "example/Main",
    new_class_name: "example/Renamed",
    output_name: "renamed.jar",
  },
  forge_compare_java: { path, right_path: "C:/analysis/other.jar" },
} as const;
const contract = <Name extends ForgeJavaOperation>(name: Name) =>
  ({
    name,
    ...toolContractMetadata(name),
    kind: "forge-static-provider",
    description: descriptions[name],
    inputSchema: javaInputSchemas[name],
    outputSchema: evidenceResultOf(javaReportSchema),
    examples: [
      {
        title: "Use actual local artifact and JVM internal class name",
        input: examples[name],
      },
    ],
  }) as const satisfies ToolContract;
export const FORGE_JAVA_TOOL_CONTRACTS = [
  contract("forge_inspect_java"),
  contract("forge_decompile_java"),
  contract("forge_disassemble_java"),
  contract("forge_search_java"),
  contract("forge_java_call_graph"),
  contract("forge_edit_java"),
  contract("forge_compare_java"),
] as const;
