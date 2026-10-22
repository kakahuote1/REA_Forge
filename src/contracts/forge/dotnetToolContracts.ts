import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import {
  dotnetInputSchemas,
  dotnetReportSchema,
  type ForgeDotnetOperation,
} from "../../domain/forge/dotnetAnalysis.js";

const descriptions: Record<ForgeDotnetOperation, string> = {
  forge_inspect_dotnet:
    "Read selected local .NET assembly types, metadata or resources with dnSpy/dnlib. Type facts include tokens, signatures, attributes and bounded IL/operands; pages explicitly report truncation. Never loads the target into the CLR for execution.",
  forge_decompile_dotnet:
    "Render one exact metadata type token using dnSpy's installed C#, Visual Basic or IL decompiler. Source is an engine rendering, not original source or proof of equivalent behavior. Does not execute target code.",
  forge_read_dotnet_resource:
    "Read one named embedded .NET resource, returning bytes as Base64 and its hash. Resources are data only, never deserialized as runtime objects.",
  forge_edit_dotnet:
    "Write a new derived .NET file with typed dnSpy actions: rename type/method/field/property/event; change signature/field/property type; replace custom attributes/resource/IL body; change assembly identity; replace one IL instruction by NOP. Original stays unchanged. Returns output identity and fresh metadata/type readback; not a guarantee of valid IL, retained strong-name signature or runtime correctness.",
  forge_compile_dotnet:
    "Compile one local C# source with fixed Roslyn references and optional embedded bytes, then re-read the derived assembly. No analyzer, source generator, target execution or custom MSBuild project is accepted. Does not sign assemblies or automatically repair assembly references.",
};
const path = "C:/analysis/example.dll";
const examples = {
  forge_inspect_dotnet: { path, view: "types" },
  forge_decompile_dotnet: { path, type_token: 33554434, language: "C#" },
  forge_read_dotnet_resource: { path, resource_name: "example.txt" },
  forge_edit_dotnet: {
    path,
    action: "rename_type",
    type_token: 33554434,
    new_name: "Renamed",
    output_name: "renamed.dll",
  },
  forge_compile_dotnet: {
    source_path: "C:/analysis/Program.cs",
    output_name: "compiled.dll",
  },
} as const;
const contract = <Name extends ForgeDotnetOperation>(name: Name) =>
  ({
    name,
    ...toolContractMetadata(name),
    kind: "artifact-provider",
    description: descriptions[name],
    inputSchema: dotnetInputSchemas[name],
    outputSchema: evidenceResultOf(dotnetReportSchema),
    examples: [
      {
        title: "Use an admitted local assembly and its observed token",
        input: examples[name],
      },
    ],
  }) as const satisfies ToolContract;
export const FORGE_DOTNET_TOOL_CONTRACTS = [
  contract("forge_inspect_dotnet"),
  contract("forge_decompile_dotnet"),
  contract("forge_read_dotnet_resource"),
  contract("forge_edit_dotnet"),
  contract("forge_compile_dotnet"),
] as const;
