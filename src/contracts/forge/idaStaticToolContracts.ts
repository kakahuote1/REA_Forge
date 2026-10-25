import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";
import {
  type ForgeIdaOperation,
  idaStaticInputs,
  idaStaticReportSchema,
} from "../../domain/forge/idaStatic.js";
const descriptions = {
  forge_edit_ida_database:
    "Edit only a new work-IDB copy: typed rename/comment/prototype/declaration/enum, exact-preimage byte or Keystone assembly patches, undefine/code/data definitions. Preserve original input; retain before/database.i64 plus direct readback. No target process, original EXE patch, borrowed GUI save, caller save path, debugger or plugin selector. Includes no preprocessor/external include surface.",
  forge_run_ida_safe_python:
    "Run the existing bounded static-IDB Python facade on a fresh work copy: JSON locals, conditions, budgeted loops, db.functions/lookup/rename/comment/set_type/save/status only. Not raw IDAPython: imports, reflection, file/process/network/debugger/plugin access are absent. Persist before/after IDBs; no implicit fallback if facade rejects code. Application controls are not an OS sandbox.",
  forge_scan_ida_crypto:
    "Scan the mapped work-IDB with pinned FindCrypt3/YARA data and bounded encoded references/optional pseudocode review. Fixed offline engine; no user rule/executable path, target execution or original plugin. Matches remain candidates, not algorithm/key/IV proof. Preserve original input and retain full results.",
  forge_ida_enum:
    "Preview pinned AutoEnum data against observed imports or explicit API names. Empty enum_names is read-only; explicit1–8 selections are checked against a fresh current preview before creating collision-safe namespaced types in a new IDB copy. No GUI plugin, automatic function type replacement or unselected enum apply. Before/after database files support exact snapshot recovery.",
  forge_ida_struct_typer:
    "Preview FLARE-style function-pointer type candidates for an existing named UDT. Empty member_names does not apply changes; explicit1–8 members must match a fresh complete UDT fingerprint before changes in a new IDB copy. Fixed library semantics, no original plugin/regex/GUI selection. Retain before/after IDBs; use digest-bound restore for whole-copy reversal.",
  forge_snapshot_ida_database:
    "Create a bounded function exchange snapshot from a new work IDB: names, bytes/mnemonics/CFG signatures with explicit per-function limits. No BinExport/BinDiff DLL or target execution. Reuse native REA IDA provider for ordinary function, xref and decompiler questions; this additional format supports separate retained comparisons.",
  forge_export_ida_data:
    "Read1–4096 mapped work-IDB bytes and format as integer/string/hex text, C or Python literals through the existing data-export library. No file path, clipboard, expression evaluation or original plugin argument. Result text is data, not executed code.",
  forge_assemble_ida:
    "Use pinned local Keystone for explicit architecture/origin and bounded assembly text without initializing IDA. Returns exact encoding, never executes it. No target, shell, custom executable or plugin; invoke typed work-IDB patches separately with exact preimage.",
  forge_compare_ida_snapshots:
    "Compare two retained function snapshots through the existing offline exchange matcher: symbol, byte, normalized instruction and CFG-shape candidates. Preserve full comparison metadata. Not official BinDiff heuristics or semantic-equivalence proof, and snapshots are not current database state.",
  forge_restore_ida_database:
    "Derive a new restored IDB from a retained before-snapshot only after authenticating receipt, current database digest and backup digest. Does not overwrite the current IDB, original EXE or user database. Whole-copy reversal is separate from arbitrary original-plugin revert tokens.",
  forge_read_ida_result:
    "Authenticate a retained static IDA receipt/full result and read selected metadata or exact bounded artifact bytes. Artifact index0 is full JSON;1+ follow artifact list. Before/after IDBs remain available for independent reopening. Historical hashes do not establish current input freshness; this does not launch an IDA engine.",
} as const;
const inputExample = (name: ForgeIdaOperation) => {
  const reference = {
    receipt_path: "/work/receipt.json",
    receipt_sha256: "a".repeat(64),
  };
  switch (name) {
    case "forge_edit_ida_database":
      return {
        path: "/targets/test.exe",
        edits: [
          {
            action: "comment",
            address: "0x401000",
            text: "reviewed static entry",
          },
        ],
      };
    case "forge_run_ida_safe_python":
      return {
        path: "/targets/test.exe",
        code: "result = db.functions(limit=8)",
      };
    case "forge_ida_enum":
      return { path: "/targets/test.exe", platform: "windows" };
    case "forge_ida_struct_typer":
      return { path: "/targets/test.i64", struct_name: "ApiTable" };
    case "forge_export_ida_data":
      return {
        path: "/targets/test.exe",
        address: "0x401000",
        length: 16,
        data_kind: "u8",
        render: "c",
      };
    case "forge_assemble_ida":
      return { architecture: "x64", assembly: "nop" };
    case "forge_compare_ida_snapshots":
      return { before: reference, after: reference };
    case "forge_restore_ida_database":
      return { ...reference, expected_database_sha256: "b".repeat(64) };
    case "forge_read_ida_result":
      return reference;
    default:
      return { path: "/targets/test.exe" };
  }
};
const contract = <Name extends ForgeIdaOperation>(name: Name) =>
  ({
    name,
    ...toolContractMetadata(name),
    kind: "forge-static-provider" as const,
    description: descriptions[name],
    inputSchema: idaStaticInputs[name],
    outputSchema: evidenceResultOf(idaStaticReportSchema),
    examples: [
      {
        title: "Use an explicit static work copy or retained result",
        input: inputExample(name),
      },
    ],
  }) as const satisfies ToolContract;
export const FORGE_IDA_TOOL_CONTRACTS = [
  contract("forge_edit_ida_database"),
  contract("forge_run_ida_safe_python"),
  contract("forge_scan_ida_crypto"),
  contract("forge_ida_enum"),
  contract("forge_ida_struct_typer"),
  contract("forge_snapshot_ida_database"),
  contract("forge_export_ida_data"),
  contract("forge_assemble_ida"),
  contract("forge_compare_ida_snapshots"),
  contract("forge_restore_ida_database"),
  contract("forge_read_ida_result"),
] as const;
