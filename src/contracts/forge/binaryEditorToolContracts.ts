import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import {
  binaryEditorInputSchemas,
  binaryEditorReportSchema,
  type ForgeBinaryEditorOperation,
} from "../../domain/forge/binaryEditor.js";

const descriptions: Record<ForgeBinaryEditorOperation, string> = {
  forge_inspect_binary_structure:
    "Inspect a selected file using a reviewed or statically constrained 010 Editor template in no-UI mode. Returns native CSV fields and offsets, exact input/template identities, retained export path/digest and truthful parse extent. Does not imply semantic validation or complete parsing. Never runs the target file.",
  forge_read_binary_bytes:
    "Read a bounded byte range from an identity-checked working copy. Returns hexadecimal and decoded text with file identity; no target execution or network.",
  forge_search_binary_bytes:
    "Search selected binary bytes for an exact hexadecimal sequence. Returns offsets and explicit truncation; no regular-expression or executable input.",
  forge_compare_binary_files:
    "Compare two selected files through fixed no-UI 010 invocation and independent byte facts. Reports exact identities, equality, size delta and first differing offset; originals are preserved.",
  forge_edit_binary_copy:
    "Create a derived non-PE binary by replacing one byte range. Original stays unchanged; output identity and derivation are recorded. An empty insert_hex performs pure deletion. PE mutation remains a separate IDA workflow.",
  forge_edit_binary_in_place:
    "Explicitly modify one selected non-PE file only when expected_sha256 still matches. Creates a verified backup and durable before/after provenance before reporting success. This changes the selected original; prefer forge_edit_binary_copy for derived edits.",
  forge_run_binary_script:
    "Run a statically constrained 010 script against a private non-PE working copy with fixed no-UI invocation. External file/process/network/configuration APIs are rejected. This is not arbitrary-script isolation; original input remains unchanged.",
  forge_list_binary_assets:
    "List installed 010 templates or scripts and separately reviewed local templates by exact file identity. Listing does not approve arbitrary assets for execution or change the GUI.",
  forge_restore_binary_backup:
    "Restore one recorded 010 edit backup only after current target digest and producing edit provenance match. Preserves a new recovery backup of the replaced bytes; cannot restore an unrelated file or change a PE target.",
  forge_read_binary_template_rows:
    "Page or filter an unchanged retained 010 CSV export without rerunning the editor. Requires exact export digest and its native producing receipt; rejects unrelated, changed or out-of-workspace CSV files.",
};

const file = "C:/fixtures/input.bin";
const sha256 = "0".repeat(64);
const examples = {
  forge_inspect_binary_structure: {
    path: file,
    template_path: "C:/templates/header.bt",
  },
  forge_read_binary_bytes: { path: file, offset: 0, length: 32 },
  forge_search_binary_bytes: { path: file, needle_hex: "41424344" },
  forge_compare_binary_files: {
    path: file,
    right_path: "C:/fixtures/other.bin",
  },
  forge_edit_binary_copy: {
    path: file,
    offset: 8,
    delete_length: 1,
    insert_hex: "5a",
  },
  forge_edit_binary_in_place: {
    path: file,
    expected_sha256: sha256,
    offset: 8,
    delete_length: 1,
    insert_hex: "5a",
  },
  forge_run_binary_script: { path: file, script_path: "C:/scripts/patch.1sc" },
  forge_list_binary_assets: { kind: "template" },
  forge_restore_binary_backup: {
    path: file,
    backup_path: "C:/work/backups/input.bak",
    expected_sha256: sha256,
  },
  forge_read_binary_template_rows: {
    csv_path: "C:/work/outputs/header.csv",
    csv_sha256: sha256,
  },
} as const;

const contract = <Name extends ForgeBinaryEditorOperation>(name: Name) =>
  ({
    name,
    ...toolContractMetadata(name),
    kind: "artifact-provider",
    description: descriptions[name],
    inputSchema: binaryEditorInputSchemas[name],
    outputSchema: evidenceResultOf(binaryEditorReportSchema),
    examples: [
      {
        title: "Use operator-configured local paths and observed digests",
        input: examples[name],
      },
    ],
  }) as const satisfies ToolContract;

export const FORGE_BINARY_EDITOR_TOOL_CONTRACTS = [
  contract("forge_inspect_binary_structure"),
  contract("forge_read_binary_bytes"),
  contract("forge_search_binary_bytes"),
  contract("forge_compare_binary_files"),
  contract("forge_edit_binary_copy"),
  contract("forge_edit_binary_in_place"),
  contract("forge_run_binary_script"),
  contract("forge_list_binary_assets"),
  contract("forge_restore_binary_backup"),
  contract("forge_read_binary_template_rows"),
] as const;
