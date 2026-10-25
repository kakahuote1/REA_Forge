import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import {
  androidBuildInputs,
  androidBuildReportSchema,
  type ForgeAndroidBuildOperation,
} from "../../domain/forge/androidBuild.js";
const descriptions = {
  forge_prepare_android_project:
    "Create a retained full apktool project from an explicit local APK, or import a copied snapshot of an existing decoded project. Keeps Smali/manifest/resources, complete bounded tree identities and paged files for subsequent builds. Does not alter the source, user GUI/cache or a device. Native decode_android_resources remains the quick resources-only reader.",
  forge_build_android_project:
    "Build a new unsigned APK from a digest-bound retained apktool project. Optional exact expected-hash text changes apply only to a fresh project copy and retain diffs; ambiguous/stale edits fail. Returns the new project receipt and APK identities. It does not modify the original APK, execute it or install packages. Use forge_sign_apk and cryptographic verification afterward.",
  forge_disassemble_dex:
    "Disassemble a standard DEX or one explicitly selected classes DEX in an APK with pinned baksmali. Retains a bounded source tree and DEX header/digest observations. Does not execute Android code or launch a GUI/device. Supports exact multidex names; no arbitrary ZIP member or native command selection.",
  forge_assemble_dex:
    "Assemble a new DEX from an explicit local Smali source directory or a digest-bound retained Smali/apktool project. Optional expected-hash text changes apply to a fresh copy, with retained diffs. Select a bounded API level and Smali subdirectory. Reread the resulting bytes/disassembly to verify the actual change; no Android execution or device installation.",
  forge_sign_apk:
    "Sign a copied APK, then require real apksigner cryptographic verification. Select a configured private signing profile or create/reuse an owned public-password test key. Passwords are selected from operator files, not MCP arguments or evidence. Returns signed APK/certificate identities and a reusable test-key receipt when applicable; never modifies a borrowed key, installs a CA or touches a device.",
  forge_verify_apk:
    "Cryptographically verify an explicit APK with pinned apksigner. Reports verified, invalid or indeterminate with actual exit evidence and certificate/scheme observations; never treats parsed declarations alone as authenticity. Native inspect_apk_signature remains useful for scheme/lineage structure. No target execution, device or trust-store changes.",
  forge_read_android_result:
    "Read a page of a retained project, an exact selected project file window, or artifact bytes using the returned receipt digest. Revalidates project/selected artifact identity. Artifact 0 is receipt JSON; following indices select declared APK/DEX/diff files, never private keystore/password bytes. Returns exact Base64 and UTF8 only when the selected byte window decodes without replacement. No engine rerun.",
};
const receipt = {
  receipt_path: "C:/work/android/receipt.json",
  receipt_sha256: "0".repeat(64),
};
const examples = {
  forge_prepare_android_project: { path: "C:/analysis/app.apk" },
  forge_build_android_project: receipt,
  forge_disassemble_dex: {
    path: "C:/analysis/app.apk",
    dex_entry: "classes.dex",
  },
  forge_assemble_dex: receipt,
  forge_sign_apk: { path: "C:/analysis/unsigned.apk", profile: "test" },
  forge_verify_apk: { path: "C:/analysis/signed.apk" },
  forge_read_android_result: receipt,
} as const;
const contract = <Name extends ForgeAndroidBuildOperation>(name: Name) =>
  ({
    name,
    ...toolContractMetadata(name),
    kind: "forge-static-provider",
    description: descriptions[name],
    inputSchema: androidBuildInputs[name],
    outputSchema: evidenceResultOf(androidBuildReportSchema),
    examples: [
      {
        title: "Inspect or derive selected Android work",
        input: examples[name],
      },
    ],
  }) as const satisfies ToolContract;
export const FORGE_ANDROID_BUILD_TOOL_CONTRACTS = [
  contract("forge_prepare_android_project"),
  contract("forge_build_android_project"),
  contract("forge_disassemble_dex"),
  contract("forge_assemble_dex"),
  contract("forge_sign_apk"),
  contract("forge_verify_apk"),
  contract("forge_read_android_result"),
] as const;
