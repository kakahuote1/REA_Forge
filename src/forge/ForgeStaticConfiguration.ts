import { lstat } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { z } from "zod";

import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import type { ProviderAvailability } from "../application/AnalysisProvider.js";
import { readRegularFileText } from "../application/RegularFileRead.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import { jsonObjectSchema, type JsonValue } from "../domain/jsonValue.js";

export type ForgeStaticFamily =
  | "editor010"
  | "java"
  | "dotnet"
  | "cyberchef"
  | "capa"
  | "floss"
  | "api_hashes"
  | "enrichment"
  | "pcap"
  | "api_documents"
  | "traffic"
  | "xdis"
  | "python_legacy"
  | "pylingual"
  | "python_results"
  | "apk_workspace"
  | "smali"
  | "apk_signing"
  | "android_results"
  | "pe_parser"
  | "upx"
  | "pe_results"
  | "ldplayer"
  | "harmony_packages"
  | "abcde"
  | "ark_disasm"
  | "jadx_hap"
  | "hap_signing"
  | "hap_verification"
  | "harmony_results"
  | "system_informer"
  | "hollows_hunter"
  | "system_results"
  | "ida_host"
  | "ida_assembly"
  | "ida_exchange"
  | "ida_results";
export const FORGE_STATIC_CONFIG_SETTING = "REA_FORGE_STATIC_CONFIG";
export const FORGE_DATA_ROOT_SETTING = "REA_FORGE_DATA_ROOT";
const MAX_CONFIGURATION_BYTES = 64 * 1024;
const absolutePath = z
  .string()
  .min(1)
  .refine(isAbsolute, "requires an absolute path");
const selectionSchema = z.object({
  configurationPath: absolutePath,
  dataRoot: absolutePath,
});
const bootstrapSchema = z.object({ python_executable: absolutePath });
const pinSchema = z.object({
  path: absolutePath,
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
});

/** Explicit selectors, not a new tool registry or a checkout-derived configuration. */
export interface ForgeStaticConfiguration {
  readonly configurationPath: string;
  readonly dataRoot: string;
  readonly python: string;
  readonly document: Record<string, JsonValue>;
}

export const readForgeStaticConfiguration = async (
  environment: Readonly<NodeJS.ProcessEnv>,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<ForgeStaticConfiguration> => {
  if (signal?.aborted)
    throw new AnalysisCancelledError("forge:configuration", {
      cause: signal.reason,
    });
  const selection = selectionSchema.parse({
    configurationPath: environment[FORGE_STATIC_CONFIG_SETTING],
    dataRoot: environment[FORGE_DATA_ROOT_SETTING],
  });
  const text = await readRegularFileText(selection.configurationPath, {
    signal,
    resources,
    symlinks: "reject",
    admit: (state) => {
      if (state.size > MAX_CONFIGURATION_BYTES)
        throw new Error("Forge static configuration exceeds 64 KiB");
    },
    cancellationFailure: (reason) =>
      new AnalysisCancelledError("forge:configuration", { cause: reason }),
  });
  const document = jsonObjectSchema.parse(
    JSON.parse(text.replace(/^\uFEFF/u, "")),
  );
  const bootstrap = bootstrapSchema.parse(document);
  return { ...selection, python: bootstrap.python_executable, document };
};

const requirePath = async (path: string, directory = false): Promise<void> => {
  if (!isAbsolute(path))
    throw new Error("Configured engine paths must be absolute");
  const state = await lstat(path);
  if (
    state.isSymbolicLink() ||
    (directory ? !state.isDirectory() : !state.isFile())
  )
    throw new Error(
      "Configured engine entry is not a regular file or directory",
    );
};

/** File-presence readiness only: this never launches Python or an analysis engine. */
export const inspectForgeStaticConfiguration = async (
  family: ForgeStaticFamily,
  environment: Readonly<NodeJS.ProcessEnv>,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<ProviderAvailability> => {
  const diagnostics = {
    readiness_scope: "configuration-and-file-presence",
    engine_execution: "not_attempted",
    family,
  };
  if (
    environment[FORGE_STATIC_CONFIG_SETTING] === undefined ||
    environment[FORGE_DATA_ROOT_SETTING] === undefined
  )
    return {
      status: "unavailable",
      code: "not_configured",
      reason: `Set ${FORGE_STATIC_CONFIG_SETTING} and ${FORGE_DATA_ROOT_SETTING} to explicit absolute paths.`,
      diagnostics,
    };
  try {
    const config = await readForgeStaticConfiguration(
      environment,
      resources,
      signal,
    );
    await requirePath(config.python);
    await requirePath(config.dataRoot, true);
    const selected = config.document[family];
    if (selected === undefined)
      return {
        status: "unavailable",
        code: "not_configured",
        reason: `Configure the ${family} member of ${FORGE_STATIC_CONFIG_SETTING}.`,
        diagnostics,
      };
    const value = jsonObjectSchema.parse(selected);
    const roots = z.array(absolutePath).min(1).parse(value.input_roots);
    await Promise.all(roots.map((root) => requirePath(root, true)));
    if (family === "editor010") {
      await requirePath(absolutePath.parse(value.executable));
      z.string()
        .regex(/^[a-f0-9]{64}$/u)
        .parse(value.executable_sha256);
      const assets = z.array(absolutePath).min(1).parse(value.asset_roots);
      await Promise.all(assets.map((root) => requirePath(root, true)));
    } else if (family === "java") {
      await Promise.all(
        ["java", "javac", "javap", "recaf", "cfr", "vineflower", "bcv"].map(
          async (name) => {
            const pin = pinSchema.parse(value[name]);
            await requirePath(pin.path);
          },
        ),
      );
      await requirePath(join(config.dataRoot, "build/java/manifest.json"));
    } else if (family === "dotnet") {
      await Promise.all(
        [
          "build/dotnet/manifest.json",
          "build/dotnet/bin/REAForgeDnSpyWorker.dll",
          "runtime/dotnet5/dotnet.exe",
        ].map((relative) => requirePath(join(config.dataRoot, relative))),
      );
    } else if (
      family === "capa" ||
      family === "floss" ||
      family === "api_hashes" ||
      family === "upx"
    ) {
      const pin = pinSchema.parse(
        value[family === "api_hashes" ? "database" : "executable"],
      );
      await requirePath(pin.path);
      z.string().min(1).parse(value.version);
    } else if (family === "ida_host") {
      await Promise.all(
        ["python", "idalib", "idapro_entry", "idapro_config"].map(
          async (name) => requirePath(pinSchema.parse(value[name]).path),
        ),
      );
      await requirePath(absolutePath.parse(value.install_root), true);
      await requirePath(absolutePath.parse(value.api_source_root), true);
      z.string()
        .regex(/^[a-f0-9]{64}$/u)
        .parse(value.api_source_tree_sha256);
      await Promise.all(
        z
          .array(pinSchema)
          .min(1)
          .max(10)
          .parse(value.approved_plugins)
          .map(async (pin) => requirePath(pin.path)),
      );
      z.string().min(1).parse(value.version);
    } else if (family === "ida_assembly" || family === "ida_exchange") {
      if (family === "ida_assembly")
        await requirePath(pinSchema.parse(value.python).path);
      await requirePath(absolutePath.parse(value.api_source_root), true);
      z.string()
        .regex(/^[a-f0-9]{64}$/u)
        .parse(value.api_source_tree_sha256);
      z.string().min(1).parse(value.version);
    } else if (family === "ida_results") {
      z.string().min(1).parse(value.version);
    } else if (family === "system_informer" || family === "hollows_hunter") {
      await requirePath(pinSchema.parse(value.executable).path);
      z.string().min(1).parse(value.version);
      z.string()
        .regex(/^[a-f0-9]{40}$/u)
        .parse(value.source_commit);
    } else if (
      family === "harmony_packages" ||
      family === "harmony_results" ||
      family === "system_results"
    ) {
      z.string().min(1).parse(value.version);
    } else if (family === "ark_disasm") {
      await requirePath(pinSchema.parse(value.executable).path);
      z.string().min(1).parse(value.version);
    } else if (
      family === "abcde" ||
      family === "jadx_hap" ||
      family === "hap_signing" ||
      family === "hap_verification"
    ) {
      await Promise.all(
        [
          "java",
          "jar",
          ...(family === "abcde" ? ["reader"] : []),
          ...(family === "hap_signing" ? ["openssl"] : []),
        ].map(async (name) => requirePath(pinSchema.parse(value[name]).path)),
      );
      z.string().min(1).parse(value.version);
    } else if (family === "ldplayer") {
      await requirePath(pinSchema.parse(value.executable).path);
      await requirePath(absolutePath.parse(value.runtime_root), true);
      z.string().min(1).parse(value.version);
    } else if (family === "pe_parser") {
      await requirePath(pinSchema.parse(value.pefile).path);
      z.string().min(1).parse(value.version);
    } else if (family === "pcap") {
      const pin = pinSchema.parse(value.tshark);
      await requirePath(pin.path);
      z.string().min(1).parse(value.version);
    } else if (
      family === "apk_workspace" ||
      family === "smali" ||
      family === "apk_signing"
    ) {
      const names =
        family === "apk_workspace"
          ? ["java", "apktool"]
          : family === "smali"
            ? ["java", "smali", "baksmali"]
            : ["java", "keytool", "apksigner"];
      await Promise.all(
        names.map(async (name) =>
          requirePath(pinSchema.parse(value[name]).path),
        ),
      );
      z.string().min(1).parse(value.version);
    } else if (family === "xdis" || family === "python_legacy") {
      await requirePath(pinSchema.parse(value.python).path);
      const names =
        family === "xdis"
          ? ["xdis"]
          : ["xdis", "spark_parser", "uncompyle6", "decompyle3"];
      await Promise.all(
        names.map(async (name) => {
          const pin = pinSchema.parse(value[name]);
          await requirePath(pin.path, true);
        }),
      );
    } else if (family === "pylingual") {
      await requirePath(pinSchema.parse(value.python).path);
      await requirePath(pinSchema.parse(value.models_manifest).path);
      await requirePath(absolutePath.parse(value.root), true);
    } else if (family === "cyberchef") {
      const node = pinSchema.parse(value.node);
      const root = absolutePath.parse(value.root);
      await requirePath(node.path);
      await requirePath(join(root, "package-lock.json"));
      await requirePath(
        join(config.dataRoot, "config/cyberchef-entrypoints.json"),
      );
    }
    signal?.throwIfAborted();
    return {
      status: "available",
      code: null,
      reason: null,
      diagnostics: {
        ...diagnostics,
        configuration_path: config.configurationPath,
        data_root: config.dataRoot,
      },
    };
  } catch (cause) {
    if (cause instanceof AnalysisCancelledError) throw cause;
    if (signal?.aborted)
      throw new AnalysisCancelledError("forge:configuration", {
        cause: signal.reason,
      });
    return {
      status: "unavailable",
      code: "runtime_unavailable",
      reason: `Repair ${family} configuration or required files selected by ${FORGE_STATIC_CONFIG_SETTING}.`,
      diagnostics: {
        ...diagnostics,
        failure: cause instanceof Error ? cause.message : String(cause),
      },
    };
  }
};
