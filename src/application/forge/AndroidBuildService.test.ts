import { expect, it, vi } from "vitest";
import { AndroidBuildService } from "./AndroidBuildService.js";
import {
  FORGE_ANDROID_BUILD_OPERATIONS,
  androidBuildFamilyFor,
  type ForgeAndroidBuildOperation,
  type AndroidBuildReport,
} from "../../domain/forge/androidBuild.js";
import type { ForgeStaticAnalysisPort } from "./ForgeStaticAnalysisPort.js";
import { ok } from "../../domain/result.js";
const target = {
  path: "C:/analysis/test.apk",
  sha256: "a".repeat(64),
  size_bytes: 500,
  kind: "file" as const,
};
const reference = {
  receipt_path: "C:/work/receipt.json",
  receipt_sha256: "b".repeat(64),
};
const report = (operation: ForgeAndroidBuildOperation): AndroidBuildReport => ({
  operation,
  target,
  result: {},
  workspace: "C:/work/android",
  sample_execution: false,
  network_used: false,
});
const fixture = () => {
  const port = () => ({
    execute: vi.fn<
      ForgeStaticAnalysisPort<
        ForgeAndroidBuildOperation,
        AndroidBuildReport
      >["execute"]
    >(async (operation) => ok(report(operation))),
    inspectAvailability: vi.fn<
      ForgeStaticAnalysisPort<
        ForgeAndroidBuildOperation,
        AndroidBuildReport
      >["inspectAvailability"]
    >(async () => ({
      status: "available",
      code: null,
      reason: null,
      diagnostics: {},
    })),
    close: vi.fn(async () => {}),
  });
  const ports = {
    apk_workspace: port(),
    smali: port(),
    apk_signing: port(),
    android_results: port(),
  };
  return { ports, service: new AndroidBuildService(ports) };
};
const inputs = {
  forge_prepare_android_project: { path: target.path },
  forge_build_android_project: reference,
  forge_disassemble_dex: { path: target.path },
  forge_assemble_dex: { source_directory: "C:/source/smali" },
  forge_sign_apk: { path: target.path },
  forge_verify_apk: { path: target.path },
  forge_read_android_result: reference,
};
it.each(FORGE_ANDROID_BUILD_OPERATIONS)(
  "routes %s through its native owner",
  async (operation) => {
    const { service, ports } = fixture();
    expect((await service.execute(operation, inputs[operation])).ok).toBe(true);
    for (const [family, port] of Object.entries(ports))
      expect(port.execute).toHaveBeenCalledTimes(
        family === androidBuildFamilyFor[operation] ? 1 : 0,
      );
    await service.close();
  },
);
it.each([
  ["forge_prepare_android_project", { path: "https://example.test/a.apk" }],
  ["forge_prepare_android_project", { path: target.path, script: "run" }],
  ["forge_disassemble_dex", { path: target.path, dex_entry: "../classes.dex" }],
  [
    "forge_build_android_project",
    {
      ...reference,
      changes: [
        {
          relative_path: "../a.smali",
          expected_sha256: target.sha256,
          old_text: "a",
          new_text: "b",
        },
      ],
    },
  ],
  [
    "forge_build_android_project",
    {
      ...reference,
      changes: [
        {
          relative_path: "a.smali",
          expected_sha256: target.sha256,
          old_text: "a",
          new_text: "a",
        },
      ],
    },
  ],
  ["forge_assemble_dex", { source_directory: "C:/source", ...reference }],
  ["forge_assemble_dex", { ...reference, api_level: 0 }],
  ["forge_sign_apk", { path: target.path, password: "not-a-tool-argument" }],
  [
    "forge_sign_apk",
    { path: target.path, key_receipt_path: reference.receipt_path },
  ],
  [
    "forge_sign_apk",
    {
      path: target.path,
      profile: "production",
      key_receipt_path: reference.receipt_path,
      key_receipt_sha256: reference.receipt_sha256,
    },
  ],
  ["forge_verify_apk", { path: target.path, timeout_ms: 45001 }],
  [
    "forge_read_android_result",
    { ...reference, relative_path: "a", artifact_index: 1 },
  ],
  ["forge_read_android_result", { ...reference, byte_count: 65537 }],
] as const)(
  "rejects malformed or expanded %s authority",
  async (operation, input) => {
    const { service, ports } = fixture();
    expect(await service.execute(operation, input)).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
    for (const port of Object.values(ports))
      expect(port.execute).not.toHaveBeenCalled();
    await service.close();
  },
);
it("keeps a missing signer independent from decode and DEX analysis", async () => {
  const { service, ports } = fixture();
  ports.apk_signing.inspectAvailability.mockResolvedValueOnce({
    status: "unavailable",
    code: "not_configured",
    reason: "no signer",
    diagnostics: {},
  });
  const values = await service.inspectAvailability();
  for (const name of FORGE_ANDROID_BUILD_OPERATIONS)
    expect(values[name]?.status).toBe(
      androidBuildFamilyFor[name] === "apk_signing"
        ? "unavailable"
        : "available",
    );
  await service.close();
});
it("preserves pre-dispatch and late cancellation", async () => {
  const { service, ports } = fixture();
  const early = new AbortController();
  early.abort("early");
  expect(
    await service.execute(
      "forge_prepare_android_project",
      inputs.forge_prepare_android_project,
      { signal: early.signal },
    ),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
  expect(ports.apk_workspace.execute).not.toHaveBeenCalled();
  const late = new AbortController();
  ports.apk_workspace.execute.mockImplementationOnce(async (operation) => {
    late.abort("late");
    return ok(report(operation));
  });
  expect(
    await service.execute(
      "forge_prepare_android_project",
      inputs.forge_prepare_android_project,
      { signal: late.signal },
    ),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
  await service.close();
});
it("settles peers and retains failed cleanup for retry", async () => {
  const { service, ports } = fixture();
  ports.smali.close.mockRejectedValueOnce(new Error("owned process retained"));
  await expect(service.close()).rejects.toThrow("incomplete cleanup");
  for (const port of Object.values(ports))
    expect(port.close).toHaveBeenCalledTimes(1);
  await service.close();
});
