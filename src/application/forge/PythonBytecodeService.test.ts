import { expect, it, vi } from "vitest";
import { PythonBytecodeService } from "./PythonBytecodeService.js";
import {
  FORGE_PYTHON_OPERATIONS,
  pythonFamilyFor,
  type ForgePythonOperation,
  type PythonBytecodeReport,
} from "../../domain/forge/pythonBytecode.js";
import type { ForgeStaticAnalysisPort } from "./ForgeStaticAnalysisPort.js";
import { ok } from "../../domain/result.js";
const target = {
  path: "C:/analysis/module.pyc",
  sha256: "a".repeat(64),
  size_bytes: 500,
};
const report = (operation: ForgePythonOperation): PythonBytecodeReport => ({
  operation,
  target,
  result: { analysis_status: "decompiled" },
  workspace: "C:/work/python",
  sample_execution: false,
  network_used: false,
});
const fixture = () => {
  const port = () => ({
    execute: vi.fn<
      ForgeStaticAnalysisPort<
        ForgePythonOperation,
        PythonBytecodeReport
      >["execute"]
    >(async (operation) => ok(report(operation))),
    inspectAvailability: vi.fn<
      ForgeStaticAnalysisPort<
        ForgePythonOperation,
        PythonBytecodeReport
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
    xdis: port(),
    python_legacy: port(),
    pylingual: port(),
    python_results: port(),
  };
  return { ports, service: new PythonBytecodeService(ports) };
};
const inputs = {
  forge_disassemble_python: { path: target.path },
  forge_decompile_legacy_python: { path: target.path },
  forge_decompile_modern_python: { path: target.path },
  forge_read_python_result: {
    receipt_path: "C:/work/python/receipt.json",
    receipt_sha256: "b".repeat(64),
  },
};
it.each(FORGE_PYTHON_OPERATIONS)(
  "routes %s to its configured owner without a binary session",
  async (operation) => {
    const { service, ports } = fixture();
    expect((await service.execute(operation, inputs[operation])).ok).toBe(true);
    for (const [family, port] of Object.entries(ports))
      expect(port.execute).toHaveBeenCalledTimes(
        family === pythonFamilyFor[operation] ? 1 : 0,
      );
    await service.close();
  },
);
it.each([
  ["forge_disassemble_python", { path: "https://example.test/module.pyc" }],
  ["forge_disassemble_python", { path: target.path, format: "execute" }],
  ["forge_disassemble_python", { path: target.path, script: "import os" }],
  ["forge_decompile_legacy_python", { path: target.path, engine: "pylingual" }],
  [
    "forge_decompile_modern_python",
    { path: target.path, python: "C:/caller.exe" },
  ],
  ["forge_decompile_modern_python", { path: target.path, timeout_ms: 112001 }],
  [
    "forge_read_python_result",
    { receipt_path: target.path, receipt_sha256: "invalid" },
  ],
] as const)(
  "refuses expanded authority or malformed %s arguments",
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
it("keeps a missing model independent from legacy, xdis and readback", async () => {
  const { service, ports } = fixture();
  ports.pylingual.inspectAvailability.mockResolvedValueOnce({
    status: "unavailable",
    code: "not_configured",
    reason: "fixture no models",
    diagnostics: {},
  });
  const availability = await service.inspectAvailability();
  for (const name of FORGE_PYTHON_OPERATIONS)
    expect(availability[name]?.status).toBe(
      name === "forge_decompile_modern_python" ? "unavailable" : "available",
    );
  await service.close();
});
it("preserves pre-dispatch and late cancellation", async () => {
  const { service, ports } = fixture();
  const controller = new AbortController();
  controller.abort("stopped");
  expect(
    await service.execute(
      "forge_disassemble_python",
      inputs.forge_disassemble_python,
      { signal: controller.signal },
    ),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
  expect(ports.xdis.execute).not.toHaveBeenCalled();
  const late = new AbortController();
  ports.xdis.execute.mockImplementationOnce(async (operation) => {
    late.abort("late cancellation");
    return ok(report(operation));
  });
  expect(
    await service.execute(
      "forge_disassemble_python",
      inputs.forge_disassemble_python,
      { signal: late.signal },
    ),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
  await service.close();
});
it("closes peer owners and retains cleanup failure for retry", async () => {
  const { service, ports } = fixture();
  ports.pylingual.close.mockRejectedValueOnce(
    new Error("retained native family"),
  );
  await expect(service.close()).rejects.toThrow("incomplete cleanup");
  for (const port of Object.values(ports))
    expect(port.close).toHaveBeenCalledTimes(1);
  await service.close();
});
