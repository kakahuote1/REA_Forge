import { expect, it, vi } from "vitest";
import { HarmonyStaticService } from "./HarmonyStaticService.js";
import {
  FORGE_HARMONY_OPERATIONS,
  harmonyFamilyFor,
  type ForgeHarmonyOperation,
  type HarmonyStaticReport,
} from "../../domain/forge/harmonyStatic.js";
import type { ForgeStaticAnalysisPort } from "./ForgeStaticAnalysisPort.js";
import { ok } from "../../domain/result.js";
const target = {
  path: "C:/analysis/sample.hap",
  sha256: "a".repeat(64),
  size_bytes: 2048,
};
const reference = {
  receipt_path: "C:/work/receipt.json",
  receipt_sha256: "b".repeat(64),
};
const report = (operation: ForgeHarmonyOperation): HarmonyStaticReport => ({
  operation,
  target,
  result: {},
  workspace: "C:/work/harmony",
  sample_execution: false,
  network_used: false,
});
const fixture = () => {
  const port = () => ({
    execute: vi.fn<
      ForgeStaticAnalysisPort<
        ForgeHarmonyOperation,
        HarmonyStaticReport
      >["execute"]
    >(async (operation) => ok(report(operation))),
    inspectAvailability: vi.fn<
      ForgeStaticAnalysisPort<
        ForgeHarmonyOperation,
        HarmonyStaticReport
      >["inspectAvailability"]
    >(async () => ({
      status: "available",
      code: null,
      reason: null,
      diagnostics: {},
    })),
    close: vi.fn(async () => undefined),
  });
  const ports = {
    harmony_packages: port(),
    abcde: port(),
    ark_disasm: port(),
    jadx_hap: port(),
    hap_signing: port(),
    hap_verification: port(),
    harmony_results: port(),
  };
  return { ports, service: new HarmonyStaticService(ports) };
};
const inputFor = (name: ForgeHarmonyOperation) =>
  name === "forge_read_harmony_result"
    ? reference
    : name === "forge_render_abc_method"
      ? { path: target.path, method_offset: 123 }
      : { path: target.path };
it.each(FORGE_HARMONY_OPERATIONS)(
  "routes %s through the exact native static owner",
  async (operation) => {
    const { service, ports } = fixture();
    expect((await service.execute(operation, inputFor(operation))).ok).toBe(
      true,
    );
    for (const [family, port] of Object.entries(ports))
      expect(port.execute).toHaveBeenCalledTimes(
        family === harmonyFamilyFor[operation] ? 1 : 0,
      );
    await service.close();
  },
);
it.each([
  ["forge_inspect_hap", { path: "https://example.test/input.hap" }],
  ["forge_inspect_hap", { path: target.path, output_path: "C:/borrowed" }],
  ["forge_inspect_abc", { path: target.path, action: "execute" }],
  ["forge_inspect_abc", { path: target.path, class_name: "arbitrary.Main" }],
  ["forge_render_abc_method", { path: target.path, method_offset: -1 }],
  ["forge_render_abc_method", { path: target.path, method_offset: 2147483648 }],
  ["forge_render_abc_method", { path: target.path, method_offset: "1;exec()" }],
  ["forge_sign_hap", { path: target.path, password: "not-a-tool-argument" }],
  ["forge_sign_hap", { path: target.path, mode: "remote" }],
  ["forge_decompile_hap", { path: target.path, timeout_ms: 45001 }],
  ["forge_read_harmony_result", { ...reference, byte_count: 65537 }],
  ["forge_read_harmony_result", { ...reference, line_count: 101 }],
] as const)(
  "rejects expanded or malformed %s authority before dispatch",
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
it("isolates absent decompilers from package, official disassembly and signature readers", async () => {
  const { service, ports } = fixture();
  ports.jadx_hap.inspectAvailability.mockResolvedValueOnce({
    status: "unavailable",
    code: "not_configured",
    reason: "absent",
    diagnostics: {},
  });
  const available = await service.inspectAvailability();
  for (const name of FORGE_HARMONY_OPERATIONS)
    expect(available[name]?.status).toBe(
      harmonyFamilyFor[name] === "jadx_hap" ? "unavailable" : "available",
    );
  await service.close();
});
it("preserves early and late cancellation, closes peers, and retains failed cleanup for retry", async () => {
  const { service, ports } = fixture();
  const early = new AbortController();
  early.abort();
  expect(
    await service.execute("forge_inspect_hap", inputFor("forge_inspect_hap"), {
      signal: early.signal,
    }),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
  expect(ports.harmony_packages.execute).not.toHaveBeenCalled();
  const late = new AbortController();
  ports.harmony_packages.execute.mockImplementationOnce(async (operation) => {
    late.abort();
    return ok(report(operation));
  });
  expect(
    await service.execute("forge_inspect_hap", inputFor("forge_inspect_hap"), {
      signal: late.signal,
    }),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
  ports.abcde.close.mockRejectedValueOnce(new Error("retained owner"));
  await expect(service.close()).rejects.toThrow("incomplete cleanup");
  for (const port of Object.values(ports))
    expect(port.close).toHaveBeenCalledOnce();
  await service.close();
});
