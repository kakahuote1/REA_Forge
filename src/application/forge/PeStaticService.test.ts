import { expect, it, vi } from "vitest";
import { PeStaticService } from "./PeStaticService.js";
import {
  FORGE_PE_OPERATIONS,
  peFamilyFor,
  type ForgePeOperation,
  type PeStaticReport,
} from "../../domain/forge/peStatic.js";
import type { ForgeStaticAnalysisPort } from "./ForgeStaticAnalysisPort.js";
import { ok } from "../../domain/result.js";
const target = {
  path: "C:/analysis/test.exe",
  sha256: "a".repeat(64),
  size_bytes: 2048,
};
const reference = {
  receipt_path: "C:/work/receipt.json",
  receipt_sha256: "b".repeat(64),
};
const report = (operation: ForgePeOperation): PeStaticReport => ({
  operation,
  target,
  result: {},
  workspace: "C:/work/pe",
  sample_execution: false,
  network_used: false,
});
const fixture = () => {
  const port = () => ({
    execute: vi.fn<
      ForgeStaticAnalysisPort<ForgePeOperation, PeStaticReport>["execute"]
    >(async (operation) => ok(report(operation))),
    inspectAvailability: vi.fn<
      ForgeStaticAnalysisPort<
        ForgePeOperation,
        PeStaticReport
      >["inspectAvailability"]
    >(async () => ({
      status: "available",
      code: null,
      reason: null,
      diagnostics: {},
    })),
    close: vi.fn(async () => {}),
  });
  const ports = { pe_parser: port(), upx: port(), pe_results: port() };
  return { ports, service: new PeStaticService(ports) };
};
const inputs = {
  forge_inspect_pe: { path: target.path },
  forge_resolve_pe_dependencies: { path: target.path },
  forge_test_upx: { path: target.path },
  forge_unpack_upx: { path: target.path },
  forge_read_pe_result: reference,
};
it.each(FORGE_PE_OPERATIONS)(
  "routes %s to the selected native owner",
  async (operation) => {
    const { service, ports } = fixture();
    expect((await service.execute(operation, inputs[operation])).ok).toBe(true);
    for (const [family, port] of Object.entries(ports))
      expect(port.execute).toHaveBeenCalledTimes(
        family === peFamilyFor[operation] ? 1 : 0,
      );
    await service.close();
  },
);
it.each([
  ["forge_inspect_pe", { path: "https://example.test/a.exe" }],
  ["forge_inspect_pe", { path: target.path, script: "run" }],
  ["forge_resolve_pe_dependencies", { path: target.path, max_depth: 11 }],
  ["forge_resolve_pe_dependencies", { path: target.path, max_nodes: 49 }],
  [
    "forge_resolve_pe_dependencies",
    { path: target.path, dependency_roots: ["relative"] },
  ],
  [
    "forge_unpack_upx",
    { path: target.path, output_path: "C:/caller/output.exe" },
  ],
  ["forge_test_upx", { path: target.path, arguments: ["--force"] }],
  ["forge_unpack_upx", { path: target.path, timeout_ms: 45001 }],
  ["forge_read_pe_result", { ...reference, byte_count: 65537 }],
] as const)(
  "rejects expanded or malformed %s requests",
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
it("keeps absent UPX independent from parser/readback", async () => {
  const { service, ports } = fixture();
  ports.upx.inspectAvailability.mockResolvedValueOnce({
    status: "unavailable",
    code: "not_configured",
    reason: "absent",
    diagnostics: {},
  });
  const values = await service.inspectAvailability();
  for (const name of FORGE_PE_OPERATIONS)
    expect(values[name]?.status).toBe(
      peFamilyFor[name] === "upx" ? "unavailable" : "available",
    );
  await service.close();
});
it("preserves pre-dispatch and late cancellation", async () => {
  const { service, ports } = fixture();
  const early = new AbortController();
  early.abort("early");
  expect(
    await service.execute("forge_inspect_pe", inputs.forge_inspect_pe, {
      signal: early.signal,
    }),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
  expect(ports.pe_parser.execute).not.toHaveBeenCalled();
  const late = new AbortController();
  ports.pe_parser.execute.mockImplementationOnce(async (operation) => {
    late.abort("late");
    return ok(report(operation));
  });
  expect(
    await service.execute("forge_inspect_pe", inputs.forge_inspect_pe, {
      signal: late.signal,
    }),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
  await service.close();
});
it("settles peer cleanup and retains failure for retry", async () => {
  const { service, ports } = fixture();
  ports.upx.close.mockRejectedValueOnce(new Error("retained owner"));
  await expect(service.close()).rejects.toThrow("incomplete cleanup");
  for (const port of Object.values(ports))
    expect(port.close).toHaveBeenCalledTimes(1);
  await service.close();
});
