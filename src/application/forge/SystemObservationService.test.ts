import { expect, it, vi } from "vitest";
import { SystemObservationService } from "./SystemObservationService.js";
import {
  FORGE_SYSTEM_OPERATIONS,
  systemFamilyFor,
  type ForgeSystemOperation,
  type SystemObservationReport,
} from "../../domain/forge/systemObservation.js";
import type { ForgeStaticAnalysisPort } from "./ForgeStaticAnalysisPort.js";
import { ok } from "../../domain/result.js";
const reference = {
  receipt_path: "C:/work/receipt.json",
  receipt_sha256: "a".repeat(64),
};
const target = { pid: 1234, created_100ns: "134000000000000001" };
const inputs = {
  forge_inspect_system: { kind: "processes", pid: 1234 },
  forge_observe_process: { ...target, kind: "modules" },
  forge_scan_process: target,
  forge_compare_process_snapshots: { before: reference, after: reference },
  forge_read_system_result: reference,
};
const report = (operation: ForgeSystemOperation): SystemObservationReport => ({
  operation,
  target: {
    path: "C:/work/snapshot.json",
    sha256: "b".repeat(64),
    size_bytes: 1024,
  },
  result: {},
  workspace: "C:/work",
  sample_execution: false,
  network_used: false,
});
const fixture = () => {
  const port = () => ({
    execute: vi.fn<
      ForgeStaticAnalysisPort<
        ForgeSystemOperation,
        SystemObservationReport
      >["execute"]
    >(async (operation) => ok(report(operation))),
    inspectAvailability: vi.fn<
      ForgeStaticAnalysisPort<
        ForgeSystemOperation,
        SystemObservationReport
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
    system_informer: port(),
    hollows_hunter: port(),
    system_results: port(),
  };
  return { ports, service: new SystemObservationService(ports) };
};
it.each(FORGE_SYSTEM_OPERATIONS)(
  "routes %s to its existing native owner",
  async (operation) => {
    const { ports, service } = fixture();
    expect((await service.execute(operation, inputs[operation])).ok).toBe(true);
    for (const [family, port] of Object.entries(ports))
      expect(port.execute).toHaveBeenCalledTimes(
        family === systemFamilyFor[operation] ? 1 : 0,
      );
    await service.close();
  },
);
it.each([
  ["forge_inspect_system", { kind: "services", pid: 1234 }],
  ["forge_inspect_system", { kind: "processes", pid: 4 }],
  ["forge_observe_process", { pid: 1234, kind: "modules" }],
  [
    "forge_observe_process",
    { ...target, created_100ns: Number(134000000000000001n), kind: "modules" },
  ],
  ["forge_observe_process", { ...target, kind: "memory_contents" }],
  ["forge_scan_process", { ...target, arguments: ["/all"] }],
  ["forge_scan_process", { ...target, output: "C:/user" }],
  ["forge_scan_process", { ...target, timeout_ms: 45001 }],
  ["forge_read_system_result", { ...reference, limit: 101 }],
  [
    "forge_compare_process_snapshots",
    { before: reference, after: { ...reference, receipt_sha256: "bad" } },
  ],
] as const)(
  "rejects expanded or identity-ambiguous %s input",
  async (operation, input) => {
    const { ports, service } = fixture();
    expect(await service.execute(operation, input)).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
    for (const port of Object.values(ports))
      expect(port.execute).not.toHaveBeenCalled();
    await service.close();
  },
);
it("isolates missing scanner readiness", async () => {
  const { ports, service } = fixture();
  ports.hollows_hunter.inspectAvailability.mockResolvedValueOnce({
    status: "unavailable",
    code: "not_configured",
    reason: "missing",
    diagnostics: {},
  });
  const availability = await service.inspectAvailability();
  for (const operation of FORGE_SYSTEM_OPERATIONS)
    expect(availability[operation]?.status).toBe(
      operation === "forge_scan_process" ? "unavailable" : "available",
    );
  await service.close();
});
it("preserves pre-dispatch/late cancellation and cleanup retry", async () => {
  const { ports, service } = fixture();
  const early = new AbortController();
  early.abort("before observation");
  expect(
    await service.execute("forge_inspect_system", inputs.forge_inspect_system, {
      signal: early.signal,
    }),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
  expect(ports.system_informer.execute).not.toHaveBeenCalled();
  const late = new AbortController();
  ports.system_informer.execute.mockImplementationOnce(async (operation) => {
    late.abort("after observation");
    return ok(report(operation));
  });
  expect(
    await service.execute("forge_inspect_system", inputs.forge_inspect_system, {
      signal: late.signal,
    }),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
  ports.hollows_hunter.close.mockRejectedValueOnce(new Error("retained owner"));
  await expect(service.close()).rejects.toThrow("incomplete cleanup");
  for (const port of Object.values(ports))
    expect(port.close).toHaveBeenCalledTimes(1);
  await service.close();
});
