import { expect, it, vi } from "vitest";
import { IdaStaticService } from "./IdaStaticService.js";
import {
  FORGE_IDA_OPERATIONS,
  idaFamilyFor,
  type ForgeIdaOperation,
  type IdaStaticReport,
} from "../../domain/forge/idaStatic.js";
import type { ForgeStaticAnalysisPort } from "./ForgeStaticAnalysisPort.js";
import { ok } from "../../domain/result.js";
const reference = {
  receipt_path: "C:/work/receipt.json",
  receipt_sha256: "a".repeat(64),
};
const source = { path: "C:/samples/test.exe" };
const edit = { action: "comment", address: "0x401000", text: "static review" };
const inputs = {
  forge_edit_ida_database: { ...source, edits: [edit] },
  forge_run_ida_safe_python: {
    ...source,
    code: "result=db.functions(limit=8)",
  },
  forge_scan_ida_crypto: source,
  forge_ida_enum: { ...source, platform: "windows" },
  forge_ida_struct_typer: { ...source, struct_name: "ApiTable" },
  forge_snapshot_ida_database: source,
  forge_export_ida_data: {
    ...source,
    address: "0x401000",
    length: 16,
    data_kind: "u8",
    render: "c",
  },
  forge_assemble_ida: { architecture: "x64", assembly: "nop" },
  forge_compare_ida_snapshots: { before: reference, after: reference },
  forge_restore_ida_database: {
    ...reference,
    expected_database_sha256: "b".repeat(64),
  },
  forge_read_ida_result: reference,
};
const report = (operation: ForgeIdaOperation): IdaStaticReport => ({
  operation,
  target: { path: source.path, sha256: "b".repeat(64), size_bytes: 1024 },
  result: {},
  workspace: "C:/work",
  sample_execution: false,
  network_used: false,
});
const fixture = () => {
  const port = () => ({
    execute: vi.fn<
      ForgeStaticAnalysisPort<ForgeIdaOperation, IdaStaticReport>["execute"]
    >(async (operation) => ok(report(operation))),
    inspectAvailability: vi.fn<
      ForgeStaticAnalysisPort<
        ForgeIdaOperation,
        IdaStaticReport
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
    ida_host: port(),
    ida_assembly: port(),
    ida_exchange: port(),
    ida_results: port(),
  };
  return { ports, service: new IdaStaticService(ports) };
};
it.each(FORGE_IDA_OPERATIONS)(
  "routes %s to its configured static owner",
  async (operation) => {
    const { ports, service } = fixture();
    expect((await service.execute(operation, inputs[operation])).ok).toBe(true);
    for (const [family, port] of Object.entries(ports))
      expect(port.execute).toHaveBeenCalledTimes(
        family === idaFamilyFor[operation] ? 1 : 0,
      );
    await service.close();
  },
);
it.each([
  [
    "forge_edit_ida_database",
    {
      ...source,
      edits: [{ ...edit, action: "raw_plugin", path: "C:/plugin.py" }],
    },
  ],
  [
    "forge_edit_ida_database",
    {
      ...source,
      edits: [{ action: "patch", address: "0x401000", data_hex: "90" }],
    },
  ],
  [
    "forge_edit_ida_database",
    {
      ...source,
      edits: [{ action: "declaration", declaration: '#include "C:/secret"' }],
    },
  ],
  [
    "forge_edit_ida_database",
    { ...source, edits: [{ ...edit, address: "1+2" }] },
  ],
  ["forge_edit_ida_database", { ...source, edits: Array(33).fill(edit) }],
  ["forge_run_ida_safe_python", { ...source, code: "result=1", raw: true }],
  ["forge_run_ida_safe_python", { ...source, code: "x".repeat(12001) }],
  ["forge_scan_ida_crypto", { ...source, rule_path: "C:/custom.yar" }],
  [
    "forge_ida_enum",
    { ...source, platform: "windows", enum_names: Array(9).fill("one") },
  ],
  [
    "forge_ida_struct_typer",
    { ...source, struct_name: "ApiTable", regex: ".*" },
  ],
  [
    "forge_export_ida_data",
    {
      ...source,
      address: "0x401000",
      length: 4097,
      data_kind: "u8",
      render: "c",
    },
  ],
  ["forge_assemble_ida", { architecture: "auto", assembly: "nop" }],
  [
    "forge_assemble_ida",
    { architecture: "x64", assembly: "nop", command: "other.exe" },
  ],
  ["forge_restore_ida_database", reference],
  ["forge_read_ida_result", { ...reference, byte_count: 65537 }],
] as const)(
  "rejects expanded or unbounded %s requests before startup",
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
it("isolates absent IDA from pure exchange and retained recovery", async () => {
  const { ports, service } = fixture();
  ports.ida_host.inspectAvailability.mockResolvedValueOnce({
    status: "unavailable",
    code: "not_configured",
    reason: "not ready",
    diagnostics: {},
  });
  const availability = await service.inspectAvailability();
  for (const operation of FORGE_IDA_OPERATIONS)
    expect(availability[operation]?.status).toBe(
      idaFamilyFor[operation] === "ida_host" ? "unavailable" : "available",
    );
  await service.close();
});
it("keeps cancellation and cleanup failures owned", async () => {
  const { ports, service } = fixture();
  const early = new AbortController();
  early.abort("before work");
  expect(
    await service.execute(
      "forge_edit_ida_database",
      inputs.forge_edit_ida_database,
      { signal: early.signal },
    ),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
  expect(ports.ida_host.execute).not.toHaveBeenCalled();
  const late = new AbortController();
  ports.ida_host.execute.mockImplementationOnce(async (operation) => {
    late.abort("after work");
    return ok(report(operation));
  });
  expect(
    await service.execute(
      "forge_edit_ida_database",
      inputs.forge_edit_ida_database,
      { signal: late.signal },
    ),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
  ports.ida_host.close.mockRejectedValueOnce(new Error("retained owner"));
  await expect(service.close()).rejects.toThrow("incomplete cleanup");
  for (const port of Object.values(ports))
    expect(port.close).toHaveBeenCalledTimes(1);
  await service.close();
});
