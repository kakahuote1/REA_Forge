import { expect, it, vi } from "vitest";
import { OfflineTrafficService } from "./OfflineTrafficService.js";
import {
  FORGE_TRAFFIC_OPERATIONS,
  trafficFamilyFor,
  type TrafficReport,
  type ForgeTrafficOperation,
} from "../../domain/forge/offlineTraffic.js";
import type { ForgeStaticAnalysisPort } from "./ForgeStaticAnalysisPort.js";
import { ok } from "../../domain/result.js";

const sample = "C:/analysis/sample.pcap";
const report = (operation: ForgeTrafficOperation): TrafficReport => ({
  operation,
  target: { path: sample, sha256: "a".repeat(64), size_bytes: 20 },
  result: {},
  engine: {},
  workspace: "C:/work/traffic",
  network_used: false,
  sample_execution: false,
});
const fixture = () => {
  const adapter = () => ({
    execute: vi.fn<
      ForgeStaticAnalysisPort<ForgeTrafficOperation, TrafficReport>["execute"]
    >(async (operation) => ok(report(operation))),
    inspectAvailability: vi.fn<
      ForgeStaticAnalysisPort<
        ForgeTrafficOperation,
        TrafficReport
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
    pcap: adapter(),
    api_documents: adapter(),
    traffic: adapter(),
  };
  return { ports, service: new OfflineTrafficService(ports) };
};
const inputs = {
  forge_inspect_packet_tree: { path: sample },
  forge_extract_packet_fields: { path: sample, fields: ["frame.number"] },
  forge_pcap_statistics: { path: sample, statistic: "io,phs" },
  forge_follow_packet_stream: {
    path: sample,
    protocol: "tcp",
    stream_index: 0,
  },
  forge_export_packet_objects: { path: sample, protocol: "http" },
  forge_inspect_api_asset: { path: "C:/analysis/openapi.json" },
  forge_compare_api_assets: {
    path: "C:/analysis/left.json",
    right_path: "C:/analysis/right.json",
  },
  forge_export_api_asset: { path: "C:/analysis/openapi.json" },
  forge_read_traffic_result: {
    receipt_path: "C:/work/receipt.json",
    receipt_sha256: "b".repeat(64),
  },
};
it.each(FORGE_TRAFFIC_OPERATIONS)(
  "routes %s to its one configured data owner",
  async (operation) => {
    const { ports, service } = fixture();
    expect((await service.execute(operation, inputs[operation])).ok).toBe(true);
    for (const [name, port] of Object.entries(ports))
      expect(port.execute).toHaveBeenCalledTimes(
        name === trafficFamilyFor[operation] ? 1 : 0,
      );
    await service.close();
  },
);
it.each([
  [
    "forge_extract_packet_fields",
    { path: sample, fields: ["frame.number", "frame.number"] },
  ],
  ["forge_extract_packet_fields", { path: sample, fields: ["-X lua_script"] }],
  [
    "forge_inspect_packet_tree",
    { path: sample, extra_arguments: ["-i", "any"] },
  ],
  ["forge_inspect_packet_tree", { path: sample, display_filter: "http\0" }],
  [
    "forge_pcap_statistics",
    { path: sample, statistic: "io,phs", display_filter: "http" },
  ],
  [
    "forge_follow_packet_stream",
    { path: sample, protocol: "http", stream_index: 0 },
  ],
  [
    "forge_export_packet_objects",
    { path: sample, protocol: "http", output_directory: "C:/Windows" },
  ],
  ["forge_inspect_api_asset", { path: "https://example.test/api.json" }],
  [
    "forge_read_traffic_result",
    {
      receipt_path: "C:/work/receipt.json",
      receipt_sha256: "b".repeat(64),
      byte_count: 65537,
    },
  ],
] as const)(
  "rejects expanded authority or invalid %s arguments",
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
it("isolates missing TShark from document parsing and retained bytes", async () => {
  const { ports, service } = fixture();
  ports.pcap.inspectAvailability.mockResolvedValueOnce({
    status: "unavailable",
    code: "executable_missing",
    reason: "fixture missing TShark",
    diagnostics: {},
  });
  const result = await service.inspectAvailability();
  for (const name of FORGE_TRAFFIC_OPERATIONS)
    expect(result[name]?.status).toBe(
      trafficFamilyFor[name] === "pcap" ? "unavailable" : "available",
    );
  await service.close();
});
it("does not admit an already cancelled request and preserves late cancellation", async () => {
  const { ports, service } = fixture();
  const stopped = new AbortController();
  stopped.abort("caller stopped");
  expect(
    await service.execute(
      "forge_inspect_packet_tree",
      { path: sample },
      { signal: stopped.signal },
    ),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
  expect(ports.pcap.execute).not.toHaveBeenCalled();
  const late = new AbortController();
  ports.pcap.execute.mockImplementationOnce(async (operation) => {
    late.abort("late caller");
    return ok(report(operation));
  });
  expect(
    await service.execute(
      "forge_inspect_packet_tree",
      { path: sample },
      { signal: late.signal },
    ),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
  await service.close();
});
it("drains all resource owners even when one close needs retry", async () => {
  const { ports, service } = fixture();
  ports.pcap.close.mockRejectedValueOnce(new Error("pending native owner"));
  await expect(service.close()).rejects.toThrow("incomplete cleanup");
  for (const port of Object.values(ports))
    expect(port.close).toHaveBeenCalledTimes(1);
  await service.close();
});
