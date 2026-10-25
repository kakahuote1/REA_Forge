import { expect, it, vi } from "vitest";
import { NativeEnrichmentService } from "./NativeEnrichmentService.js";
import {
  FORGE_ENRICHMENT_OPERATIONS,
  type EnrichmentReport,
  type ForgeEnrichmentOperation,
} from "../../domain/forge/nativeEnrichment.js";
import { ok } from "../../domain/result.js";
import type { ProviderAvailability } from "../AnalysisProvider.js";

const fixture = () => {
  const adapter = () => ({
    execute: vi.fn(async (operation: ForgeEnrichmentOperation) =>
      ok<EnrichmentReport>({
        operation,
        target: null,
        result: {},
        engine: {},
        workspace: "C:/work/enrichment",
        sample_execution: false,
        network_used: false,
      }),
    ),
    inspectAvailability: vi.fn<
      (signal?: AbortSignal) => Promise<ProviderAvailability>
    >(async () => ({
      status: "available",
      code: null,
      reason: null,
      diagnostics: {},
    })),
    close: vi.fn(async () => {}),
  });
  const ports = {
    capa: adapter(),
    floss: adapter(),
    api_hashes: adapter(),
    enrichment: adapter(),
  };
  return { ports, service: new NativeEnrichmentService(ports) };
};

it("selects the exact engine port, applies typed defaults and shares Evidence semantics", async () => {
  const { ports, service } = fixture();
  const result = await service.execute("forge_recover_strings", {
    path: "C:/analysis/example.exe",
  });
  expect(result.ok).toBe(true);
  expect(ports.floss.execute).toHaveBeenCalledWith(
    "forge_recover_strings",
    expect.objectContaining({
      format: "auto",
      timeout_ms: 45000,
      minimum_length: 4,
      limit: 50,
    }),
    undefined,
  );
  expect(ports.capa.execute).not.toHaveBeenCalled();
  expect(ports.api_hashes.execute).not.toHaveBeenCalled();
  await service.close();
});

it("database operations do not need a sample and reader does not borrow a live engine", async () => {
  const { ports, service } = fixture();
  expect((await service.execute("forge_list_api_hash_types", {})).ok).toBe(
    true,
  );
  expect(
    (
      await service.execute("forge_lookup_api_hash", {
        hash_value: "0xEC0E4E8E",
      })
    ).ok,
  ).toBe(true);
  expect(
    (
      await service.execute("forge_read_enrichment_result", {
        receipt_path: "C:/work/receipt.json",
        receipt_sha256: "a".repeat(64),
      })
    ).ok,
  ).toBe(true);
  expect(ports.api_hashes.execute).toHaveBeenCalledTimes(2);
  expect(ports.enrichment.execute).toHaveBeenCalledTimes(1);
  expect(ports.capa.execute).not.toHaveBeenCalled();
  await service.close();
});

it.each([
  ["forge_lookup_api_hash", { hash_value: true }],
  ["forge_lookup_api_hash", { hash_value: 0x1_0000_0000 }],
  ["forge_lookup_api_hash", { hash_value: "0x1", sql: "SELECT 1" }],
  ["forge_analyze_capabilities", { path: "C:/example.exe", backend: "ida" }],
  ["forge_analyze_capabilities", { path: "C:/example.exe", timeout_ms: 45001 }],
  [
    "forge_recover_strings",
    { path: "C:/example.exe", string_kinds: ["arbitrary"] },
  ],
  [
    "forge_read_enrichment_result",
    { receipt_path: "C:/work/receipt.json", receipt_sha256: "bad" },
  ],
] as const)(
  "refuses malformed or expanded authority before an adapter: %s",
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

it("reports five exact readiness entries without conflating missing engines", async () => {
  const { ports, service } = fixture();
  ports.floss.inspectAvailability.mockResolvedValueOnce({
    status: "unavailable",
    code: "runtime_unavailable",
    reason: "fixture missing engine",
    diagnostics: {},
  });
  const availability = await service.inspectAvailability();
  expect(Object.keys(availability)).toEqual([...FORGE_ENRICHMENT_OPERATIONS]);
  expect(availability.forge_recover_strings).toMatchObject({
    status: "unavailable",
  });
  expect(availability.forge_analyze_capabilities).toMatchObject({
    status: "available",
  });
  expect(availability.forge_read_enrichment_result).toMatchObject({
    status: "available",
  });
  await service.close();
});

it("drains all owners and retains a failed owner for close retry", async () => {
  const { ports, service } = fixture();
  ports.capa.close.mockRejectedValueOnce(new Error("retained owned command"));
  await expect(service.close()).rejects.toThrow("incomplete cleanup");
  for (const port of Object.values(ports))
    expect(port.close).toHaveBeenCalledTimes(1);
  await service.close();
});
