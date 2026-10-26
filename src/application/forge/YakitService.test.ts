import { expect, it, vi } from "vitest";
import { YakitService } from "./YakitService.js";
import {
  FORGE_YAKIT_OPERATIONS,
  yakitFamilyFor,
  type ForgeYakitOperation,
  type YakitReport,
} from "../../domain/forge/yakit.js";
import type { ForgeStaticAnalysisPort } from "./ForgeStaticAnalysisPort.js";
import { ok } from "../../domain/result.js";

const reference = {
  receipt_path: "C:/work/receipt.json",
  receipt_sha256: "a".repeat(64),
};
const inputs = {
  forge_yakit_request: { url: "http://127.0.0.1:8080/fixture" },
  forge_yakit_flows: { keyword: "fixture" },
  forge_read_yakit_result: reference,
};
const fixture = () => {
  const port = () => ({
    execute: vi.fn<
      ForgeStaticAnalysisPort<ForgeYakitOperation, YakitReport>["execute"]
    >(async (operation) =>
      ok({
        operation,
        target: {
          path: "C:/work/input.json",
          sha256: "b".repeat(64),
          size_bytes: 32,
        },
        result: {},
        workspace: "C:/work",
        sample_execution: false,
        network_used: operation === "forge_yakit_request",
      }),
    ),
    inspectAvailability: vi.fn<
      ForgeStaticAnalysisPort<
        ForgeYakitOperation,
        YakitReport
      >["inspectAvailability"]
    >(async () => ({
      status: "available",
      code: null,
      reason: null,
      diagnostics: {},
    })),
    close: vi.fn(async () => {}),
  });
  const ports = { yakit: port(), yakit_results: port() };
  return { ports, service: new YakitService(ports) };
};

it.each(FORGE_YAKIT_OPERATIONS)(
  "routes %s through one shared service",
  async (operation) => {
    const { ports, service } = fixture();
    expect((await service.execute(operation, inputs[operation])).ok).toBe(true);
    for (const [family, port] of Object.entries(ports))
      expect(port.execute).toHaveBeenCalledTimes(
        family === yakitFamilyFor[operation] ? 1 : 0,
      );
    await service.close();
  },
);
it.each([
  { url: "file:///C:/secret" },
  { url: "http://user:pass@127.0.0.1/" },
  { url: "http://127.0.0.1/#fragment" },
  { url: "http://127.0.0.1/", headers: [{ name: "Host", value: "other" }] },
  { url: "http://127.0.0.1/", headers: [{ name: "X", value: "a\r\nb" }] },
  { url: "http://127.0.0.1/", concurrent: 20 },
  { url: "http://127.0.0.1/", fuzzTagMode: "standard" },
  { url: "http://127.0.0.1/", proxy: "http://other:8080" },
  { url: "http://127.0.0.1/", script: "arbitrary" },
  { url: "http://127.0.0.1/", profile: "../human-profile" },
  { url: "http://127.0.0.1/", timeout_ms: 30001 },
])(
  "refuses unsafe/unselected request fields %# before executing an engine",
  async (input) => {
    const { ports, service } = fixture();
    expect((await service.execute("forge_yakit_request", input)).ok).toBe(
      false,
    );
    expect(ports.yakit.execute).not.toHaveBeenCalled();
    await service.close();
  },
);
it("keeps result readback available without launching an engine and closes each owner", async () => {
  const { ports, service } = fixture();
  ports.yakit.inspectAvailability.mockResolvedValue({
    status: "unavailable",
    code: "not_configured",
    reason: "missing",
    diagnostics: {},
  });
  const availability = await service.inspectAvailability();
  expect(availability.forge_read_yakit_result?.status).toBe("available");
  expect(availability.forge_yakit_request?.status).toBe("unavailable");
  const abort = new AbortController();
  abort.abort("test cancelled");
  expect(
    (
      await service.execute("forge_yakit_request", inputs.forge_yakit_request, {
        signal: abort.signal,
      })
    ).ok,
  ).toBe(false);
  expect(ports.yakit.execute).not.toHaveBeenCalled();
  await service.close();
  expect(ports.yakit.close).toHaveBeenCalledOnce();
  expect(ports.yakit_results.close).toHaveBeenCalledOnce();
});
it("serializes one private profile through physical adapter settlement", async () => {
  const { ports, service } = fixture();
  const execute = ports.yakit.execute.getMockImplementation()!;
  let release!: () => void;
  const barrier = new Promise<void>((resolve) => {
    release = resolve;
  });
  ports.yakit.execute.mockImplementationOnce(async (...args) => {
    await barrier;
    return execute(...args);
  });
  const first = service.execute(
    "forge_yakit_request",
    inputs.forge_yakit_request,
  );
  const second = service.execute("forge_yakit_flows", inputs.forge_yakit_flows);
  await Promise.resolve();
  expect(ports.yakit.execute).toHaveBeenCalledTimes(1);
  release();
  expect((await first).ok).toBe(true);
  expect((await second).ok).toBe(true);
  expect(ports.yakit.execute).toHaveBeenCalledTimes(2);
  await service.close();
});
