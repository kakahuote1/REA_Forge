import { expect, it, vi } from "vitest";
import { GuestRuntimeBinding } from "./GuestRuntimeBinding.js";
import type {
  GuestHealthPort,
  GuestRuntimeObservation,
} from "./GuestRuntimePort.js";

const observation: GuestRuntimeObservation = {
  ok: true,
  version: "2.0.0",
  computerName: "test-guest",
  bridgeInstanceId: "a".repeat(32),
  bridgeProcessId: 21,
  bridgeProcessStartTicks: "638000000000000001",
};
const fixture = () => {
  const port = {
    inspect: vi.fn<GuestHealthPort["inspect"]>().mockResolvedValue(observation),
    close: vi.fn<GuestHealthPort["close"]>().mockResolvedValue(),
  };
  return { port, binding: new GuestRuntimeBinding("selected-win10", port) };
};

it("binds a case to transport-observed identity and rechecks every use", async () => {
  const { port, binding } = fixture();
  const opened = await binding.openCase();
  expect(opened.runtime).toMatchObject({
    guestId: "selected-win10",
    bridgeProcessId: 21,
  });
  expect(Object.isFrozen(opened.runtime)).toBe(true);
  expect(await binding.requireCase(opened.caseId)).toBe(opened);
  expect(port.inspect).toHaveBeenCalledTimes(2);
  binding.closeCase(opened.caseId);
  await expect(binding.requireCase(opened.caseId)).rejects.toThrow(
    "unknown or closed",
  );
  expect(port.inspect).toHaveBeenCalledTimes(2);
  await binding.close();
  expect(port.close).toHaveBeenCalledTimes(1);
});

it.each([
  { bridgeProcessStartTicks: "638000000000000002" },
  { bridgeProcessId: 22 },
  { bridgeInstanceId: "b".repeat(32) },
  { computerName: "different-machine" },
])("refuses old cases when observed runtime changes: %j", async (change) => {
  const { port, binding } = fixture();
  const opened = await binding.openCase();
  port.inspect.mockResolvedValue({ ...observation, ...change });
  await expect(binding.requireCase(opened.caseId)).rejects.toThrow(
    "generation changed",
  );
  await binding.close();
});

it("does not accept a machine name and PID without process creation identity", async () => {
  const { port, binding } = fixture();
  port.inspect.mockResolvedValue({
    ok: true,
    version: "2.0.0",
    computerName: "test-guest",
  });
  await expect(binding.openCase()).rejects.toThrow("process creation identity");
  await binding.close();
});

it("does not resurrect a case closed during observation", async () => {
  const { port, binding } = fixture();
  const opened = await binding.openCase();
  let finish!: (value: GuestRuntimeObservation) => void;
  port.inspect.mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const pending = binding.requireCase(opened.caseId);
  binding.closeCase(opened.caseId);
  finish(observation);
  await expect(pending).rejects.toThrow("case closed during");
  await binding.close();
});

it("refuses a late handshake after close and can retry physical close", async () => {
  const { port, binding } = fixture();
  let finish!: (value: GuestRuntimeObservation) => void;
  port.inspect.mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const pending = binding.openCase();
  port.close.mockRejectedValueOnce(new Error("retained close owner"));
  await expect(binding.close()).rejects.toThrow("retained close owner");
  finish(observation);
  await expect(pending).rejects.toThrow("closed during");
  await binding.close();
  expect(port.close).toHaveBeenCalledTimes(2);
  await expect(binding.openCase()).rejects.toThrow("closed");
});

it("preserves late caller cancellation instead of creating a case", async () => {
  const { port, binding } = fixture();
  const controller = new AbortController();
  port.inspect.mockImplementationOnce(async () => {
    controller.abort("caller left");
    return observation;
  });
  await expect(binding.openCase(controller.signal)).rejects.toMatchObject({
    _tag: "AnalysisCancelledError",
  });
  await binding.close();
});
