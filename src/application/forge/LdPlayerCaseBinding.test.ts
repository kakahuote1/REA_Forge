import { expect, it, vi } from "vitest";
import { LdPlayerCaseBinding } from "./LdPlayerCaseBinding.js";
import type { LdPlayerInstanceObservation, LdPlayerObservationPort } from "./LdPlayerRuntimePort.js";
const observed: LdPlayerInstanceObservation = { index: 2, name: "我的雷电,练习机", physicalGeneration: "a".repeat(64), machineUuid: "{20160302-aaaa-aaaa-31e2-000000000002}", androidStarted: false, runtime: { playerPid: null, playerStartTicks: null, vmPid: null, vmStartTicks: null } };
const fixture = () => { const port: LdPlayerObservationPort = { inspect: vi.fn(async () => structuredClone(observed)), list: vi.fn(async () => [observed]), close: vi.fn(async () => undefined) }; return { port, owner: new LdPlayerCaseBinding(port) }; };
it.each([0, -1, 1.5, Number.NaN])("never opens instance %s", async (index) => { const { port, owner } = fixture(); await expect(owner.openCase(index)).rejects.toThrow("nonzero"); expect(port.inspect).not.toHaveBeenCalled(); await owner.close(); });
it("keeps human names separate from physical identity and does not invent missing runtime ownership", async () => {
  const { port, owner } = fixture(); const { binding } = await owner.openCase(2);
  vi.mocked(port.inspect).mockResolvedValueOnce({ ...observed, name: "重新命名" });
  expect((await owner.requireCase(binding.caseId)).binding).toBe(binding);
  expect((await owner.requireCase(binding.caseId)).observation.runtime.playerStartTicks).toBeNull();
  await owner.close(); expect(port.close).toHaveBeenCalledOnce();
});
it("rejects replacement with the same deterministic VBox UUID, invalidation, and reuse after close", async () => {
  const { port, owner } = fixture(); const { binding } = await owner.openCase(2);
  vi.mocked(port.inspect).mockResolvedValueOnce({ ...observed, physicalGeneration: "b".repeat(64) });
  await expect(owner.requireCase(binding.caseId)).rejects.toThrow("replaced");
  owner.invalidateInstance(2); await expect(owner.requireCase(binding.caseId)).rejects.toThrow("unknown or closed");
  await owner.close(); await expect(owner.openCase(2)).rejects.toThrow("closed");
});
it("refuses a mismatched index and late observations after close", async () => {
  const { port, owner } = fixture(); vi.mocked(port.inspect).mockResolvedValueOnce({ ...observed, index: 3 });
  await expect(owner.openCase(2)).rejects.toThrow("exact instance");
  let settle!: (value: LdPlayerInstanceObservation) => void;
  vi.mocked(port.inspect).mockImplementationOnce(() => new Promise(resolve => { settle = resolve; }));
  const pending = owner.openCase(2); const rejected = expect(pending).rejects.toThrow("closed"); await owner.close(); settle(observed); await rejected;
});
