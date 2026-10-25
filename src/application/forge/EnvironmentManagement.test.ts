import { expect, it, vi } from "vitest";
import { EnvironmentManagement, type EnvironmentManagementIntent, type EnvironmentManagementPort, type ManagementPreflight } from "./EnvironmentManagement.js";

const intent: EnvironmentManagementIntent = { operation: "delete_snapshot", targetId: "win10", objectName: "one-exact-snapshot", purpose: "explicit_cleanup", necessity: "The selected obsolete snapshot has an individually reviewed backup and disk chain." };
const observed: ManagementPreflight = { targetId: intent.targetId, objectName: intent.objectName, generation: "a".repeat(64), protected: false, ready: true, facts: {} };
const fixture = () => {
  const port: EnvironmentManagementPort = { inspect: vi.fn(async () => structuredClone(observed)), applyOne: vi.fn(async () => ({ applied: true })), close: vi.fn(async () => undefined) };
  let now = 100;
  return { port, owner: new EnvironmentManagement(port, () => now), expire: () => { now += 600001; } };
};
const confirmed = { confirm: vi.fn(async () => ({ action: "accept" as const, typedTarget: intent.objectName })) };

it("consumes proposals before requiring separate trusted confirmation; arguments never authorize deletion", async () => {
  const { port, owner } = fixture();
  const proposal = await owner.prepare(intent);
  await expect(owner.execute(proposal.proposalId)).rejects.toThrow("separate trusted");
  await expect(owner.execute(proposal.proposalId, confirmed)).rejects.toThrow("consumed");
  expect(port.applyOne).not.toHaveBeenCalled();
  await owner.close();
});
it.each(["decline", "cancel", "wrong-target"])("refuses %s without invoking the management writer", async (action) => {
  const { port, owner } = fixture();
  const proposal = await owner.prepare(intent);
  await expect(owner.execute(proposal.proposalId, { confirm: async () => action === "wrong-target" ? { action: "accept", typedTarget: "other-snapshot" } : { action: action as "decline" | "cancel" } })).rejects.toThrow("not separately confirmed");
  expect(port.applyOne).not.toHaveBeenCalled(); await owner.close();
});
it("uses exact one-shot confirmation and rechecks generation before applyOne", async () => {
  const { port, owner } = fixture(); const proposal = await owner.prepare(intent);
  expect(await owner.execute(proposal.proposalId, confirmed)).toEqual({ applied: true });
  expect(port.inspect).toHaveBeenCalledTimes(2); expect(port.applyOne).toHaveBeenCalledTimes(1);
  await expect(owner.execute(proposal.proposalId, confirmed)).rejects.toThrow("consumed"); await owner.close();
});
it("rejects expiration, protected baselines, missing identity and changed preflight", async () => {
  const { port, owner, expire } = fixture(); const proposal = await owner.prepare(intent); expire();
  await expect(owner.execute(proposal.proposalId, confirmed)).rejects.toThrow("expired");
  vi.mocked(port.inspect).mockResolvedValueOnce({ ...observed, protected: true });
  await expect(owner.prepare(intent)).rejects.toThrow("protected baseline");
  vi.mocked(port.inspect).mockResolvedValueOnce({ ...observed, generation: "" });
  await expect(owner.prepare(intent)).rejects.toThrow("exact stable");
  const changed = await owner.prepare(intent); vi.mocked(port.inspect).mockResolvedValueOnce({ ...observed, generation: "b".repeat(64) });
  await expect(owner.execute(changed.proposalId, confirmed)).rejects.toThrow("changed after preflight");
  expect(port.applyOne).not.toHaveBeenCalled(); await owner.close();
});
it.each(["routine preparation for another ordinary task", "例行准备测试使用，不存在特别变更必要"])("does not create or revert snapshots as routine preparation", async (necessity) => {
  const { port, owner } = fixture();
  await expect(owner.prepare({ ...intent, operation: "create_snapshot", purpose: "before_risky_change", necessity })).rejects.toThrow("cannot be routine");
  expect(port.inspect).not.toHaveBeenCalled(); await owner.close();
});
it("serializes different confirmed proposals and latches any unresolved write failure", async () => {
  const { port, owner } = fixture(); const one = await owner.prepare(intent); const two = await owner.prepare(intent);
  let settle!: () => void; const held = new Promise<void>(resolve => { settle = resolve; });
  vi.mocked(port.applyOne).mockImplementationOnce(async () => { await held; return { applied: true }; }).mockRejectedValueOnce(new Error("postflight disk-chain check failed"));
  const first = owner.execute(one.proposalId, confirmed); const second = owner.execute(two.proposalId, confirmed);
  await vi.waitFor(() => expect(port.applyOne).toHaveBeenCalledTimes(1)); settle(); await first;
  await expect(second).rejects.toThrow("postflight disk-chain");
  await expect(owner.prepare(intent)).rejects.toThrow("latched");
  expect(port.applyOne).toHaveBeenCalledTimes(2); await owner.close();
});
it("close during external confirmation revokes authority before the management writer", async () => {
  const { port, owner } = fixture(); const proposal = await owner.prepare(intent);
  let accept!: () => void; const held = new Promise<void>(resolve => { accept = resolve; });
  const pending = owner.execute(proposal.proposalId, { confirm: async () => { await held; return { action: "accept", typedTarget: intent.objectName }; } });
  const rejected = expect(pending).rejects.toThrow("closed"); await owner.close(); accept(); await rejected;
  expect(port.applyOne).not.toHaveBeenCalled();
});
