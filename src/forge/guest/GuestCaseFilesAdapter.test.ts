import { createHash } from "node:crypto";
import { expect, it, vi } from "vitest";
import { GuestCaseFilesAdapter } from "./GuestCaseFilesAdapter.js";
import { casePath, CHUNK_BYTES } from "./guestCasePrograms.js";
import type { GuestCaseBinding } from "../../application/forge/GuestRuntimeBinding.js";
const binding: GuestCaseBinding = { caseId: "00000000-0000-4000-8000-000000000002", runtime: { guestId: "win10", computerName: "test-guest", bridgeInstanceId: "b".repeat(32), bridgeProcessId: 17, bridgeProcessStartTicks: "638000000000000001" } };
const fixture = () => {
  const storage = new Map<string, Uint8Array>(); const programs: string[] = [];
  const transport = {
    writeSmallFile: vi.fn(async (path: string, bytes: Uint8Array) => { storage.set(path, Buffer.from(bytes)); }),
    readSmallFile: vi.fn(async (path: string) => storage.get(path.replace(".read", "")) ?? new Uint8Array()),
    runCaseProgram: vi.fn(async ({ source }: { source: string }) => {
      programs.push(source); let value: unknown;
      if (source.includes("allocated=$true")) value = { caseId: binding.caseId, path: casePath(binding), allocated: true };
      else if (source.includes("released=$true")) value = { caseId: binding.caseId, released: true };
      else {
        const transferId = /transferId='([^']+)'/u.exec(source)?.[1];
        if (source.includes("prepared=$true")) value = { transferId, prepared: true };
        else if (source.includes("cleared=$true")) value = { transferId, cleared: true };
        else { const facts = /;bytes=(\d+);sha256='([a-f0-9]+)'/u.exec(source); value = { transferId, path: `${casePath(binding)}\\${transferId}.bin`, bytes: Number(facts?.[1]), sha256: facts?.[2] }; }
      }
      return { exitCode: 0, timedOut: false, stdout: JSON.stringify(value), stderr: "" };
    }),
  };
  return { owner: new GuestCaseFilesAdapter(transport), transport, storage, programs };
};
it("transfers bounded chunks with whole-file digests and readback, preserving the original bytes", async () => {
  const { owner, transport, programs } = fixture(); await owner.allocate(binding);
  const bytes = Buffer.alloc(CHUNK_BYTES * 5 + 13, 0x5a); const before = createHash("sha256").update(bytes).digest("hex");
  const file = await owner.stage(binding, bytes); expect(file.sha256).toBe(before); expect(transport.writeSmallFile).toHaveBeenCalledTimes(6);
  expect(await owner.read(binding, file)).toEqual(bytes); expect(createHash("sha256").update(bytes).digest("hex")).toBe(before);
  expect(programs.every(source => source.includes("Guest runtime changed before case operation"))).toBe(true);
  await owner.release(binding); await owner.close(); expect(programs.filter(source => source.includes("released=$true"))).toHaveLength(1);
});
it("supports an empty file without zero-extent bridge reads", async () => {
  const { owner, transport } = fixture(); await owner.allocate(binding); const file = await owner.stage(binding, new Uint8Array());
  expect(await owner.read(binding, file)).toHaveLength(0); expect(transport.readSmallFile).not.toHaveBeenCalled(); await owner.close();
});
it("rejects foreign owners and tampered guest paths before launching file programs", async () => {
  const { owner, transport } = fixture(); await owner.allocate(binding); const file = await owner.stage(binding, Buffer.from("marker"));
  const before = transport.runCaseProgram.mock.calls.length;
  await expect(owner.stage(structuredClone(binding), Buffer.from("foreign"))).rejects.toThrow("does not belong");
  await expect(owner.read(binding, { ...file, path: "C:\\Windows\\not-owned" })).rejects.toThrow("exact bounded");
  expect(transport.runCaseProgram).toHaveBeenCalledTimes(before); await owner.close();
});
it("does not delete a case after a mutation's physical outcome becomes unknown", async () => {
  const { owner, transport, programs } = fixture(); await owner.allocate(binding);
  transport.writeSmallFile.mockRejectedValueOnce(new Error("transport deadline before response"));
  await expect(owner.stage(binding, Buffer.from("marker"))).rejects.toThrow("transport deadline");
  await expect(owner.close()).rejects.toThrow("exact owners retained");
  expect(programs.some(source => source.includes("released=$true"))).toBe(false);
});
it("drains concurrent chunk outcomes before starting case cleanup and refuses new work during close", async () => {
  const { owner, transport, programs } = fixture(); await owner.allocate(binding);
  let settle!: () => void; const held = new Promise<void>(resolve => { settle = resolve; });
  transport.writeSmallFile.mockImplementation(async () => held);
  const pending = owner.stage(binding, Buffer.alloc(CHUNK_BYTES * 5));
  const rejected = expect(pending).rejects.toThrow("closed");
  await vi.waitFor(() => expect(transport.writeSmallFile).toHaveBeenCalledTimes(4));
  const closed = owner.close(); expect(programs.some(source => source.includes("released=$true"))).toBe(false);
  settle(); await rejected; await closed;
  expect(programs.at(-1)).toContain("released=$true");
});
it("cancellation between known completed requests permits owned cleanup without an uncertain write", async () => {
  const { owner, transport } = fixture(); await owner.allocate(binding); const controller = new AbortController();
  const original = transport.runCaseProgram.getMockImplementation()!;
  transport.runCaseProgram.mockImplementation(async (...args) => { const result = await original(...args); if (args[0].source.includes("prepared=$true")) controller.abort(); return result; });
  await expect(owner.stage(binding, Buffer.from("marker"), controller.signal)).rejects.toThrow();
  expect(transport.writeSmallFile).not.toHaveBeenCalled(); await owner.close();
});
