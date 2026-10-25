import { createHash, randomUUID } from "node:crypto";
import { expect, it, vi } from "vitest";
import type { GuestCaseBinding } from "../../application/forge/GuestRuntimeBinding.js";
import type { GuestCaseFilesPort, GuestStagedFile } from "../../application/forge/GuestCaseFilesPort.js";
import { GuestIdaJobAdapter } from "./GuestIdaJobAdapter.js";
import { casePath } from "./guestCasePrograms.js";
import { guestIdaWrapper } from "./guestIdaWrapper.js";
const binding: GuestCaseBinding = { caseId: "00000000-0000-4000-8000-000000000002", runtime: { guestId: "win10", computerName: "guest", bridgeInstanceId: "a".repeat(32), bridgeProcessId: 17, bridgeProcessStartTicks: "638000000000000001" } };
const file: GuestStagedFile = { transferId: "00000000-0000-4000-8000-000000000003", path: `${casePath(binding)}\\00000000-0000-4000-8000-000000000003.bin`, bytes: 4, sha256: "a".repeat(64) };
const workerStamp = "2026-10-25T01:00:00.0000001Z", guardStamp = "2026-10-25T01:00:00.0000002Z";
const fixture = () => {
  let facts: Record<string, unknown> = {};
  const files: GuestCaseFilesPort = { allocate: vi.fn(async () => casePath(binding)), stage: vi.fn(async (_binding, bytes) => { const transferId = randomUUID(); return { transferId, path: `${casePath(binding)}\\${transferId}.bin`, bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") }; }), read: vi.fn(async () => new Uint8Array()), release: vi.fn(async () => undefined), close: vi.fn(async () => undefined) };
  const transport = { writeSmallFile: vi.fn(async (_path: string, _bytes: Uint8Array) => undefined), readSmallFile: vi.fn(async (path: string) => Buffer.from(JSON.stringify({jobId:/ida-job-[a-f0-9]{24}/u.exec(path)?.[0],workerPid:31,workerStartUtc:workerStamp}))), runCaseProgram: vi.fn(async ({ source }: { source: string }) => {
    const jobId = /jobId='(ida-job-[a-f0-9]{24})'/u.exec(source)?.[1];
    const value = source.includes("$facts.processes=") ? facts : source.includes("$worker=Start-Process") ? { jobId, workerPid: 31, workerStartUtc: workerStamp } : { jobId, prepared: true };
    return { exitCode: 0, timedOut: false, stderr: "", stdout: JSON.stringify(value) };
  }) };
  const owner = new GuestIdaJobAdapter(transport, files, "b".repeat(64));
  return { owner, transport, files, setFacts: (value: Record<string, unknown>) => { facts = value; } };
};
const finished = (jobId: string) => {
  const identity = { job_id: jobId, worker_pid: 31, worker_start_utc: workerStamp, guard_pid: 32, guard_start_utc: guardStamp };
  return { jobId, "containment-ready": { value: identity }, "containment-cleanup": { value: { ...identity, active_processes: 0, reason: "worker_exited" } }, completion: { value: { job_id: jobId, state: "exited" } }, result: { value: { ok: true, idb_saved: true } }, processes: [{ pid: 31, expectedStart: workerStamp, outcome: "not_found" }, { pid: 32, expectedStart: guardStamp, outcome: "not_found" }] };
};

it("uses only shipped contained workers and pinned target identities; a successful result is not cleanup proof", async () => {
  const { owner, transport, files, setFacts } = fixture();
  const job = await owner.submit(binding, file, "forge_result={'marker':42}", 20);
  expect(files.stage).toHaveBeenCalledOnce();
  const specCall = transport.writeSmallFile.mock.calls.find(call => String(call[0]).endsWith("spec.json"));
  expect(JSON.parse(Buffer.from(specCall?.[1] ?? []).toString())).toMatchObject({ frontend: "idat", frontend_sha256: "b".repeat(64), input_sha256: file.sha256, input_bytes: 4 });
  setFacts({ jobId: job.jobId, result: { value: { ok: true, idb_saved: true } }, processes: [] });
  expect((await owner.inspect(binding, job.jobId)).cleanupConfirmed).toBe(false);
  setFacts(finished(job.jobId)); expect(await owner.inspect(binding, job.jobId)).toMatchObject({ state: "completed", cleanupConfirmed: true });
  await owner.close(); expect(files.close).not.toHaveBeenCalled();
});
it.each(["wrong-launch-identity", "active-worker", "unknown-process", "nonzero-tree", "wrong-job"])("does not infer cleanup for %s", async (variant) => {
  const { owner, setFacts } = fixture(); const job = await owner.submit(binding, file, "forge_result=42", 20);
  const facts = finished(job.jobId);
  if (variant === "wrong-launch-identity") facts["containment-ready"].value.worker_pid = 999;
  if (variant === "active-worker") facts.processes[0]!.outcome = "same_process_alive";
  if (variant === "unknown-process") facts.processes[0]!.outcome = "unknown";
  if (variant === "nonzero-tree") facts["containment-cleanup"].value.active_processes = 1;
  if (variant === "wrong-job") facts["containment-cleanup"].value.job_id = "ida-job-"+"f".repeat(24);
  setFacts(facts); expect((await owner.inspect(binding, job.jobId)).cleanupConfirmed).toBe(false);
  setFacts(finished(job.jobId)); await owner.inspect(binding, job.jobId); await owner.close();
});
it("refuses other case owners, invalid paths, unsupported timeouts and concurrent jobs", async () => {
  const { owner, transport, setFacts } = fixture();
  await expect(owner.submit(binding, { ...file, path: `${casePath(binding)}\\..\\foreign` }, "", 20)).rejects.toThrow("exact bounded");
  await expect(owner.submit(binding, file, "", 51)).rejects.toThrow("1..50");
  expect(transport.runCaseProgram).not.toHaveBeenCalled();
  const job = await owner.submit(binding, file, "forge_result=1", 20);
  await expect(owner.submit(binding, file, "", 20)).rejects.toThrow("still active");
  await expect(owner.inspect(structuredClone(binding), job.jobId)).rejects.toThrow("another case owner");
  setFacts(finished(job.jobId)); await owner.inspect(binding, job.jobId); await owner.close();
});
it("uses a stop marker, never arbitrary PID killing, and preserves timed-out outcomes", async () => {
  const { owner, transport, setFacts } = fixture(); const job = await owner.submit(binding, file, "forge_result=1", 1);
  const facts = finished(job.jobId); facts["containment-cleanup"].value.reason = "absolute_deadline"; setFacts(facts);
  expect(await owner.stop(binding, job.jobId)).toMatchObject({ state: "timed_out", cleanupConfirmed: true });
  expect(transport.runCaseProgram.mock.calls.some(([value]) => value.source.includes("stop.request"))).toBe(true);
  expect(transport.runCaseProgram.mock.calls.some(([value]) => value.source.includes("Stop-Process"))).toBe(false);
  await owner.close();
});
it("closes a known pre-launch failure without inventing a remote worker to stop", async () => {
  const { owner, files, transport } = fixture(); vi.mocked(files.stage).mockRejectedValueOnce(new Error("input staging failed before launch"));
  await expect(owner.submit(binding, file, "", 20)).rejects.toThrow("staging failed");
  await owner.close(); expect(transport.runCaseProgram).not.toHaveBeenCalled();
});
it("builds Python source as encoded guest data, with exact result/case identity", () => {
  const id = "ida-job-"+"a".repeat(24); const path = `${casePath(binding)}\\ida_jobs\\${id}\\result.json`;
  const source = guestIdaWrapper(binding, id, path, "forge_result = {'literal': '引号 \\\"'}\n");
  expect(source).toContain("base64.b64decode"); expect(source).toContain("ida_kernwin.execute_sync");
  expect(source).toContain("os.replace(pending,_result_path)");
  expect(() => guestIdaWrapper(binding, id, "C:\\foreign\\result.json", "")).toThrow("Invalid bounded");
});

it("recovers an empty immediate launch acknowledgement from its durable exact-job receipt without relaunching", async () => {
  const { owner, transport, setFacts } = fixture(); const original = transport.runCaseProgram.getMockImplementation()!;
  transport.runCaseProgram.mockImplementation(async (...args) => {const value=await original(...args);return args[0].source.includes("$worker=Start-Process")?{...value,stdout:""}:value;});
  const job=await owner.submit(binding,file,"forge_result=42",20);
  expect(transport.readSmallFile).toHaveBeenCalledWith(`${job.root}\\launch.json`,4096);
  expect(transport.runCaseProgram.mock.calls.filter(([value])=>value.source.includes("$worker=Start-Process"))).toHaveLength(1);
  setFacts(finished(job.jobId));await owner.inspect(binding,job.jobId);await owner.close();
});
