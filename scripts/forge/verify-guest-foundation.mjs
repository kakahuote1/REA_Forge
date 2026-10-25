/** Real metadata and inert byte-transfer boundary; never launches an analysis target. */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { GuestBridgeClient } from "../../dist/forge/guest/GuestBridgeClient.js";
import { GuestCaseFilesAdapter } from "../../dist/forge/guest/GuestCaseFilesAdapter.js";
import { GuestRuntimeBinding } from "../../dist/application/forge/GuestRuntimeBinding.js";
import { LdPlayerCaseBinding } from "../../dist/application/forge/LdPlayerCaseBinding.js";
import { LdPlayerObservationAdapter } from "../../dist/forge/ldplayer/LdPlayerObservationAdapter.js";

const configPath = process.env.REA_FORGE_GUEST_CONFIG;
const dataRoot = process.env.REA_FORGE_DATA_ROOT;
assert.ok(configPath && dataRoot, "explicit existing guest selection and Forge data root required");
const configuration = JSON.parse(await readFile(configPath, "utf8"));
const transport = new GuestBridgeClient(configuration);
const runtime = new GuestRuntimeBinding(configuration.id, transport);
const files = new GuestCaseFilesAdapter(transport);
const ld = new LdPlayerCaseBinding(new LdPlayerObservationAdapter());
const report = { status: "running", scope: "P2 guest identity/inert case-file transfer and read-only LDPlayer physical identity; no target execution or environment management", checks: {}, target_executed: false, bridge_restarted: false, gui_started: false, configuration_changed: false, cpu_seconds: "unmeasured", peak_process_family_memory: "unmeasured" };
const started = performance.now();
let binding;
try {
  binding = await runtime.openCase(AbortSignal.timeout(30000));
  report.runtime = binding.runtime;
  report.guest_case_path = await files.allocate(binding, AbortSignal.timeout(30000));
  const bytes = Buffer.alloc(128 * 1024 + 19);
  for (let index = 0; index < bytes.length; index++) bytes[index] = index % 251;
  const digest = createHash("sha256").update(bytes).digest("hex");
  const staged = await files.stage(binding, bytes, AbortSignal.timeout(90000));
  report.staged = staged;
  assert.equal(staged.sha256, digest);
  assert.deepEqual(Buffer.from(await files.read(binding, staged, AbortSignal.timeout(90000))), bytes);
  report.checks.guest_stage_sha256_and_readback = true;
  assert.deepEqual((await runtime.requireCase(binding.caseId)).runtime, binding.runtime);
  await files.release(binding, AbortSignal.timeout(30000));
  report.checks.owned_guest_case_removed = true;
  runtime.closeCase(binding.caseId);
  await assert.rejects(() => runtime.requireCase(binding.caseId), /unknown or closed/u);
  assert.deepEqual(await runtime.inspect(), binding.runtime);
  report.checks.borrowed_bridge_preserved = true;
  report.checks.closed_case_refused = true;
  const selectedIndex = Number(process.env.REA_FORGE_LDPLAYER_INDEX);
  assert.ok(Number.isSafeInteger(selectedIndex) && selectedIndex > 0, "explicit nonzero read-only instance selection required");
  const selected = await ld.openCase(selectedIndex, AbortSignal.timeout(20000));
  report.ldplayer = selected;
  assert.equal((await ld.requireCase(selected.binding.caseId)).observation.physicalGeneration, selected.binding.physicalGeneration);
  ld.invalidateInstance(selectedIndex);
  await assert.rejects(() => ld.requireCase(selected.binding.caseId), /unknown or closed/u);
  report.checks.ldplayer_physical_generation_and_invalidation = true;
  report.status = "passed";
} catch (cause) {
  report.status = "failed";
  report.failure = String(cause);
  process.exitCode = 1;
} finally {
  for (const [name, owner] of [["files", files], ["ldplayer", ld], ["runtime", runtime]]) {
    try { await owner.close(); report.checks[`${name}_owner_closed`] = true; }
    catch (cause) { report.status = "failed"; report[`${name}_cleanup_failure`] = String(cause); process.exitCode = 1; }
  }
  report.elapsed_seconds = (performance.now() - started) / 1000;
  report.limitations = ["No MCP guest debugger/job surface delivered by this foundation verifier", "Guest endpoint association is not cryptographic VM attestation", "Read-only instance case is not Android boot or target-process authority", "Management writer/OS-lock/journal and native human-confirmation transport still need separate integration", "Unknown write settlement retains exact case ownership rather than attempting deletion"];
  const path = join(dataRoot, "evidence", `guest-foundation-${Date.now()}.json`);
  await writeFile(path, `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify({ status: report.status, receipt: path, elapsed_seconds: report.elapsed_seconds, checks: report.checks, failure: report.failure, files_cleanup_failure: report.files_cleanup_failure }));
}
