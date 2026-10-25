/** Real owned headless IDA job only. The copied PE is analyzed, never debugged or executed. */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { GuestBridgeClient } from "../../dist/forge/guest/GuestBridgeClient.js";
import { GuestCaseFilesAdapter } from "../../dist/forge/guest/GuestCaseFilesAdapter.js";
import { GuestIdaJobAdapter } from "../../dist/forge/guest/GuestIdaJobAdapter.js";
import { GuestRuntimeBinding } from "../../dist/application/forge/GuestRuntimeBinding.js";
const dataRoot = process.env.REA_FORGE_DATA_ROOT, configPath = process.env.REA_FORGE_GUEST_CONFIG, fixture = process.env.REA_FORGE_GUEST_IDA_FIXTURE, pin = process.env.REA_FORGE_GUEST_IDAT_SHA256;
assert.ok(dataRoot && configPath && fixture && pin, "explicit guest/config/input/idat pin required");
const config = JSON.parse(await readFile(configPath, "utf8"));
const transport = new GuestBridgeClient(config), runtime = new GuestRuntimeBinding(config.id, transport), files = new GuestCaseFilesAdapter(transport);
const report = { status: "running", scope: "P2 owned guest IDA worker/guard and harmless IDAPython metadata; not debugger or MCP integration", checks: {}, target_executed: false, gui_started: false, configuration_changed: false, cpu_seconds: "unmeasured", peak_process_family_memory: "unmeasured" };
report.job_protocol=[];
const jobs = new GuestIdaJobAdapter({writeSmallFile:transport.writeSmallFile.bind(transport),readSmallFile:transport.readSmallFile.bind(transport),runCaseProgram:async(program,signal)=>{const value=await transport.runCaseProgram(program,signal);report.job_protocol.push({phase:program.source.includes('$facts.processes=')?'observe':program.source.includes('$worker=Start-Process')?'launch':'prepare-or-stop',...value});return value;}},files,pin);
const started = performance.now(); let safeToRelease = true;
const bytes = await readFile(fixture), sha = createHash("sha256").update(bytes).digest("hex");
assert.equal(sha, "a921abab86c03214ab31e53038b4529317a1b0691aeffe754d315d6f7a348f88", "known-source original UPX test fixture required");
try {
  const binding = await runtime.openCase(); report.runtime = binding.runtime;
  report.case_path = await files.allocate(binding);
  const input = await files.stage(binding, bytes); report.input = input;
  await runtime.requireCase(binding.caseId);
  safeToRelease = false; // Submit may lose its response after the actual worker launch.
  const job = await jobs.submit(binding, input, "import ida_ida, ida_name\nea=ida_ida.inf_get_start_ea()\nassert ida_name.set_name(ea,'forge_guest_entry')\nforge_result={'marker':'forge-guest-idapython','entry':ea,'name':ida_name.get_name(ea)}\n", 35);
  report.job = job;
  const deadline = performance.now() + 65000;
  let observation;
  do {
    await new Promise(resolve => setTimeout(resolve, 250));
    observation = await jobs.inspect(binding, job.jobId, AbortSignal.timeout(20000));
    report.latest = observation;
    if (observation.cleanupConfirmed) break;
  } while (performance.now() < deadline);
  assert.ok(observation.cleanupConfirmed, "independent guard and exact worker/guard creation identities must settle");
  safeToRelease = true;
  assert.equal(observation.state, "completed");
  const result = observation.facts.result.value;
  assert.equal(result.returned.marker, "forge-guest-idapython"); assert.equal(result.returned.name, "forge_guest_entry");
  assert.equal(result.main_thread_dispatch, true); assert.equal(result.idb_saved, true); assert.match(result.idb_sha256, /^[a-f0-9]{64}$/u);
  report.checks.idapython_metadata_name_and_saved_idb = true;
  report.checks.exact_creation_identity_and_zero_active_job_tree = true;
  assert.equal(createHash("sha256").update(await readFile(fixture)).digest("hex"), sha);
  report.checks.original_unchanged = true;
  assert.deepEqual(await runtime.inspect(), binding.runtime); report.checks.borrowed_bridge_preserved = true;
  report.status = "passed";
} catch (cause) { report.status = "failed"; report.failure = String(cause); process.exitCode = 1; }
finally {
  try { await jobs.close(); safeToRelease = true; report.checks.jobs_closed = true; } catch (cause) { safeToRelease = false; report.status = "failed"; report.job_cleanup_failure = String(cause); process.exitCode = 1; }
  if (safeToRelease) { try { await files.close(); report.checks.owned_case_removed = true; } catch (cause) { report.status = "failed"; report.file_cleanup_failure = String(cause); process.exitCode = 1; } }
  else report.case_retained = true;
  await runtime.close();
  report.elapsed_seconds = (performance.now() - started) / 1000;
  const receipt = join(dataRoot, "evidence", `guest-ida-job-${Date.now()}.json`); await writeFile(receipt, `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify({ status: report.status, receipt, elapsed_seconds: report.elapsed_seconds, checks: report.checks, failure: report.failure, job_cleanup_failure: report.job_cleanup_failure, file_cleanup_failure: report.file_cleanup_failure }));
}
