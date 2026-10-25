import { createHash, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { GuestCaseBinding } from "../../application/forge/GuestRuntimeBinding.js";
import type { GuestCaseFilesPort, GuestStagedFile } from "../../application/forge/GuestCaseFilesPort.js";
import type { GuestIdaJob, GuestIdaJobObservation, GuestIdaJobPort } from "../../application/forge/GuestIdaJobPort.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import type { GuestBridgeClient } from "./GuestBridgeClient.js";
import { assertGuestCaseFile, casePath, guestCaseProgramPrefix } from "./guestCasePrograms.js";
import { guestIdaWrapper } from "./guestIdaWrapper.js";

type Transport = Pick<GuestBridgeClient, "writeSmallFile" | "readSmallFile" | "runCaseProgram">;
type OwnedJob = { readonly binding: GuestCaseBinding; readonly job: GuestIdaJob; cleanupConfirmed: boolean; launchIdentity?: { readonly pid: number; readonly start: string } };
const quote = (value: string) => `'${value.replaceAll("'", "''")}'`;
const digest = (value: Uint8Array) => createHash("sha256").update(value).digest("hex");
const PID_STAMP = /^[0-9]{4}-[0-9T:.-]+Z$/u;
const receiptSchema = z.object({ job_id: z.string(), worker_pid: z.int().positive(), worker_start_utc: z.string().regex(PID_STAMP), guard_pid: z.int().positive(), guard_start_utc: z.string().regex(PID_STAMP) });

/** Existing bridge + pure worker/JobObject guard. No interactive desktop or new daemon. */
export class GuestIdaJobAdapter implements GuestIdaJobPort {
  readonly #jobs = new Map<string, OwnedJob>();
  readonly #active = new Set<Promise<unknown>>();
  #closed = false;
  #submitting = false;
  constructor(private readonly transport: Transport, private readonly files: GuestCaseFilesPort, private readonly idatSha256: string) {
    if (!/^[a-f0-9]{64}$/u.test(idatSha256)) throw new Error("Operator-pinned guest idat identity is required");
  }

  submit(binding: GuestCaseBinding, input: GuestStagedFile, source: string, timeoutSeconds: number, signal?: AbortSignal): Promise<GuestIdaJob> {
    return this.#track(async () => {
      this.#activeOwner(signal);
      if (!Number.isInteger(timeoutSeconds) || timeoutSeconds < 1 || timeoutSeconds > 50 || Buffer.byteLength(source, "utf8") > 128 * 1024) throw new Error("Guest IDA work requires1..50seconds and at most128KiB source");
      assertGuestCaseFile(binding, input);
      if (this.#submitting || [...this.#jobs.values()].some(value => !value.cleanupConfirmed)) throw new Error("A guest IDA job is still active or has unresolved cleanup");
      this.#submitting = true;
      try {
      const jobId = `ida-job-${randomBytes(12).toString("hex")}`;
      const root = `${casePath(binding)}\\ida_jobs\\${jobId}`;
      const job = { jobId, caseId: binding.caseId, root };
      const owned: OwnedJob = { binding, job, cleanupConfirmed: true };
      this.#jobs.set(jobId, owned); // Publish ownership before any guest preparation or launch.
      const wrapper = await this.files.stage(binding, Buffer.from(guestIdaWrapper(binding, jobId, `${root}\\result.json`, source)), signal);
      this.#activeOwner(signal);
      await this.#program(binding, `
$inputPath=${quote(input.path)};$wrapperPath=${quote(wrapper.path)}
foreach($selected in @($inputPath,$wrapperPath)){Assert-PlainPath $selected}
if((Get-Item -LiteralPath $inputPath).Length -ne ${input.bytes} -or (Get-FileHash -LiteralPath $inputPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne ${quote(input.sha256)}){throw 'Staged input identity changed'}
if((Get-FileHash -LiteralPath $wrapperPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne ${quote(wrapper.sha256)}){throw 'Wrapper identity changed'}
$jobRoot=${quote(root)};Assert-PlainPath $jobRoot
if(Test-Path -LiteralPath $jobRoot){throw 'Job directory already exists'}
if(@(Get-Process -Name ida,idat -ErrorAction SilentlyContinue).Count -ne 0){throw 'Borrowed IDA process already present; refusing to replace it'}
[void][IO.Directory]::CreateDirectory($jobRoot)
[IO.File]::Copy($inputPath,(Join-Path $jobRoot 'target.exe'),$false)
[IO.File]::Copy($wrapperPath,(Join-Path $jobRoot 'wrapper.py'),$false)
@{jobId=${quote(jobId)};prepared=$true}|ConvertTo-Json -Compress`, signal);
      const worker = await readFile(new URL("../../../bridge/forge/guest/ida_owned_worker.ps1", import.meta.url));
      const guard = await readFile(new URL("../../../bridge/forge/guest/session_guard.ps1", import.meta.url));
      const spec = Buffer.from(JSON.stringify({ job_id: jobId, frontend: "idat", frontend_sha256: this.idatSha256, input_sha256: input.sha256, input_bytes: input.bytes, wrapper_sha256: wrapper.sha256, timeout_seconds: timeoutSeconds, arguments: ["-c", "-A", `-L${root}\\ida.log`, `-S\"${root}\\wrapper.py\"`, `${root}\\target.exe`] }));
      for (const [name, bytes] of [["worker.ps1", worker], ["guard.ps1", guard], ["spec.json", spec]] as const) {
        this.#activeOwner(signal); await this.transport.writeSmallFile(`${root}\\${name}`, bytes);
      }
      this.#activeOwner(signal);
      owned.cleanupConfirmed = false; // From this dispatch onward, absence is not assumed.
      await this.#run(binding, `
$jobRoot=${quote(root)}
${([["worker.ps1", worker], ["guard.ps1", guard], ["spec.json", spec]] as const).map(([name, bytes]) => `if((Get-FileHash -LiteralPath (Join-Path $jobRoot ${quote(name)}) -Algorithm SHA256).Hash.ToLowerInvariant() -cne ${quote(digest(bytes))}){throw 'Shipped job member identity changed'}`).join("\n")}
if(Test-Path -LiteralPath (Join-Path $jobRoot 'stop.request')){throw 'Job was cancelled before launch'}
$arguments=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$jobRoot+'\\worker.ps1"'),'-JobRoot',('"'+$jobRoot+'"'))
$worker=Start-Process -FilePath ($PSHOME+'\\powershell.exe') -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput ($jobRoot+'\\worker.stdout') -RedirectStandardError ($jobRoot+'\\worker.stderr')
try{$receipt=@{jobId=${quote(jobId)};workerPid=$worker.Id;workerStartUtc=$worker.StartTime.ToUniversalTime().ToString('o')};$text=$receipt|ConvertTo-Json -Compress;Write-NewBytes (Join-Path $jobRoot 'launch.json') ([Text.Encoding]::UTF8.GetBytes($text));$text}finally{$worker.Dispose()}`, signal);
      // The real bridge may finish launch with empty stdout. The generated
      // program persists this receipt before responding; recover it read-only,
      // never resubmit a launch because its immediate acknowledgement is lost.
      const launch = launchSchema(jobId).parse(JSON.parse(Buffer.from(await this.transport.readSmallFile(`${root}\\launch.json`, 4096)).toString("utf8")));
      owned.launchIdentity = { pid: launch.workerPid, start: launch.workerStartUtc };
      return job;
      } finally { this.#submitting = false; }
    });
  }

  inspect(binding: GuestCaseBinding, jobId: string, signal?: AbortSignal): Promise<GuestIdaJobObservation> {
    return this.#track(async () => {
      signal?.throwIfAborted(); const owned = this.#require(binding, jobId);
      const facts = await this.#program(binding, this.#observeProgram(owned));
      if (!owned.launchIdentity) {
        const launch = launchSchema(jobId).safeParse(valueOf(facts, "launch"));
        if (launch.success) owned.launchIdentity = { pid: launch.data.workerPid, start: launch.data.workerStartUtc };
      }
      const ready = receiptSchema.safeParse(valueOf(facts, "containment-ready"));
      const cleanup = z.object({ job_id: z.literal(jobId), worker_pid: z.int().positive(), worker_start_utc: z.string(), guard_pid: z.int().positive(), guard_start_utc: z.string(), active_processes: z.literal(0), reason: z.string() }).safeParse(valueOf(facts, "containment-cleanup"));
      const processFacts = z.array(z.object({ pid: z.int().positive(), expectedStart: z.string(), outcome: z.enum(["same_process_alive", "different_process", "not_found", "unknown"]) })).safeParse(facts.processes);
      let confirmed = false;
      if (ready.success && cleanup.success && ready.data.job_id === jobId && processFacts.success && owned.launchIdentity?.pid === ready.data.worker_pid && owned.launchIdentity.start === ready.data.worker_start_utc) {
        const references = ["worker_pid", "worker_start_utc", "guard_pid", "guard_start_utc"] as const;
        confirmed = references.every(key => ready.data[key] === cleanup.data[key]) && [[ready.data.worker_pid, ready.data.worker_start_utc], [ready.data.guard_pid, ready.data.guard_start_utc]].every(([pid, stamp]) => processFacts.data.some(value => value.pid === pid && value.expectedStart === stamp && (value.outcome === "not_found" || value.outcome === "different_process")));
      }
      owned.cleanupConfirmed = confirmed;
      const completion = jsonObjectSchema.safeParse(valueOf(facts, "completion"));
      const result = jsonObjectSchema.safeParse(valueOf(facts, "result"));
      if (!confirmed && !ready.success && completion.success && completion.data.job_id === jobId && completion.data.ida_launch_attempted === false && owned.launchIdentity && completion.data.worker_pid === owned.launchIdentity.pid && completion.data.worker_start_utc === owned.launchIdentity.start && processFacts.success) {
        const needed: { pid: number; start: string }[] = [owned.launchIdentity];
        let complete = completion.data.guard_launch_attempted === false;
        if (completion.data.guard_launch_attempted === true) {
          const guard = z.object({ job_id: z.literal(jobId), guard_pid: z.int().positive(), guard_start_utc: z.string().regex(PID_STAMP) }).safeParse(valueOf(facts, "guard-started"));
          if (guard.success) { needed.push({ pid: guard.data.guard_pid, start: guard.data.guard_start_utc }); complete = true; }
        }
        confirmed = complete && needed.every(expected => processFacts.data.some(observed => observed.pid === expected.pid && observed.expectedStart === expected.start && (observed.outcome === "not_found" || observed.outcome === "different_process")));
        owned.cleanupConfirmed = confirmed;
      }
      let state: GuestIdaJobObservation["state"] = ready.success ? "running" : "starting";
      if (cleanup.success || completion.success) state = "finishing";
      if (confirmed) {
        const reason = cleanup.success ? cleanup.data.reason : "";
        state = reason === "absolute_deadline" || completion.success && completion.data.state === "timed_out" ? "timed_out" : reason === "stop_deadline" || completion.success && completion.data.state === "stopped" ? "stopped" : result.success && result.data.ok === true && result.data.idb_saved === true ? "completed" : "failed";
      }
      return { jobId, state, cleanupConfirmed: confirmed, facts };
    });
  }

  stop(binding: GuestCaseBinding, jobId: string, signal?: AbortSignal): Promise<GuestIdaJobObservation> {
    return this.#track(async () => {
      signal?.throwIfAborted(); const owned = this.#require(binding, jobId);
      if (!owned.cleanupConfirmed) await this.#program(binding, `
$path=${quote(`${owned.job.root}\\stop.request`)};Assert-PlainPath $path
if(!(Test-Path -LiteralPath $path)){Write-NewBytes $path ([Text.Encoding]::ASCII.GetBytes('stop'))}
@{jobId=${quote(jobId)};stopRequested=$true}|ConvertTo-Json -Compress`);
      return this.inspect(binding, jobId, signal);
    });
  }

  #observeProgram(owned: OwnedJob): string {
    return `
$jobRoot=${quote(owned.job.root)};Assert-PlainPath $jobRoot
$facts=@{};$inlineBudget=8192
foreach($name in @('launch','worker-ready','guard-started','runtime','completion','containment-ready','containment-cleanup','result')){
  $path=Join-Path $jobRoot ($name+'.json');Assert-PlainPath $path
  if(Test-Path -LiteralPath $path -PathType Leaf){
    $item=Get-Item -LiteralPath $path
    if($item.Length -gt 16777216){throw 'Job receipt exceeds bounded extent'}
    $entry=@{present=$true;bytes=$item.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();path=$path;inline_omitted=$true}
    if($item.Length -le 4096 -and $item.Length -le $inlineBudget){try{$entry.value=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json;$entry.inline_omitted=$false;$inlineBudget-=$item.Length}catch{$entry.invalid_json=$true}}
    $facts[$name]=$entry
  }else{$facts[$name]=@{present=$false}}
}
$references=@()
if($facts['containment-ready'].value){$ready=$facts['containment-ready'].value;$references=@(@{pid=$ready.worker_pid;stamp=$ready.worker_start_utc},@{pid=$ready.guard_pid;stamp=$ready.guard_start_utc})}
elseif($facts['completion'].value -and $facts['launch'].value){$early=$facts['completion'].value;$launch=$facts['launch'].value;$references=@(@{pid=$launch.workerPid;stamp=$launch.workerStartUtc});if($early.guard_launch_attempted -eq $true -and $facts['guard-started'].value){$guard=$facts['guard-started'].value;$references+=@{pid=$guard.guard_pid;stamp=$guard.guard_start_utc}}}
$processes=@(foreach($reference in $references){
  $outcome='unknown';$process=$null
  try{$process=[Diagnostics.Process]::GetProcessById([int]$reference.pid);if($process.StartTime.ToUniversalTime().ToString('o') -ceq $reference.stamp){$outcome=if($process.HasExited){'not_found'}else{'same_process_alive'}}else{$outcome='different_process'}}
  catch [ArgumentException]{$outcome='not_found'}catch{$outcome='unknown'}finally{if($process){$process.Dispose()}}
  @{pid=[int]$reference.pid;expectedStart=[string]$reference.stamp;outcome=$outcome}
})
$facts.processes=$processes;$facts.jobId=${quote(owned.job.jobId)}
$logs=@{}
foreach($name in @('worker.stderr','guard.stderr','ida.log')){
  $path=Join-Path $jobRoot $name;Assert-PlainPath $path
  if(Test-Path -LiteralPath $path -PathType Leaf){
    $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try{$extent=$stream.Length;$count=[int][Math]::Min(768,$extent);[void]$stream.Seek(-$count,[IO.SeekOrigin]::End);$buffer=New-Object byte[] $count;$used=$stream.Read($buffer,0,$count);$logs[$name]=@{bytes=$extent;tail=[Text.Encoding]::UTF8.GetString($buffer,0,$used);truncated=($extent -gt $used)}}finally{$stream.Dispose()}
  }
}
$facts.logs=$logs
$facts|ConvertTo-Json -Depth 14 -Compress`;
  }
  #require(binding: GuestCaseBinding, jobId: string): OwnedJob {
    const owned = this.#jobs.get(jobId);
    if (!owned || owned.binding !== binding) throw new Error("Guest job is unknown or belongs to another case owner");
    return owned;
  }
  #activeOwner(signal?: AbortSignal): void { signal?.throwIfAborted(); if (this.#closed) throw new Error("Guest IDA job owner is closed"); }
  #track<Value>(operation: () => Promise<Value>): Promise<Value> {
    const pending = operation(); this.#active.add(pending);
    void pending.finally(() => this.#active.delete(pending)).catch(() => undefined); return pending;
  }
  async #run(binding: GuestCaseBinding, body: string, signal?: AbortSignal) {
    signal?.throwIfAborted();
    const result = await this.transport.runCaseProgram({ source: guestCaseProgramPrefix(binding) + body, timeoutMs: 10000, cwd: "C:\\CodexBridge" });
    if (result.timedOut || result.exitCode !== 0 || result.stderr !== "") throw new Error("Fixed guest job operation failed; owned job retained for recovery");
    return result;
  }
  async #program(binding: GuestCaseBinding, body: string, signal?: AbortSignal) {
    const result = await this.#run(binding, body, signal);
    try { return jsonObjectSchema.parse(JSON.parse(result.stdout)); } catch { throw new Error("Fixed guest job operation returned invalid facts; owner retained"); }
  }
  async close(): Promise<void> {
    this.#closed = true; await Promise.allSettled(this.#active);
    const unsettled = [...this.#jobs.values()].filter(value => !value.cleanupConfirmed);
    const deadline = Date.now() + 25000;
    for (const owned of unsettled) {
      await this.stop(owned.binding, owned.job.jobId, AbortSignal.timeout(Math.max(1, deadline - Date.now())));
      while (!owned.cleanupConfirmed && Date.now() < deadline) {
        await new Promise(resolve => setTimeout(resolve, 150));
        await this.inspect(owned.binding, owned.job.jobId, AbortSignal.timeout(Math.max(1, deadline - Date.now())));
      }
    }
    const remaining = [...this.#jobs.values()].filter(value => !value.cleanupConfirmed);
    if (remaining.length) throw new Error(`Guest IDA cleanup unconfirmed; retaining ${remaining.map(value => value.job.root).join(", ")}`);
  }
}
const valueOf = (facts: Readonly<Record<string, unknown>>, name: string): unknown => {
  const entry = z.object({ value: z.unknown() }).safeParse(facts[name]); return entry.success ? entry.data.value : undefined;
};
const launchSchema = (jobId: string) => z.object({ jobId: z.literal(jobId), workerPid: z.int().positive(), workerStartUtc: z.string().regex(PID_STAMP) });
