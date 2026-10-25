# Pure owned-worker implementation migrated from the existing workstation adapter.
param([Parameter(Mandatory=$true)][string]$JobRoot)
$ErrorActionPreference='Stop'
$clock=[Diagnostics.Stopwatch]::StartNew()
$spec=Get-Content -LiteralPath ($JobRoot+'\spec.json') -Raw|ConvertFrom-Json
function Save-State([string]$name,$value) {
  $path=$JobRoot+'\'+$name+'.json'
  [IO.File]::WriteAllText(($path+'.tmp'),($value|ConvertTo-Json -Depth 8 -Compress),[Text.UTF8Encoding]::new($false))
  Move-Item -LiteralPath ($path+'.tmp') -Destination $path -Force
}
$stamp=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToString('o')
Save-State 'worker-ready' @{job_id=$spec.job_id;worker_pid=$PID;worker_start_utc=$stamp}
$child=$null;$state='startup_failed';$failure=$null
$guardLaunchAttempted=$false;$idaLaunchAttempted=$false
try {
  if($spec.job_id -notmatch '^ida-job-[a-f0-9]{24}$' -or $spec.timeout_seconds -lt 1 -or $spec.timeout_seconds -gt 50){throw 'invalid_spec'}
  if($spec.frontend -ne 'idat'){throw 'invalid_frontend'}
  if(Test-Path -LiteralPath ($JobRoot+'\stop.request')){throw 'cancelled_before_guard'}
  $guardArgs=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$JobRoot+'\guard.ps1"'),'-JobRoot',('"'+$JobRoot+'"'),'-WorkerPid',[string]$PID,'-WorkerStamp',$stamp,'-Lifetime','50')
  $guardLaunchAttempted=$true
  $guard=Start-Process powershell.exe -ArgumentList $guardArgs -WindowStyle Hidden -PassThru -RedirectStandardOutput ($JobRoot+'\guard.stdout') -RedirectStandardError ($JobRoot+'\guard.stderr')
  Save-State 'guard-started' @{job_id=$spec.job_id;guard_pid=$guard.Id;guard_start_utc=$guard.StartTime.ToUniversalTime().ToString('o')}
  while(-not(Test-Path -LiteralPath ($JobRoot+'\containment-ready.json'))){
    if($clock.Elapsed.TotalSeconds -ge 8 -or $guard.HasExited){throw 'guard_not_ready'}
    Start-Sleep -Milliseconds 50
  }
  $ready=Get-Content -LiteralPath ($JobRoot+'\containment-ready.json') -Raw|ConvertFrom-Json
  if($ready.job_id -ne $spec.job_id -or $ready.worker_pid -ne $PID -or $ready.worker_start_utc -ne $stamp){throw 'guard_identity_mismatch'}
  if(Test-Path -LiteralPath ($JobRoot+'\stop.request')){throw 'cancelled_before_ida'}
  $exe='C:\ctf\IDA Professional 9.1\idat.exe'
  if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $spec.frontend_sha256){throw 'configured_idat_identity_changed'}
  $target=Join-Path $JobRoot 'target.exe';$wrapper=Join-Path $JobRoot 'wrapper.py'
  if((Get-Item -LiteralPath $target).Length -ne $spec.input_bytes -or (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -cne $spec.input_sha256){throw 'target_identity_changed_before_launch'}
  if((Get-FileHash -LiteralPath $wrapper -Algorithm SHA256).Hash.ToLowerInvariant() -cne $spec.wrapper_sha256){throw 'wrapper_identity_changed_before_launch'}
  $idaLaunchAttempted=$true
  $child=Start-Process -FilePath $exe -ArgumentList @($spec.arguments) -WorkingDirectory $JobRoot -WindowStyle Hidden -PassThru
  $childStamp=$child.StartTime.ToUniversalTime().ToString('o')
  Save-State 'runtime' @{schema_version=3;job_id=$spec.job_id;pid=$child.Id;exists=$true;start_utc=$childStamp;worker_pid=$PID;worker_start_utc=$stamp;guard_pid=$ready.guard_pid;guard_start_utc=$ready.guard_start_utc;launcher='existing_bridge_owned_worker'}
  $state='exited'
  while(-not $child.WaitForExit(100)) {
    if(Test-Path -LiteralPath ($JobRoot+'\stop.request')){$state='stopped';break}
    if($clock.Elapsed.TotalSeconds -ge $spec.timeout_seconds){$state='timed_out';break}
  }
} catch {$failure=$_.Exception.GetType().Name}
finally {
  # Worker intent is not process-tree cleanup proof. The independent guard owns it.
  $receipt=@{job_id=$spec.job_id;state=$state;error_type=$failure;worker_pid=$PID;worker_start_utc=$stamp;guard_launch_attempted=$guardLaunchAttempted;ida_launch_attempted=$idaLaunchAttempted}
  if($child){$receipt.pid=$child.Id;$receipt.process_start_utc=$childStamp}
  Save-State 'completion' $receipt
  if($child){$child.Dispose()}
}
