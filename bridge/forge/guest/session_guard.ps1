# Existing independent kill-on-close Windows JobObject guard, without the old control plane.
param([string]$JobRoot,[int]$WorkerPid,[string]$WorkerStamp,[int]$Lifetime)
$ErrorActionPreference='Stop'
$clock=[Diagnostics.Stopwatch]::StartNew()
$spec=Get-Content -LiteralPath ($JobRoot+'\spec.json') -Raw|ConvertFrom-Json
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public sealed class ForgeSessionJob : IDisposable {
  IntPtr handle;
  [StructLayout(LayoutKind.Sequential)] struct BasicLimit {
    public long ProcessTime, JobTime; public uint Flags;
    public UIntPtr MinWorkingSet, MaxWorkingSet; public uint ActiveLimit;
    public UIntPtr Affinity; public uint Priority, Scheduling;
  }
  [StructLayout(LayoutKind.Sequential)] struct IoCounters {
    public ulong ReadCount, WriteCount, OtherCount, ReadBytes, WriteBytes, OtherBytes;
  }
  [StructLayout(LayoutKind.Sequential)] struct ExtendedLimit {
    public BasicLimit Basic; public IoCounters Io;
    public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
  }
  [StructLayout(LayoutKind.Sequential)] struct Accounting {
    public long UserTime, KernelTime, PeriodUserTime, PeriodKernelTime;
    public uint PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses;
  }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attrs,string name);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int type,ref ExtendedLimit limits,uint size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int type,out Accounting value,uint size,IntPtr returned);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool member);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  public ForgeSessionJob() {
    handle=CreateJobObject(IntPtr.Zero,null);
    if(handle==IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
    ExtendedLimit limits=new ExtendedLimit(); limits.Basic.Flags=0x2000;
    if(!SetInformationJobObject(handle,9,ref limits,(uint)Marshal.SizeOf(typeof(ExtendedLimit)))) {
      int code=Marshal.GetLastWin32Error(); Dispose(); throw new System.ComponentModel.Win32Exception(code);
    }
  }
  public void Assign(System.Diagnostics.Process process) {
    bool member;
    if(!IsProcessInJob(process.Handle,handle,out member)) throw new System.ComponentModel.Win32Exception();
    if(!member && !AssignProcessToJobObject(handle,process.Handle)) throw new System.ComponentModel.Win32Exception();
  }
  public uint ActiveCount() {
    Accounting value;
    if(!QueryInformationJobObject(handle,1,out value,(uint)Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero)) throw new System.ComponentModel.Win32Exception();
    return value.ActiveProcesses;
  }
  public void Terminate() { if(!TerminateJobObject(handle,0xc000013a)) throw new System.ComponentModel.Win32Exception(); }
  public void Dispose() { if(handle!=IntPtr.Zero) { CloseHandle(handle); handle=IntPtr.Zero; } }
}
'@
function Save-State([string]$name,$value) {
  $text=$value|ConvertTo-Json -Depth 5 -Compress
  [IO.File]::WriteAllText(($JobRoot+'\'+$name+'.tmp'),$text,[Text.UTF8Encoding]::new($false))
  [IO.File]::Move(($JobRoot+'\'+$name+'.tmp'),($JobRoot+'\'+$name+'.json'))
}
$job=$null
try {
  $worker=Get-Process -Id $WorkerPid -ErrorAction Stop
  if($worker.StartTime.ToUniversalTime().ToString('o') -cne $WorkerStamp){throw 'worker_identity_mismatch'}
  $job=[ForgeSessionJob]::new();$job.Assign($worker)
  $guardStamp=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToString('o')
  Save-State 'containment-ready' @{job_id=$spec.job_id;worker_pid=$WorkerPid;worker_start_utc=$WorkerStamp;guard_pid=$PID;guard_start_utc=$guardStamp}
  $reason='worker_exited'
  while(-not $worker.HasExited) {
    if($clock.Elapsed.TotalSeconds -ge $Lifetime){$reason='absolute_deadline';break}
    if((Test-Path -LiteralPath ($JobRoot+'\stop.request')) -and -not $stopClock){$stopClock=[Diagnostics.Stopwatch]::StartNew()}
    if($stopClock -and $stopClock.Elapsed.TotalSeconds -ge 4){$reason='stop_deadline';break}
    Start-Sleep -Milliseconds 100;$worker.Refresh()
  }
  $job.Terminate();$cleanup=[Diagnostics.Stopwatch]::StartNew()
  while($job.ActiveCount() -ne 0 -and $cleanup.Elapsed.TotalSeconds -lt 2){Start-Sleep -Milliseconds 50}
  Save-State 'containment-cleanup' @{job_id=$spec.job_id;worker_pid=$WorkerPid;worker_start_utc=$WorkerStamp;guard_pid=$PID;guard_start_utc=$guardStamp;active_processes=$job.ActiveCount();reason=$reason}
} finally {if($job){$job.Dispose()}}
