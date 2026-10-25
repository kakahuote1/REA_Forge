/** Fixed trusted metadata only. It is never assembled from agent-supplied code. */
export const GUEST_METADATA_PROBE = String.raw`
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class ForgeBridgeParent {
    [StructLayout(LayoutKind.Sequential)]
    private struct BasicInformation {
        public int ExitStatus;
        public IntPtr PebBaseAddress;
        public UIntPtr AffinityMask;
        public int BasePriority;
        public UIntPtr UniqueProcessId;
        public UIntPtr InheritedFromUniqueProcessId;
    }
    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr process, int kind,
        out BasicInformation information, int length, out int returned);
    public static int Read() {
        using (Process self = Process.GetCurrentProcess()) {
            BasicInformation information;
            int returned;
            int size = Marshal.SizeOf(typeof(BasicInformation));
            if (NtQueryInformationProcess(self.Handle, 0, out information, size, out returned) != 0 || returned != size)
                throw new InvalidOperationException("Parent process identity is unavailable");
            ulong parent = information.InheritedFromUniqueProcessId.ToUInt64();
            if (parent == 0 || parent > Int32.MaxValue)
                throw new InvalidOperationException("Parent process identity is invalid");
            return (int)parent;
        }
    }
}
'@
$self = [Diagnostics.Process]::GetCurrentProcess()
$owner = [Diagnostics.Process]::GetProcessById([ForgeBridgeParent]::Read())
try {
    $created = $owner.StartTime.ToUniversalTime()
    if ($owner.HasExited -or $created -gt $self.StartTime.ToUniversalTime()) {
        throw 'Bridge parent identity changed during observation'
    }
    [ordered]@{
        computerName = [Environment]::MachineName
        bridgeProcessId = $owner.Id
        bridgeProcessStartTicks = $created.Ticks.ToString([Globalization.CultureInfo]::InvariantCulture)
    } | ConvertTo-Json -Compress
} finally {
    $owner.Dispose()
    $self.Dispose()
}
`;
