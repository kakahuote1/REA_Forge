import { randomUUID } from "node:crypto";
import type { GuestCaseBinding } from "../../application/forge/GuestRuntimeBinding.js";
import type { GuestStagedFile } from "../../application/forge/GuestCaseFilesPort.js";
import { GUEST_METADATA_PROBE } from "./guestMetadataProbe.js";

const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;
const sha = /^[a-f0-9]{64}$/u;
export const GUEST_CASE_PARENT = "C:\\CodexBridge\\forge-cases";
export const CHUNK_BYTES = 40 * 1024;
export const MAX_TRANSFER_BYTES = 16 * 1024 * 1024;

export const casePath = (binding: GuestCaseBinding): string => {
  if (!uuid.test(binding.caseId))
    throw new Error("Invalid internal guest case identity");
  return `${GUEST_CASE_PARENT}\\${binding.caseId}`;
};
export const newTransfer = (
  binding: GuestCaseBinding,
  bytes: number,
  digest: string,
): GuestStagedFile => {
  if (
    !Number.isSafeInteger(bytes) ||
    bytes < 0 ||
    bytes > MAX_TRANSFER_BYTES ||
    !sha.test(digest)
  )
    throw new Error("Invalid bounded transfer identity");
  const transferId = randomUUID();
  return {
    transferId,
    path: `${casePath(binding)}\\${transferId}.bin`,
    bytes,
    sha256: digest,
  };
};
export const chunkPath = (
  binding: GuestCaseBinding,
  file: GuestStagedFile,
  index: number,
): string => {
  validateFile(binding, file);
  if (
    !Number.isSafeInteger(index) ||
    index < 0 ||
    index >= Math.max(1, Math.ceil(MAX_TRANSFER_BYTES / CHUNK_BYTES))
  )
    throw new Error("Invalid internal chunk index");
  return `${casePath(binding)}\\${file.transferId}\\${index.toString().padStart(6, "0")}.part`;
};
const quote = (value: string): string => `'${value.replaceAll("'", "''")}'`;
const marker = (binding: GuestCaseBinding) =>
  JSON.stringify({ caseId: binding.caseId, runtime: binding.runtime });
const validateFile = (
  binding: GuestCaseBinding,
  file: GuestStagedFile,
): void => {
  if (
    !uuid.test(file.transferId) ||
    !sha.test(file.sha256) ||
    !Number.isSafeInteger(file.bytes) ||
    file.bytes < 0 ||
    file.bytes > MAX_TRANSFER_BYTES ||
    file.path !== `${casePath(binding)}\\${file.transferId}.bin`
  )
    throw new Error("File does not belong to the exact bounded guest case");
};

/** Every modifying program attributes its direct parent before touching the case. */
const prefix = (binding: GuestCaseBinding, requireMarker = true): string => {
  const source = GUEST_METADATA_PROBE.trim();
  const runtime = binding.runtime;
  if (
    !/^[1-9][0-9]{0,18}$/u.test(runtime.bridgeProcessStartTicks) ||
    !Number.isSafeInteger(runtime.bridgeProcessId) ||
    runtime.bridgeProcessId <= 0
  )
    throw new Error("Invalid bridge process identity");
  return `$ErrorActionPreference='Stop'
$observed = (& { ${source} }) | ConvertFrom-Json
if ($observed.computerName -cne ${quote(runtime.computerName)} -or $observed.bridgeProcessId -ne ${runtime.bridgeProcessId} -or $observed.bridgeProcessStartTicks -cne ${quote(runtime.bridgeProcessStartTicks)}) { throw 'Guest runtime changed before case operation' }
$root=${quote(casePath(binding))}
$expectedMarker=${quote(marker(binding))}
function Assert-PlainPath([string]$path) {
  $cursor=[IO.Path]::GetFullPath($path)
  while ($cursor) {
    if ([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) {
      if (([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Guest case path traverses a reparse point' }
    }
    $parent=[IO.Path]::GetDirectoryName($cursor)
    if ($parent -eq $cursor) { break }; $cursor=$parent
  }
}
function Write-NewBytes([string]$path,[byte[]]$bytes) {
  $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
}
Assert-PlainPath $root
${requireMarker ? `$ownerFile=Join-Path $root 'owner.json'; Assert-PlainPath $ownerFile
if (![IO.Directory]::Exists($root) -or !(Test-Path -LiteralPath $ownerFile -PathType Leaf) -or (Get-Item -LiteralPath $ownerFile).Length -gt 4096 -or [IO.File]::ReadAllText($ownerFile) -cne $expectedMarker) { throw 'Guest case ownership marker differs or is absent' }` : ""}
`;
};

export const allocateCaseProgram = (
  binding: GuestCaseBinding,
): string => `${prefix(binding, false)}
if ([IO.File]::Exists($root) -or [IO.Directory]::Exists($root)) { throw 'Guest case already exists; refusing to borrow it' }
[void][IO.Directory]::CreateDirectory(${quote(GUEST_CASE_PARENT)})
[void][IO.Directory]::CreateDirectory($root)
Assert-PlainPath $root
Write-NewBytes (Join-Path $root 'owner.json') ([Text.Encoding]::UTF8.GetBytes($expectedMarker))
@{caseId=${quote(binding.caseId)};path=$root;allocated=$true}|ConvertTo-Json -Compress
`;

export const prepareTransferProgram = (
  binding: GuestCaseBinding,
  file: GuestStagedFile,
): string => {
  validateFile(binding, file);
  return `${prefix(binding)}
$folder=Join-Path $root ${quote(file.transferId)}
if ([IO.Directory]::Exists($folder) -or [IO.File]::Exists($folder) -or [IO.File]::Exists(${quote(file.path)})) { throw 'Transfer identity already exists' }
[void][IO.Directory]::CreateDirectory($folder)
@{transferId=${quote(file.transferId)};prepared=$true}|ConvertTo-Json -Compress
`;
};

export const finishTransferProgram = (
  binding: GuestCaseBinding,
  file: GuestStagedFile,
): string => {
  validateFile(binding, file);
  const count = Math.ceil(file.bytes / CHUNK_BYTES);
  return `${prefix(binding)}
$folder=Join-Path $root ${quote(file.transferId)}
Assert-PlainPath $folder
$parts=@([IO.Directory]::GetFiles($folder))
if ($parts.Count -ne ${count} -or [IO.Directory]::GetDirectories($folder).Length -ne 0) { throw 'Unexpected transfer members' }
$pending=Join-Path $root ${quote(`${file.transferId}.pending`)}
$output=[IO.File]::Open($pending,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try {
  for ($i=0;$i -lt ${count};$i++) {
    $part=Join-Path $folder ($i.ToString('D6')+'.part'); Assert-PlainPath $part
    $expected=[Math]::Min(${CHUNK_BYTES},${file.bytes}-($i*${CHUNK_BYTES}))
    $input=[IO.File]::Open($part,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try { if ($input.Length -ne $expected) { throw 'Transfer chunk extent differs' }; $input.CopyTo($output) } finally { $input.Dispose() }
  }
} finally { $output.Dispose() }
if ((Get-Item -LiteralPath $pending).Length -ne ${file.bytes} -or (Get-FileHash -LiteralPath $pending -Algorithm SHA256).Hash.ToLowerInvariant() -cne ${quote(file.sha256)}) { throw 'Whole transfer digest differs' }
[IO.File]::Move($pending,${quote(file.path)})
foreach ($part in $parts) { [IO.File]::Delete($part) }
[IO.Directory]::Delete($folder,$false)
@{transferId=${quote(file.transferId)};path=${quote(file.path)};bytes=${file.bytes};sha256=${quote(file.sha256)}}|ConvertTo-Json -Compress
`;
};

/** Readback uses only the exact owned source, hash-checked before slicing. */
export const prepareReadProgram = (
  binding: GuestCaseBinding,
  file: GuestStagedFile,
): string => {
  validateFile(binding, file);
  return `${prefix(binding)}
$source=${quote(file.path)}; Assert-PlainPath $source
$readFolder=Join-Path $root ${quote(`${file.transferId}.read`)}
if ([IO.Directory]::Exists($readFolder) -or [IO.File]::Exists($readFolder)) { throw 'Readback already pending' }
$input=[IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try {
  $hasher=[Security.Cryptography.SHA256]::Create()
  try { $digest=([BitConverter]::ToString($hasher.ComputeHash($input))).Replace('-','').ToLowerInvariant() } finally { $hasher.Dispose() }
  if ($input.Length -ne ${file.bytes} -or $digest -cne ${quote(file.sha256)}) { throw 'Staged guest source changed before readback' }
  [void][IO.Directory]::CreateDirectory($readFolder); $input.Position=0
  $buffer=New-Object byte[] ${CHUNK_BYTES};$i=0
  while ($input.Position -lt $input.Length) {
    $wanted=[int][Math]::Min($buffer.Length,$input.Length-$input.Position);$used=0
    while ($used -lt $wanted) { $read=$input.Read($buffer,$used,$wanted-$used);if ($read -eq 0) { throw 'Unexpected guest read end' };$used+=$read }
    $part=Join-Path $readFolder ($i.ToString('D6')+'.part')
    $output=[IO.File]::Open($part,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $output.Write($buffer,0,$used) } finally { $output.Dispose() };$i++
  }
} finally { $input.Dispose() }
@{transferId=${quote(file.transferId)};prepared=$true}|ConvertTo-Json -Compress
`;
};

export const releaseCaseProgram = (
  binding: GuestCaseBinding,
): string => `${prefix(binding)}
# Validate the complete small owned tree before deleting any member. No recursive shell delete.
$entries=New-Object 'Collections.Generic.List[IO.FileSystemInfo]'
$queue=New-Object 'Collections.Generic.Queue[string]';$queue.Enqueue($root)
while ($queue.Count -gt 0) {
  $directory=$queue.Dequeue();Assert-PlainPath $directory
  foreach ($entry in ([IO.DirectoryInfo]$directory).EnumerateFileSystemInfos()) {
    if ($entries.Count -ge 2000) { throw 'Guest case cleanup exceeds bounded inventory' }
    Assert-PlainPath $entry.FullName;$entries.Add($entry)
    if (($entry.Attributes -band [IO.FileAttributes]::Directory) -ne 0) { $queue.Enqueue($entry.FullName) }
  }
}
foreach ($entry in @($entries | Sort-Object { $_.FullName.Length } -Descending)) {
  if (($entry.Attributes -band [IO.FileAttributes]::Directory) -ne 0) { [IO.Directory]::Delete($entry.FullName,$false) } else { [IO.File]::Delete($entry.FullName) }
}
[IO.Directory]::Delete($root,$false)
@{caseId=${quote(binding.caseId)};released=$true}|ConvertTo-Json -Compress
`;

export const clearReadProgram = (
  binding: GuestCaseBinding,
  file: GuestStagedFile,
): string => {
  validateFile(binding, file);
  return `${prefix(binding)}
$folder=Join-Path $root ${quote(`${file.transferId}.read`)};Assert-PlainPath $folder
if ([IO.Directory]::GetDirectories($folder).Length -ne 0) { throw 'Unexpected readback directory' }
$parts=@([IO.Directory]::GetFiles($folder));if ($parts.Count -ne ${Math.ceil(file.bytes / CHUNK_BYTES)}) { throw 'Readback extent differs' }
foreach ($part in $parts) { Assert-PlainPath $part;if ([IO.Path]::GetFileName($part) -notmatch '^\\d{6}\\.part$') { throw 'Unexpected readback member' } }
foreach ($part in $parts) { [IO.File]::Delete($part) };[IO.Directory]::Delete($folder,$false)
@{transferId=${quote(file.transferId)};cleared=$true}|ConvertTo-Json -Compress
`;
};
