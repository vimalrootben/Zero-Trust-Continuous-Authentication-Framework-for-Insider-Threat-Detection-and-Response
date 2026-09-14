# Exact-identity Windows process termination with PID-reuse protection.
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)][int]$ProcessId,
    [Parameter(Mandatory=$true)][string]$ProcessName,
    [Parameter(Mandatory=$true)][string]$ProcessPath,
    [Parameter(Mandatory=$true)][string]$ProcessCreatedAt,
    [Parameter(Mandatory=$true)][int]$AgentProcessId
)
$ErrorActionPreference = 'Stop'
$protectedNames = @('system','registry','smss','csrss','wininit','services','lsass','winlogon','svchost','securityhealthservice','sense','msmpeng','wazuh-agent','sysmon','sysmon64')
try {
    if ($ProcessId -le 4 -or $ProcessId -eq $AgentProcessId) { throw 'Protected process target' }
    $target = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction Stop
    if (-not $target) { throw 'Target process does not exist' }
    $actualName = [IO.Path]::GetFileName($target.ExecutablePath)
    if (-not $actualName) { $actualName = $target.Name }
    if (-not [String]::Equals($actualName, [IO.Path]::GetFileName($ProcessName), [StringComparison]::OrdinalIgnoreCase)) { throw 'PID identity name changed' }
    if (-not $target.ExecutablePath -or -not [String]::Equals([IO.Path]::GetFullPath($target.ExecutablePath), [IO.Path]::GetFullPath($ProcessPath), [StringComparison]::OrdinalIgnoreCase)) { throw 'PID executable path changed' }
    $expectedCreated = [DateTimeOffset]::Parse($ProcessCreatedAt).ToUniversalTime()
    $actualCreated = ([DateTimeOffset]$target.CreationDate).ToUniversalTime()
    if ([Math]::Abs(($actualCreated - $expectedCreated).TotalSeconds) -gt 1) { throw 'PID creation time changed' }
    if ($protectedNames -contains [IO.Path]::GetFileNameWithoutExtension($actualName).ToLowerInvariant()) { throw 'Protected system/security process target' }
    Stop-Process -Id $ProcessId -Force -ErrorAction Stop
    try { Wait-Process -Id $ProcessId -Timeout 10 -ErrorAction Stop } catch { }
    if (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue) { throw 'Target process remains active' }
    Write-Output 'PROCESS_NOT_ACTIVE'
    exit 0
} catch {
    Write-Error $_
    exit 1
}
