# Predefined exact-process response. Policy selection remains in Python.
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)][int]$ProcessId,
    [Parameter(Mandatory=$true)][string]$ProcessName
)
$ErrorActionPreference = 'Stop'
try {
    if ($ProcessId -le 4) { throw 'Protected/system process ID' }
    $target = Get-Process -Id $ProcessId -ErrorAction Stop
    $expected = [IO.Path]::GetFileNameWithoutExtension($ProcessName)
    if (-not [String]::Equals($target.ProcessName, $expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Process name does not own the requested process ID'
    }
    Stop-Process -InputObject $target -Force -ErrorAction Stop
    if (-not $target.WaitForExit(10000)) { throw 'Target process remains active' }
    Write-Output 'PROCESS_NOT_ACTIVE'
    exit 0
} catch {
    Write-Error $_
    exit 1
}
