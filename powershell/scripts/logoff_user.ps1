# Identity validation and verification belong to the Agent executor.
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$UserName,
    [Parameter(Mandatory=$true)]
    [ValidateRange(1, 2147483647)]
    [int]$SessionId
)
$ErrorActionPreference = 'Stop'
try {
    & "$env:SystemRoot\System32\logoff.exe" $SessionId
    if ($LASTEXITCODE -ne 0) {
        throw "Windows logoff failed with exit code $LASTEXITCODE"
    }
    Write-Output 'LOGOFF_REQUEST_COMPLETED'
    # Agent verifies SESSION_NOT_ACTIVE before reporting SUCCESS.
    exit 0
} catch {
    Write-Error "Logoff request failed: $_"
    exit 1
}
