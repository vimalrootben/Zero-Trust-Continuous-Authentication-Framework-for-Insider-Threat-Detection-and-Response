# Retained under the existing template allowlist for compatibility.
# Network containment is unavailable until a separately reviewed implementation is approved.
[CmdletBinding()]
param (
    [ValidateSet("ISOLATE", "UNISOLATE")][string]$Action = "ISOLATE",
    [ValidateNotNullOrEmpty()][string]$ManagerIP = "127.0.0.1"
)

Write-Error "Network isolation is unavailable"
exit 1
