# ZTA Allowlisted PowerShell Script: Network Isolation / Firewall Containment
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$Action = "ISOLATE", # ISOLATE or UNISOLATE

    [Parameter(Mandatory=$false)]
    [string]$ManagerIP = "127.0.0.1"
)

$RuleName = "ZTA_Emergency_Network_Isolation"

try {
    if ($Action -eq "ISOLATE") {
        Write-Output "Enforcing ZTA emergency network isolation..."
        
        # Remove old rule if present
        Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue

        # Create outbound block rule except for loopback and Manager IP
        New-NetFirewallRule -DisplayName $RuleName `
                            -Direction Outbound `
                            -Action Block `
                            -Enabled True `
                            -Description "ZTA Emergency Endpoint Isolation"

        # Add explicit allow rule for ZTA Manager IP
        New-NetFirewallRule -DisplayName "${RuleName}_Manager_Allow" `
                            -Direction Outbound `
                            -Action Allow `
                            -RemoteAddress $ManagerIP `
                            -Enabled True `
                            -Description "ZTA Manager Control Channel Allow"

        Write-Output "Endpoint successfully isolated. ZTA Manager communication channel preserved."
    } elseif ($Action -eq "UNISOLATE") {
        Write-Output "Removing ZTA network isolation..."
        Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName "${RuleName}_Manager_Allow" -ErrorAction SilentlyContinue
        Write-Output "Network isolation removed successfully."
    } else {
        Write-Error "Invalid action specified: $Action"
        exit 1
    }
} catch {
    Write-Error "Failed to execute network isolation: $_"
    exit 1
}
