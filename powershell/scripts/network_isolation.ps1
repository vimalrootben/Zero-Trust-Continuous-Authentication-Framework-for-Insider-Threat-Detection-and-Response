# ZTA allowlisted, verified and reversible Windows Firewall containment.
[CmdletBinding()]
param (
    [ValidateSet("ISOLATE", "UNISOLATE")][string]$Action = "ISOLATE",
    [ValidateNotNullOrEmpty()][string]$ManagerIP = "127.0.0.1"
)

$ErrorActionPreference = "Stop"
$RuleName = "ZTA_Manager_Reachability"
$DnsUdpRule = "ZTA_DNS_Reachability_UDP"
$DnsTcpRule = "ZTA_DNS_Reachability_TCP"
$StateDir = Join-Path $env:ProgramData "ZTA"
$StatePath = Join-Path $StateDir "network-isolation-state.json"

function Resolve-ManagerAddress([string]$Address) {
    $parsed = $null
    if ([Net.IPAddress]::TryParse($Address, [ref]$parsed)) { return $parsed.IPAddressToString }
    $resolved = [Net.Dns]::GetHostAddresses($Address) | Select-Object -First 1
    if (-not $resolved) { throw "Manager address could not be resolved" }
    return $resolved.IPAddressToString
}

function Restore-NetworkState($State) {
    Remove-NetFirewallRule -DisplayName $RuleName,$DnsUdpRule,$DnsTcpRule -ErrorAction SilentlyContinue
    foreach ($profile in $State.profiles) {
        Set-NetFirewallProfile -Name $profile.Name -DefaultOutboundAction $profile.DefaultOutboundAction
    }
    foreach ($ruleName in $State.disabled_allow_rules) {
        Enable-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    }
}

try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Network isolation requires an elevated agent service"
    }

    if ($Action -eq "ISOLATE") {
        $managerAddress = Resolve-ManagerAddress $ManagerIP
        if (Test-Path $StatePath) {
            $existing = Get-Content $StatePath -Raw | ConvertFrom-Json
            $profilesBlocked = -not (Get-NetFirewallProfile | Where-Object DefaultOutboundAction -ne "Block")
            $allowRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
            $otherAllows = Get-NetFirewallRule -Direction Outbound -Enabled True -Action Allow | Where-Object DisplayName -notin @($RuleName,$DnsUdpRule,$DnsTcpRule)
            if ($profilesBlocked -and $allowRule -and -not $otherAllows -and $existing.manager_address -eq $managerAddress) {
                Write-Output "ISOLATION_VERIFIED ALREADY_ISOLATED manager=$managerAddress"
                exit 0
            }
            Restore-NetworkState $existing
            Remove-Item $StatePath -Force -ErrorAction SilentlyContinue
        }

        New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
        $enabledAllowRules = @(Get-NetFirewallRule -Direction Outbound -Enabled True -Action Allow)
        $dnsAddresses = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | ForEach-Object ServerAddresses | Where-Object { $_ } | Sort-Object -Unique)
        $state = [ordered]@{
            manager_address = $managerAddress
            created_at = [DateTime]::UtcNow.ToString("o")
            disabled_allow_rules = @($enabledAllowRules | ForEach-Object Name)
            dns_addresses = $dnsAddresses
            profiles = @(Get-NetFirewallProfile | ForEach-Object {
                [ordered]@{ Name = $_.Name; DefaultOutboundAction = [string]$_.DefaultOutboundAction }
            })
        }
        $state | ConvertTo-Json -Depth 4 | Set-Content -Path $StatePath -Encoding UTF8

        $enabledAllowRules | Disable-NetFirewallRule
        Remove-NetFirewallRule -DisplayName $RuleName,$DnsUdpRule,$DnsTcpRule -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -Action Allow `
            -RemoteAddress $managerAddress -Enabled True `
            -Description "ZTA manager control channel during endpoint isolation" | Out-Null
        if ($dnsAddresses) {
            New-NetFirewallRule -DisplayName $DnsUdpRule -Direction Outbound -Action Allow -Protocol UDP `
                -RemotePort 53 -RemoteAddress $dnsAddresses -Enabled True -Description "ZTA DNS during containment" | Out-Null
            New-NetFirewallRule -DisplayName $DnsTcpRule -Direction Outbound -Action Allow -Protocol TCP `
                -RemotePort 53 -RemoteAddress $dnsAddresses -Enabled True -Description "ZTA DNS during containment" | Out-Null
        }
        Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block

        $profilesBlocked = -not (Get-NetFirewallProfile | Where-Object DefaultOutboundAction -ne "Block")
        $allowRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction Stop
        $addressFilter = $allowRule | Get-NetFirewallAddressFilter
        $otherAllows = Get-NetFirewallRule -Direction Outbound -Enabled True -Action Allow | Where-Object DisplayName -notin @($RuleName,$DnsUdpRule,$DnsTcpRule)
        if (-not $profilesBlocked -or $otherAllows -or $allowRule.Enabled -ne "True" -or $addressFilter.RemoteAddress -notcontains $managerAddress) {
            throw "Isolation verification failed"
        }
        Write-Output "ISOLATION_VERIFIED manager=$managerAddress"
        exit 0
    }

    if (-not (Test-Path $StatePath)) {
        Remove-NetFirewallRule -DisplayName $RuleName,$DnsUdpRule,$DnsTcpRule -ErrorAction SilentlyContinue
        Write-Output "UNISOLATION_VERIFIED ALREADY_UNISOLATED"
        exit 0
    }
    $state = Get-Content $StatePath -Raw | ConvertFrom-Json
    Restore-NetworkState $state
    if (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue) {
        throw "Manager allow rule remains after rollback"
    }
    foreach ($profile in $state.profiles) {
        $current = Get-NetFirewallProfile -Name $profile.Name
        if ([string]$current.DefaultOutboundAction -ne [string]$profile.DefaultOutboundAction) {
            throw "Firewall profile $($profile.Name) was not restored"
        }
    }
    Remove-Item $StatePath -Force
    Write-Output "UNISOLATION_VERIFIED"
    exit 0
} catch {
    if ($Action -eq "ISOLATE" -and (Test-Path $StatePath)) {
        try {
            $rollback = Get-Content $StatePath -Raw | ConvertFrom-Json
            Restore-NetworkState $rollback
        } catch { }
    }
    Write-Error "Network isolation failed: $_"
    exit 1
}
