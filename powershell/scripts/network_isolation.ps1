[CmdletBinding()]
param([ValidateSet('ISOLATE','UNISOLATE')][string]$Action='ISOLATE',[string]$ManagerIP='127.0.0.1',[int]$ManagerPort=8080)
$ErrorActionPreference='Stop'; $prefix='ZTA-Isolation-'; $dir=Join-Path $env:ProgramData 'ZTA'; $statePath=Join-Path $dir 'network-isolation-state.json'
function Remove-ZtaRules { Get-NetFirewallRule -DisplayName "$prefix*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
function Restore-State($state) {
  Remove-ZtaRules
  foreach($profile in $state.profiles){Set-NetFirewallProfile -Name $profile.name -DefaultOutboundAction $profile.outbound}
  foreach($name in $state.disabled_rules){Enable-NetFirewallRule -Name $name -ErrorAction SilentlyContinue}
}
function Verify-Rollback($state) {
  if(Get-NetFirewallRule -DisplayName "$prefix*" -ErrorAction SilentlyContinue){throw 'Rollback left ZTA firewall rules'}
  foreach($profile in $state.profiles){if([string](Get-NetFirewallProfile -Name $profile.name).DefaultOutboundAction -ne [string]$profile.outbound){throw 'Rollback verification failed'}}
}
try {
  $admin=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if(-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Network isolation requires an elevated agent service'}
  if($Action -eq 'UNISOLATE'){
    if(-not(Test-Path -LiteralPath $statePath)){Remove-ZtaRules; Write-Output 'UNISOLATION_VERIFIED ALREADY_UNISOLATED'; exit 0}
    $state=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json; Restore-State $state; Verify-Rollback $state
    Remove-Item -LiteralPath $statePath -Force; Write-Output 'UNISOLATION_VERIFIED'; exit 0
  }
  $addresses=@([Net.Dns]::GetHostAddresses($ManagerIP)|ForEach-Object IPAddressToString|Sort-Object -Unique)
  if(-not $addresses){throw 'Manager address resolution failed'}
  if(Test-Path -LiteralPath $statePath){
    $existing=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json
    if($existing.manager_ip -eq $ManagerIP -and [int]$existing.manager_port -eq $ManagerPort -and -not(Get-NetFirewallProfile|Where-Object DefaultOutboundAction -ne 'Block')){Write-Output 'ISOLATION_VERIFIED ALREADY_ISOLATED';exit 0}
    Restore-State $existing; Verify-Rollback $existing; Remove-Item -LiteralPath $statePath -Force
  }
  New-Item -ItemType Directory -Force -Path $dir|Out-Null
  $allows=@(Get-NetFirewallRule -Direction Outbound -Enabled True -Action Allow)
  $dns=@(Get-DnsClientServerAddress|ForEach-Object ServerAddresses|Where-Object {$_}|Sort-Object -Unique)
  $state=[ordered]@{manager_ip=$ManagerIP;manager_port=$ManagerPort;created_at=[DateTimeOffset]::UtcNow.ToString('o');disabled_rules=@($allows|ForEach-Object Name);profiles=@(Get-NetFirewallProfile|ForEach-Object{[ordered]@{name=$_.Name;outbound=[string]$_.DefaultOutboundAction}})}
  $state|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $statePath -Encoding UTF8
  try {
    $allows|Disable-NetFirewallRule; Remove-ZtaRules
    New-NetFirewallRule -DisplayName "${prefix}Manager" -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress $addresses -RemotePort $ManagerPort|Out-Null
    if($dns){New-NetFirewallRule -DisplayName "${prefix}DNS-UDP" -Direction Outbound -Action Allow -Protocol UDP -RemoteAddress $dns -RemotePort 53|Out-Null;New-NetFirewallRule -DisplayName "${prefix}DNS-TCP" -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress $dns -RemotePort 53|Out-Null}
    New-NetFirewallRule -DisplayName "${prefix}DHCPv4" -Direction Outbound -Action Allow -Protocol UDP -LocalPort 68 -RemotePort 67|Out-Null
    New-NetFirewallRule -DisplayName "${prefix}DHCPv6" -Direction Outbound -Action Allow -Protocol UDP -LocalPort 546 -RemotePort 547|Out-Null
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
    if(Get-NetFirewallProfile|Where-Object DefaultOutboundAction -ne 'Block'){throw 'Firewall profile isolation verification failed'}
    if(-not(Test-NetConnection -ComputerName $ManagerIP -Port $ManagerPort -InformationLevel Quiet)){throw 'Manager reachability verification failed'}
    Write-Output 'ISOLATION_VERIFIED';exit 0
  } catch { Restore-State $state; Verify-Rollback $state; Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue; throw }
} catch { Write-Error "Network isolation failed and rollback was attempted: $_"; exit 1 }
