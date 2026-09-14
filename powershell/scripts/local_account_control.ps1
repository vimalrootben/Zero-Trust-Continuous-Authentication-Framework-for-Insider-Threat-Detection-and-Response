[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)][ValidateSet('LOCK','UNLOCK')][string]$Action,
    [Parameter(Mandatory=$true)][string]$UserName,
    [string]$Domain = '',
    [ValidateSet('true','false')][string]$LogoutExistingSessions = 'false',
    [string]$AgentAccount = ''
)
$ErrorActionPreference='Stop'
$protected=@('administrator','system','localsystem','networkservice','localservice','defaultaccount','wdagutilityaccount')
$stateDir=Join-Path $env:ProgramData 'ZTA\account-state'
$statePath=Join-Path $stateDir (($UserName.ToLowerInvariant() -replace '[^a-z0-9_.-]','_')+'.json')
try {
    if ($Domain -and $Domain -ne '.' -and $Domain -ne $env:COMPUTERNAME) { throw 'Only local accounts may be contained' }
    if ($protected -contains $UserName.ToLowerInvariant() -or ($AgentAccount -and $UserName -ieq $AgentAccount) -or $UserName.EndsWith('$')) { throw 'Protected account target' }
    $account=Get-LocalUser -Name $UserName -ErrorAction Stop
    if ($Action -eq 'LOCK') {
        New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
        @{UserName=$account.Name;WasEnabled=[bool]$account.Enabled;RecordedAt=[DateTimeOffset]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
        if ($account.Enabled) { Disable-LocalUser -Name $account.Name -ErrorAction Stop }
        if ((Get-LocalUser -Name $account.Name).Enabled) { throw 'Account disable verification failed' }
        Write-Output 'LOCAL_ACCOUNT_DISABLED'
    } else {
        if (-not (Test-Path -LiteralPath $statePath)) { throw 'No reversible account state exists' }
        $state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        if ($state.UserName -ine $account.Name) { throw 'Saved account identity mismatch' }
        if ([bool]$state.WasEnabled) { Enable-LocalUser -Name $account.Name -ErrorAction Stop }
        if ([bool]$state.WasEnabled -and -not (Get-LocalUser -Name $account.Name).Enabled) { throw 'Account enable verification failed' }
        Remove-Item -LiteralPath $statePath -Force
        Write-Output ($(if ([bool]$state.WasEnabled) {'LOCAL_ACCOUNT_ENABLED'} else {'LOCAL_ACCOUNT_RESTORED_DISABLED'}))
    }
    if ($LogoutExistingSessions -eq 'true') { Write-Output 'SESSION_LOGOUT_REQUESTED_SEPARATELY' }
    exit 0
} catch { Write-Error $_; exit 1 }
