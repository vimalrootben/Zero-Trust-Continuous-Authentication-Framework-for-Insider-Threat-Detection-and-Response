<# Install the existing Python agent and register background startup on Windows. #>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)][string]$ManagerUrl,
    [Parameter(Mandatory=$true)][string]$AgentId,
    [string]$InstallDir = 'C:\Program Files\ZTA Agent'
)
$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Administrator privileges are required for the background task and event channels.' }
if ($AgentId -match '[\r\n]' -or $ManagerUrl -match '[\r\n]') { throw 'Invalid configuration value' }
$python = (Get-Command python -ErrorAction Stop).Source
$venv = Join-Path $InstallDir 'venv'
New-Item -ItemType Directory -Force -Path "$InstallDir\config", "$InstallDir\storage", "$InstallDir\logs" | Out-Null
# Credentials/cache and evidence belong only to Administrators and SYSTEM.
& icacls.exe $InstallDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to protect agent directory' }
& $python -m venv $venv
if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed' }
$agentPython = Join-Path $venv 'Scripts\python.exe'
& $agentPython -m pip install $PSScriptRoot
if ($LASTEXITCODE -ne 0) { throw 'Agent package installation failed' }
$config = Join-Path $InstallDir 'config\zta_agent.env'
if (-not (Test-Path $config)) {
    $secureToken = Read-Host 'Enter the provisioned per-agent token (same value configured on manager)' -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
    try {
        $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        if (-not $token -or $token -match '[\r\n]') { throw 'Invalid credential' }
        @"
ZTA_MANAGER_URL=$ManagerUrl
ZTA_AGENT_ID=$AgentId
ZTA_AGENT_TOKEN=$token
ZTA_LOCAL_DB_PATH=$InstallDir\storage\zta_agent_offline.db
ZTA_HEARTBEAT_INTERVAL=15
"@ | Set-Content -Encoding utf8 $config
    } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr); $token = $null }
}
$action = New-ScheduledTaskAction -Execute $agentPython -Argument "-m zta.agent.agent_daemon --config `"$config`"" -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 100 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 'ZTA Endpoint Agent' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 'ZTA Endpoint Agent'
Write-Host 'Agent task registered and started. Confirm heartbeat, collector status and command verification in the manager.'
Write-Host 'Existing configuration was preserved. Sysmon and Windows audit policy require separate deployment.'
