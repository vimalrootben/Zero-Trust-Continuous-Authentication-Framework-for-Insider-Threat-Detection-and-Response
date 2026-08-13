#define MyAppName "ZeroTrust EDR Agent"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "ZeroTrust EDR"
#define MyAppExeName "agent_service.exe"

[Setup]
AppId={{C6D85E9F-1A2B-4C3D-8E9F-0A1B2C3D4E5F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\ZeroTrustEDR
DefaultGroupName={#MyAppName}
OutputBaseFilename=ZeroTrustEDRAgentSetup
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin

[Files]
Source: "..\agent\*"; DestDir: "{app}\agent"; Flags: recursesubdirs createallsubdirs

[Run]
Filename: "{app}\python\python.exe"; Parameters: "-m agent.windows_service.service_entry --install"; Flags: runhidden

[UninstallRun]
Filename: "{app}\python\python.exe"; Parameters: "-m agent.windows_service.service_entry --stop"; Flags: runhidden
