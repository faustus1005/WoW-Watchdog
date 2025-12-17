; --------------------------------------------------
; WoW Watchdog Installer (EXE-based GUI)
; --------------------------------------------------
 
[Setup]
AppName=WoW Watchdog
AppVersion=1.0.5
AppPublisher=WoW Watchdog Project
DefaultDirName={commonpf32}\WoWWatchdog
DefaultGroupName=WoW Watchdog
DisableProgramGroupPage=yes
OutputBaseFilename=WoWWatchdog-Setup
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x86 x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
UninstallDisplayIcon={app}\WoWWatcher.exe
SetupIconFile=WoWWatcher.ico
WizardStyle=modern

DisableWelcomePage=no
DisableReadyMemo=no

; --------------------------------------------------
; Files
; --------------------------------------------------
[Files]
; GUI executable
Source: "WoWWatcher.exe"; DestDir: "{app}"; Flags: ignoreversion

; Watchdog service script (still PowerShell)
Source: "watchdog.ps1"; DestDir: "{app}"; Flags: ignoreversion

; Assets
Source: "WoWWatcher.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "nssm.exe";       DestDir: "{app}"; Flags: ignoreversion

; Optional default config
Source: "config.json"; DestDir: "{commonappdata}\WoWWatchdog"; Flags: onlyifdoesntexist ignoreversion

; --------------------------------------------------
; Directories
; --------------------------------------------------
[Dirs]
Name: "{commonappdata}\WoWWatchdog"; Permissions: users-modify

; --------------------------------------------------
; Icons
; --------------------------------------------------
[Icons]
Name: "{group}\WoW Watchdog"; \
    Filename: "{app}\WoWWatcher.exe"; \
    WorkingDir: "{app}"; \
    IconFilename: "{app}\WoWWatcher.ico"

Name: "{commondesktop}\WoW Watchdog"; \
    Filename: "{app}\WoWWatcher.exe"; \
    WorkingDir: "{app}"; \
    IconFilename: "{app}\WoWWatcher.ico"

; --------------------------------------------------
; Run (Install-time)
; --------------------------------------------------
[Run]

; Install service (CORRECT QUOTING)
Filename: "{app}\nssm.exe"; \
  Parameters: "install WoWWatchdog ""{sys}\WindowsPowerShell\v1.0\powershell.exe"" ""-NoProfile -ExecutionPolicy Bypass -File \""{app}\watchdog.ps1\"" """; \
  Flags: runhidden

; Service metadata
Filename: "{app}\nssm.exe"; Parameters: "set WoWWatchdog DisplayName ""WoW Watchdog"""; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "set WoWWatchdog Description ""WoW private server watchdog service"""; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "set WoWWatchdog AppExit Default Restart"; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "set WoWWatchdog RestartDelay 5000"; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "set WoWWatchdog AppDirectory ""{app}"""; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "set WoWWatchdog Start SERVICE_AUTO_START"; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "set WoWWatchdog AppNoConsole 1"; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "set WoWWatchdog ObjectName LocalSystem"; Flags: runhidden

; Start service
Filename: "sc.exe"; Parameters: "start WoWWatchdog"; Flags: runhidden



; --------------------------------------------------
; Uninstall
; --------------------------------------------------
[UninstallRun]
Filename: "{app}\nssm.exe"; \
    Parameters: "stop WoWWatchdog"; \
    Flags: runhidden; \
    RunOnceId: "StopService"

Filename: "{app}\nssm.exe"; \
    Parameters: "remove WoWWatchdog confirm"; \
    Flags: runhidden; \
    RunOnceId: "RemoveService"

; --------------------------------------------------
; Code
; --------------------------------------------------
[Code]
function IsSilent(): Boolean;
begin
  Result := WizardSilent;
end;

procedure InitializeWizard;
begin
  if not IsSilent() then
    MsgBox(
      'WoW Watchdog will be installed as a Windows service and start automatically.' + #13#10 +
      'Configuration will be stored in:' + #13#10 +
      'C:\ProgramData\WoWWatchdog',
      mbInformation,
      MB_OK
    );
end;
