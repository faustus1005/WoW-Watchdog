#define AppName "WoW Watchdog"
#define AppVersion "1.0.0"
#define AppPublisher "Darken Worlds"
#define AppExeName "WoWWatcherGUI.ps1"

[Setup]
AppId={{B4B9F9B1-2D2B-4D6C-9A9A-7D6F3DAA2A11}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\WoWWatchdog
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputBaseFilename=WoWWatchdog-Setup
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
WizardStyle=modern
UninstallDisplayIcon={app}\assets\WoWWatcher.ico

[Files]
Source: "watchdog.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "WoWWatcherGUI.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "config.json"; DestDir: "{app}"; Flags: ignoreversion onlyifdoesntexist
Source: "install-service.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "uninstall-service.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "nssm.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\WoWWatcher.ico"; DestDir: "{app}\assets"; Flags: ignoreversion; Check: FileExists(ExpandConstant('{src}\assets\WoWWatcher.ico'))

[Icons]
Name: "{group}\WoW Watchdog (GUI)"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\WoWWatcherGUI.ps1"""; WorkingDir: "{app}"; IconFilename: "{app}\assets\WoWWatcher.ico"
Name: "{commondesktop}\WoW Watchdog (GUI)"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\WoWWatcherGUI.ps1"""; WorkingDir: "{app}"; IconFilename: "{app}\assets\WoWWatcher.ico"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a Desktop icon"; Flags: unchecked

[Run]
; Install/Update service and start it
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\install-service.ps1"" -Silent"; WorkingDir: "{app}"; Flags: runhidden

; Optionally launch GUI at end (not in silent)
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\WoWWatcherGUI.ps1"""; WorkingDir: "{app}"; Flags: postinstall skipifsilent nowait

[UninstallRun]
; Stop and remove service
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\uninstall-service.ps1"""; WorkingDir: "{app}"; Flags: runhidden
