<# 
    WoW Watchdog GUI Script
#>


[CmdletBinding()]
param(
    # Portable mode / overrides (optional)
    [switch]$Portable,
    [string]$AppRootOverride,
    [string]$DataDirOverride,
    [string]$LogsDirOverride,
    [string]$ToolsDirOverride,
    [string]$ConfigPathOverride,
    [string]$SecretsPathOverride
)

function Get-WwAppRoot {
    param([string]$Override)

    if ($Override -and (Test-Path -LiteralPath $Override)) {
        return (Resolve-Path -LiteralPath $Override).Path
    }

    # Script execution path
    if ($PSScriptRoot -and (Test-Path -LiteralPath $PSScriptRoot)) {
        return (Resolve-Path -LiteralPath $PSScriptRoot).Path
    }

    if ($MyInvocation.MyCommand.Path) {
        return (Split-Path -Parent $MyInvocation.MyCommand.Path)
    }

    # PS2EXE / EXE execution path
    try {
        $bd = [System.AppDomain]::CurrentDomain.BaseDirectory
        if ($bd) {
            return $bd.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
        }
    } catch { }

    return (Get-Location).Path
}

function Test-WwPortable {
    param(
        [Parameter(Mandatory)][string]$Root,
        [switch]$PortableSwitch
    )

    if ($PortableSwitch) { return $true }
    if (Test-Path -LiteralPath (Join-Path $Root "portable.flag")) { return $true }

    # Heuristics: if a local config exists, treat it as portable
    if (Test-Path -LiteralPath (Join-Path $Root "data\config.json")) { return $true }
    if (Test-Path -LiteralPath (Join-Path $Root "config.json")) { return $true }

    return $false
}

function Ensure-WwDir {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

# Resolve portable vs installed mode as early as possible (before elevation)
$script:WwAppRoot    = Get-WwAppRoot -Override $AppRootOverride
$script:WwIsPortable = Test-WwPortable -Root $script:WwAppRoot -PortableSwitch:$Portable

# Crash log path is needed even before the main UI initializes
$script:CrashDir = if ($LogsDirOverride) {
    $LogsDirOverride
} elseif ($script:WwIsPortable) {
    Join-Path $script:WwAppRoot "logs"
} else {
    Join-Path $env:ProgramData "WoWWatchdog"
}
Ensure-WwDir $script:CrashDir
$script:CrashLogPath = Join-Path $script:CrashDir "crash.log"

# -------------------------------------------------
# Self-elevate to Administrator if not already
# -------------------------------------------------
function Test-IsAdmin {
    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
    } catch {
        return $false
    }
}

if (-not (Test-IsAdmin) -and (-not $script:WwIsPortable)) {

    # Relaunch elevated. Prefer restarting the script when running as .ps1, otherwise restart this EXE (PS2EXE).
    $procExe    = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $scriptPath = $MyInvocation.MyCommand.Path

    try {
        if ($scriptPath -and $scriptPath.ToLowerInvariant().EndsWith(".ps1")) {
            $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File', $scriptPath)
            Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $args -WorkingDirectory (Split-Path -Parent $scriptPath)
        } else {
            Start-Process -FilePath $procExe -Verb RunAs -WorkingDirectory $script:WwAppRoot
        }
    } catch {
        [System.Windows.MessageBox]::Show(
            "WoW Watchdog requires administrative privileges.",
            "Elevation Required",
            'OK',
            'Error'
        )
    }

    return
}

$ErrorActionPreference = 'Stop'

trap {
    try {
        $msg = "Unhandled exception:`n$($_)"
        [System.Windows.MessageBox]::Show($msg, "WoW Watchdog", 'OK', 'Error')
        Add-Content -Path $script:CrashLogPath -Value $msg
    } catch { }
    break
}


Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms



# -------------------------------------------------
# JSON helpers
# -------------------------------------------------
function Read-JsonFile {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }

    try {
        return ($raw | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        # If config is corrupted, return null so caller can recreate/default
        return $null
    }
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Object
    )

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    $Object | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $Path -Encoding UTF8
}

$AppVersion = [version]"1.2.3"
$RepoOwner  = "FAUSTUS1005"
$RepoName   = "WoW-Watchdog"

# -------------------------------------------------
# Paths / constants
# -------------------------------------------------
# Canonical paths and globals
# -------------------------------------------------
$AppName     = "WoWWatchdog"
$ExePath     = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

# App root resolved via portable-aware bootstrap (works for .ps1 and PS2EXE)
$InstallDir  = $script:WwAppRoot
$ScriptDir   = $InstallDir

$script:ScriptDir  = $ScriptDir
$script:IsPortable = $script:WwIsPortable

# State/config directory: installed mode remains backward-compatible (ProgramData\WoWWatchdog)
$DataDir = if ($DataDirOverride) {
    $DataDirOverride
} elseif ($script:IsPortable) {
    Join-Path $InstallDir "data"
} else {
    Join-Path $env:ProgramData $AppName
}
Ensure-WwDir $DataDir

# Logs: installed mode keeps legacy location, portable uses .\logs
$script:LogsDir = if ($LogsDirOverride) {
    $LogsDirOverride
} elseif ($script:IsPortable) {
    Join-Path $InstallDir "logs"
} else {
    $DataDir
}
Ensure-WwDir $script:LogsDir

# Tools downloaded/installed by launchers MUST be writable without elevation.
$script:ToolsDir = if ($ToolsDirOverride) {
    $ToolsDirOverride
} elseif ($script:IsPortable) {
    Join-Path $InstallDir "tools"
} else {
    Join-Path $DataDir "Tools"
}
Ensure-WwDir $script:ToolsDir

# Prefer data\config.json for portable; migrate from legacy root files if present
$preferredConfig  = Join-Path $DataDir "config.json"
$legacyConfig     = Join-Path $InstallDir "config.json"
$preferredSecrets = Join-Path $DataDir "secrets.json"
$legacySecrets    = Join-Path $InstallDir "secrets.json"

if (-not $ConfigPathOverride) {
    if ((Test-Path -LiteralPath $legacyConfig) -and (-not (Test-Path -LiteralPath $preferredConfig))) {
        Copy-Item -LiteralPath $legacyConfig -Destination $preferredConfig -Force
    }
}
if (-not $SecretsPathOverride) {
    if ((Test-Path -LiteralPath $legacySecrets) -and (-not (Test-Path -LiteralPath $preferredSecrets))) {
        Copy-Item -LiteralPath $legacySecrets -Destination $preferredSecrets -Force
    }
}

$ConfigPath  = if ($ConfigPathOverride) { $ConfigPathOverride } else { $preferredConfig }
$SecretsPath = if ($SecretsPathOverride) { $SecretsPathOverride } else { $preferredSecrets }

# Keep logs in the logs directory in portable mode
$LogPath        = Join-Path $script:LogsDir "watchdog.log"
$HeartbeatFile  = Join-Path $DataDir "watchdog.heartbeat"
$StopSignalFile = Join-Path $DataDir "watchdog.stop"
$LogMaxBytes    = 5242880
$LogRetainCount = 5

$ServiceName    = "WoWWatchdog"

# Normalize working directory (Scheduled Tasks / shortcuts often default to System32)
try { Set-Location -LiteralPath $InstallDir } catch { }

# Align crash log location with resolved logs directory
$script:CrashLogPath = Join-Path $script:LogsDir "crash.log"
# Status flags for LED + NTFY baseline
$global:MySqlUp       = $false
$global:AuthUp        = $false
$global:WorldUp       = $false
$global:NtfyBaselineInitialized = $false
$global:NtfySuppressUntil = $null
$global:LedPulseFlip = $false
$global:PlayerCountCache = [pscustomobject]@{
    Value     = $null
    Timestamp = [datetime]::MinValue
}
$global:PlayerCountCacheTtlSeconds = 5

# -------------------------------------------------
# Default config (NON-secrets)
# -------------------------------------------------
$DefaultConfig = [ordered]@{
    ServerName   = ""
    Expansion    = "Unknown"

    MySQL        = ""     # e.g. C:\WoWSrv\Database\start_mysql.bat
    MySQLExe     = ""     # e.g. C:\WoWSrv\Database\bin\mysql.exe
    Authserver   = ""     # e.g. C:\WoWSrv\authserver.exe
    Worldserver  = ""     # e.g. C:\WoWSrv\worldserver.exe


    # Worldserver Telnet console (in-GUI remote console)
    WorldTelnetHost = "127.0.0.1"
    WorldTelnetPort = 3443
    WorldTelnetUser = ""

    WorldserverLogPath = ""

    RepackRoot  = ""     # e.g. C:\WoWSrv (root folder to back up for full repack backups)
    DbBackupFolder     = (Join-Path $DataDir "backups")
    RepackBackupFolder = (Join-Path $DataDir "backups")


    # DB settings (non-secrets)
    DbHost       = "127.0.0.1"
    DbPort       = 3306
    DbUser       = "root"
    DbNameChar   = "legion_characters"

    # NTFY settings (non-secrets)
    NTFY = [ordered]@{
        Server            = ""
        Topic             = ""
        Tags              = "wow,watchdog"
        PriorityDefault   = 4
        Username          = ""
        AuthMode          = "None"

        EnableMySQL       = $true
        EnableAuthserver  = $true
        EnableWorldserver = $true

        ServicePriorities = [ordered]@{
            MySQL      = 0
            Authserver = 0
            Worldserver= 0
        }

        SendOnDown        = $true
        SendOnUp          = $false
    }
}

# Load/create config.json (and upgrade schema if needed)
$Config = Read-JsonFile $ConfigPath
if (-not $Config) {
    Write-JsonFile -Path $ConfigPath -Object $DefaultConfig
    $Config = Read-JsonFile $ConfigPath
}

function Ensure-ConfigSchema {
    param([Parameter(Mandatory)]$Cfg, [Parameter(Mandatory)]$Defaults)

    foreach ($p in $Defaults.PSObject.Properties) {
        if (-not $Cfg.PSObject.Properties[$p.Name]) {
            $Cfg | Add-Member -MemberType NoteProperty -Name $p.Name -Value $p.Value
            continue
        }

        # Recurse into nested objects
        $dv = $p.Value
        $cv = $Cfg.$($p.Name)

        if ($dv -is [System.Collections.IDictionary] -or $dv -is [pscustomobject]) {
            if ($cv -is [pscustomobject]) {
                Ensure-ConfigSchema -Cfg $cv -Defaults $dv
            }
        }
    }
}

Ensure-ConfigSchema -Cfg $Config -Defaults ([pscustomobject]$DefaultConfig)

# Persist upgraded config immediately
Write-JsonFile -Path $ConfigPath -Object $Config

function Ensure-UrlZipToolInstalled {
    param(
        [Parameter(Mandatory)][string]$ZipUrl,
        [Parameter(Mandatory)][string]$InstallDir,

        # Exact expected EXE location after extraction (relative to InstallDir)
        [Parameter(Mandatory)][string]$ExeRelativePath,

        # Optional: for nicer temp naming/logging
        [string]$ToolName = "Tool",
        [string]$TempZipFileName = "tool.zip"
    )

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    $exePath = Join-Path $InstallDir $ExeRelativePath
    if (Test-Path $exePath) { return $exePath }

    # PS 5.1: ensure TLS 1.2
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

    $tempZip = Join-Path $env:TEMP $TempZipFileName

    try {
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }

        # UseBasicParsing for PS 5.1
        Invoke-WebRequest -Uri $ZipUrl -OutFile $tempZip -UseBasicParsing -ErrorAction Stop
    } catch {
        throw "Failed to download $ToolName from URL. $($_.Exception.Message)"
    }

    if (-not (Test-Path $tempZip)) {
        throw "Download did not produce a file at: $tempZip"
    }

    try {
        Expand-ZipSafe -ZipPath $tempZip -Destination $InstallDir
    } catch {
        throw "Failed to extract $ToolName archive to '$InstallDir'. $($_.Exception.Message)"
    }

    if (-not (Test-Path $exePath)) {
        throw "$ToolName install completed, but expected EXE was not found: $exePath"
    }

    return $exePath
}

# -------------------------------------------------
# DPAPI Secrets Store
# -------------------------------------------------
function Get-SecretsStore {
    if (-not (Test-Path $SecretsPath)) { return @{} }
    try {
        $raw = Get-Content $SecretsPath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        $ht = @{}
        foreach ($p in $obj.PSObject.Properties) { $ht[$p.Name] = [string]$p.Value }
        return $ht
    } catch {
        return @{}
    }
}

function Save-SecretsStore([hashtable]$Store) {
    if (-not (Test-Path $DataDir)) {
        New-Item -Path $DataDir -ItemType Directory -Force | Out-Null
    }
    $Store | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $SecretsPath -Encoding UTF8
}

Add-Type -AssemblyName System.Security

function Protect-Secret {
    param([Parameter(Mandatory)][string]$Plain)

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Plain)

    # LocalMachine scope so a Windows Service can read it too
    $protected = [System.Security.Cryptography.ProtectedData]::Protect(
        $bytes,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )

    # store as base64
    return [Convert]::ToBase64String($protected)
}

function Unprotect-Secret {
    param([Parameter(Mandatory)][string]$Protected)

    $protectedBytes = [Convert]::FromBase64String($Protected)

    $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $protectedBytes,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )

    return [System.Text.Encoding]::UTF8.GetString($bytes)
}

function Get-NtfySecretKey {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("BasicPassword","Token")]
        [string]$Kind
    )

    # Prefer current UI values, but fall back to persisted config values (important during startup/load).
    $server = $null
    $topic  = $null

    try { $server = [string]$TxtNtfyServer.Text } catch { }
    try { $topic  = [string]$TxtNtfyTopic.Text } catch { }

    if ([string]::IsNullOrWhiteSpace($server)) {
        try { $server = [string]$Config.NTFY.Server } catch { $server = "" }
    }
    if ([string]::IsNullOrWhiteSpace($topic)) {
        try { $topic = [string]$Config.NTFY.Topic } catch { $topic = "" }
    }

    # PowerShell 5.1-safe null handling and normalization
    if ($null -eq $server) { $server = "" }
    if ($null -eq $topic)  { $topic  = "" }

    $server = $server.Trim()
    $topic  = $topic.Trim()

    return ("NTFY::{0}::{1}@{2}" -f $Kind, $server, $topic)
}

function Set-NtfySecret {
    param(
        [Parameter(Mandatory)][ValidateSet("BasicPassword","Token")][string]$Kind,
        [Parameter(Mandatory)][string]$Plain
    )
    $store = Get-SecretsStore
    $key   = Get-NtfySecretKey -Kind $Kind
    $store[$key] = Protect-Secret -Plain $Plain
    Save-SecretsStore -Store $store
}

function Get-NtfySecret {
    param([Parameter(Mandatory)][ValidateSet("BasicPassword","Token")][string]$Kind)

    $store = Get-SecretsStore
    $key   = Get-NtfySecretKey -Kind $Kind
    if (-not $store.ContainsKey($key)) { return $null }

    try { Unprotect-Secret -Protected $store[$key] }
    catch { return $null }
}

function Remove-NtfySecret {
    param([Parameter(Mandatory)][ValidateSet("BasicPassword","Token")][string]$Kind)

    $store = Get-SecretsStore
    $key   = Get-NtfySecretKey -Kind $Kind
    if ($store.ContainsKey($key)) {
        [void]$store.Remove($key)
        Save-SecretsStore -Store $store
    }
}

function Get-DbSecretKey {
    # Bind the password to host/port/user so it survives GUI restarts, but allows multiple DB targets.
    $h = ""
    $p = ""
    $u = ""

    try { $h = [string]$TxtDbHost.Text } catch { $h = [string]$Config.DbHost }
    try { $p = [string]$TxtDbPort.Text } catch { $p = [string]$Config.DbPort }
    try { $u = [string]$TxtDbUser.Text } catch { $u = [string]$Config.DbUser }

    $h = ($h.Trim())
    if ([string]::IsNullOrWhiteSpace($h)) { $h = "127.0.0.1" }

    $p = ($p.Trim())
    if (-not $p) { $p = "3306" }

    $u = ($u.Trim())
    if ([string]::IsNullOrWhiteSpace($u)) { $u = "root" }

    return "DB::mysql::$u@$h`:$p"
}

function Set-DbSecretPassword {
    param([Parameter(Mandatory)][string]$Plain)

    $store = Get-SecretsStore
    $key   = Get-DbSecretKey
    $store[$key] = Protect-Secret -Plain $Plain
    Save-SecretsStore -Store $store
}

function Get-DbSecretPassword {
    $store = Get-SecretsStore
    $key   = Get-DbSecretKey
    if (-not $store.ContainsKey($key)) { return $null }

    try { return (Unprotect-Secret -Protected $store[$key]) }
    catch { return $null }
}

function Remove-DbSecretPassword {
    $store = Get-SecretsStore
    $key   = Get-DbSecretKey
    if ($store.ContainsKey($key)) {
        [void]$store.Remove($key)
        Save-SecretsStore -Store $store
    }
}

# -------------------------------------------------
# Worldserver Telnet password (DPAPI secret)
# -------------------------------------------------
function Get-WorldTelnetSecretKey {
    param(
        [string]$telnetHost,
        [int]$Port,
        [string]$Username
    )

    # Prefer explicit arguments, then UI, then persisted config
    if ([string]::IsNullOrWhiteSpace($telnetHost)) {
        try { $telnetHost = [string]$TxtWorldTelnetHost.Text } catch { $telnetHost = $null }
        if ([string]::IsNullOrWhiteSpace($telnetHost)) {
            try { $telnetHost = [string]$Config.WorldTelnetHost } catch { $telnetHost = "" }
        }
    }

    if (-not $Port) {
        try { $Port = [int]([string]$TxtWorldTelnetPort.Text) } catch { $Port = 0 }
        if (-not $Port) {
            try { $Port = [int]$Config.WorldTelnetPort } catch { $Port = 3443 }
        }
    }

    if ([string]::IsNullOrWhiteSpace($Username)) {
        try { $Username = [string]$TxtWorldTelnetUser.Text } catch { $Username = $null }
        if ([string]::IsNullOrWhiteSpace($Username)) {
            try { $Username = [string]$Config.WorldTelnetUser } catch { $Username = "" }
        }
    }

    if ($null -eq $telnetHost) { $telnetHost = "" }
    if ($null -eq $Username) { $Username = "" }

    $telnetHost = $telnetHost.Trim()
    if ([string]::IsNullOrWhiteSpace($telnetHost)) { $telnetHost = "127.0.0.1" }

    if (-not $Port) { $Port = 3443 }

    $Username = $Username.Trim()

    # Key: bind to target + username so multiple servers/users can coexist
    return ("WSTELNET::PASS::{0}@{1}:{2}" -f $Username.ToLowerInvariant(), $telnetHost.ToLowerInvariant(), $Port)
}

function Set-WorldTelnetPassword {
    param(
        [Parameter(Mandatory)][string]$telnetHost,
        [Parameter(Mandatory)][int]$Port,
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)][string]$Plain
    )

    $store = Get-SecretsStore
    $key   = Get-WorldTelnetSecretKey -TelnetHost $telnetHost -Port $Port -Username $Username
    $store[$key] = Protect-Secret -Plain $Plain
    Save-SecretsStore -Store $store
}

function Get-WorldTelnetPassword {
    param(
        [Parameter(Mandatory)][string]$telnetHost,
        [Parameter(Mandatory)][int]$Port,
        [Parameter(Mandatory)][string]$Username
    )

    $store = Get-SecretsStore
    $key   = Get-WorldTelnetSecretKey -TelnetHost $telnetHost -Port $Port -Username $Username
    if (-not $store.ContainsKey($key)) { return $null }

    try { return (Unprotect-Secret -Protected $store[$key]) }
    catch { return $null }
}

function Has-WorldTelnetPassword {
    param(
        [Parameter(Mandatory)][string]$telnetHost,
        [Parameter(Mandatory)][int]$Port,
        [Parameter(Mandatory)][string]$Username
    )
    $store = Get-SecretsStore
    $key   = Get-WorldTelnetSecretKey -TelnetHost $telnetHost -Port $Port -Username $Username
    return $store.ContainsKey($key)
}

function Remove-WorldTelnetPassword {
    param(
        [Parameter(Mandatory)][string]$telnetHost,
        [Parameter(Mandatory)][int]$Port,
        [Parameter(Mandatory)][string]$Username
    )

    $store = Get-SecretsStore
    $key   = Get-WorldTelnetSecretKey -TelnetHost $telnetHost -Port $Port -Username $Username
    if ($store.ContainsKey($key)) {
        [void]$store.Remove($key)
        Save-SecretsStore -Store $store
    }
}


function Get-OnlinePlayerCount_Legion {

    # mysql.exe
    $mysqlExePath = [string]$Config.MySQLExe
    if ([string]::IsNullOrWhiteSpace($mysqlExePath) -or
        -not (Test-Path -LiteralPath $mysqlExePath)) {
        throw "mysql.exe path not set or invalid."
    }

    # DB password (DPAPI secret)
    $dbPassword = Get-DbSecretPassword
    if ([string]::IsNullOrWhiteSpace($dbPassword)) {
        throw "DB password not set in secrets store."
    }

    # Host
    $dbHostName = [string]$Config.DbHost
    if ([string]::IsNullOrWhiteSpace($dbHostName)) {
        $dbHostName = "127.0.0.1"
    }

    # Port
    $dbPortNum = 3306
    try { $dbPortNum = [int]$Config.DbPort } catch { $dbPortNum = 3306 }

    # User
    $dbUserName = [string]$Config.DbUser
    if ([string]::IsNullOrWhiteSpace($dbUserName)) {
        $dbUserName = "root"
    }

    # Character DB (configurable, defaulted)
    $dbNameChars = [string]$Config.DbNameChar
    if ([string]::IsNullOrWhiteSpace($dbNameChars)) {
        $dbNameChars = "legion_characters"
    }

    # Query (confirmed schema)
    $query = "SELECT COUNT(*) FROM characters WHERE online=1;"

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $mysqlExePath
    $psi.Arguments = "--host=$dbHostName --port=$dbPortNum --user=$dbUserName --database=$dbNameChars --batch --skip-column-names -e `"$query`""
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow = $true

    # Secure password injection (not visible in process list)
    $psi.EnvironmentVariables["MYSQL_PWD"] = $dbPassword

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    if (-not $proc.Start()) {
        throw "Failed to start mysql.exe"
    }

    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()

    if ($proc.ExitCode -ne 0) {
        $err = $stderr.Trim()
        if ([string]::IsNullOrWhiteSpace($err)) {
            $err = "Exit code $($proc.ExitCode)"
        }
        throw "mysql.exe query failed: $err"
    }

    $line = ($stdout.Trim() -split "\r?\n" | Select-Object -First 1).Trim()
    $count = 0
    if (-not [int]::TryParse($line, [ref]$count)) {
        throw "Unexpected mysql output: '$line'"
    }

    return $count
}

function Get-OnlinePlayerCountCached_Legion {
    $now = Get-Date
    $age = ($now - $global:PlayerCountCache.Timestamp).TotalSeconds

    if ($null -ne $global:PlayerCountCache.Value -and $age -lt $global:PlayerCountCacheTtlSeconds) {
        return [int]$global:PlayerCountCache.Value
    }

    $val = Get-OnlinePlayerCount_Legion
    $global:PlayerCountCache.Value = [int]$val
    $global:PlayerCountCache.Timestamp = $now
    return [int]$val
}

function Parse-ReleaseVersion {
    param([string]$TagName)

    $t = ""
    if ($TagName) { $t = $TagName.Trim() }
    if ($t.StartsWith("v")) { $t = $t.Substring(1) }
    [version]$t
}


function Get-LatestReleaseAssetInfo {
    param(
        [Parameter(Mandatory)][string]$Owner,
        [Parameter(Mandatory)][string]$Repo,

        # Use ONE of these:
        [string]$ExpectedAssetName,
        [string]$AssetNameRegex
    )

    $rel = Get-LatestGitHubRelease -Owner $Owner -Repo $Repo

    if (-not $rel.assets -or $rel.assets.Count -lt 1) {
        throw "Latest release '$($rel.tag_name)' has no assets."
    }

    $asset = $null

    if ($ExpectedAssetName) {
        $asset = $rel.assets | Where-Object { $_.name -eq $ExpectedAssetName } | Select-Object -First 1
        if (-not $asset) {
            $names = ($rel.assets | ForEach-Object { $_.name }) -join ", "
            throw "Could not find expected asset '$ExpectedAssetName' in latest release assets: $names"
        }
    }
    elseif ($AssetNameRegex) {
        $asset = $rel.assets | Where-Object { $_.name -match $AssetNameRegex } | Select-Object -First 1
        if (-not $asset) {
            $names = ($rel.assets | ForEach-Object { $_.name }) -join ", "
            throw "Could not find an asset matching regex '$AssetNameRegex' in: $names"
        }
    }
    else {
        throw "Provide either -ExpectedAssetName or -AssetNameRegex."
    }

    [pscustomobject]@{
        Release          = $rel
        Tag              = $rel.tag_name
        LatestVersion    = (Parse-ReleaseVersion -TagName $rel.tag_name)
        AssetName        = $asset.name
        DownloadUrl      = $asset.browser_download_url
    }
}
function Get-LatestGitHubRelease {
    param(
        [Parameter(Mandatory)][string]$Owner,
        [Parameter(Mandatory)][string]$Repo
    )

    # PS 5.1: ensure TLS 1.2
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

    $uri = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
    $headers = @{
        "User-Agent" = "WoWWatchdog"
        "Accept"     = "application/vnd.github+json"
    }

    Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
}

function Get-7ZipCliPath {
    param(
        # AppRoot defaults to the installed app folder (where WoWWatcher.exe lives)
        [string]$AppRoot = $script:ScriptDir,

        # Optional: also look in ProgramData tools deps if you choose to place it there
        [string]$DataToolsDir = $script:ToolsDir
    )

    $candidates = @()

    if (-not [string]::IsNullOrWhiteSpace($AppRoot)) {
        $candidates += @(
            (Join-Path $AppRoot "Tools\_deps\7zip\7za.exe"),
            (Join-Path $AppRoot "Tools\_deps\7zip\7z.exe")
        )
    }

    if (-not [string]::IsNullOrWhiteSpace($DataToolsDir)) {
        $candidates += @(
            (Join-Path $DataToolsDir "_deps\7zip\7za.exe"),
            (Join-Path $DataToolsDir "_deps\7zip\7z.exe")
        )
    }

    $candidates += @(
        (Join-Path $env:ProgramFiles "7-Zip\7z.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "7-Zip\7z.exe")
    )

    foreach ($p in $candidates) {
        if ($p -and (Test-Path -LiteralPath $p)) { return $p }
    }

    return $null
}

function Expand-ArchiveWith7Zip {
    param(
        [Parameter(Mandatory)][string]$SevenZipExe,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$DestinationPath
    )

    if (-not (Test-Path -LiteralPath $SevenZipExe)) {
        throw "7-Zip CLI not found at: $SevenZipExe"
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Archive not found at: $Path"
    }
    if (-not (Test-Path -LiteralPath $DestinationPath)) {
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    }

    # IMPORTANT: Use the call operator (&) to preserve arguments containing spaces (e.g., Program Files paths).
    $args = @(
        "x",                 # extract with full paths
        "-y",                # assume yes
        "-aoa",              # overwrite all
        "-o$DestinationPath",
        $Path
    )

    $out = & $SevenZipExe @args 2>&1
    $code = $LASTEXITCODE

    # 7-Zip exit codes: 0 = OK, 1 = Warnings, 2+ = Fatal errors
    if ($code -gt 1) {
        $msg = ($out | Out-String).Trim()
        if ([string]::IsNullOrWhiteSpace($msg)) { $msg = "(no output)" }
        throw "7-Zip extraction failed (exit code $code). Output:`n$msg"
    }
}

function Expand-ZipSafe {
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][string]$Destination
    )

    if ([string]::IsNullOrWhiteSpace($ZipPath))     { throw "Expand-ZipSafe: ZipPath is empty." }
    if ([string]::IsNullOrWhiteSpace($Destination)) { throw "Expand-ZipSafe: Destination is empty." }

    if (-not (Test-Path -LiteralPath $ZipPath)) {
        throw "Expand-ZipSafe: Archive not found: $ZipPath"
    }

    if (-not (Test-Path -LiteralPath $Destination)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }

    try {
        # Built-in ZIP extraction (works for standard ZIP methods only)
        Expand-Archive -LiteralPath $ZipPath -DestinationPath $Destination -Force
    }
    catch {
        # Non-standard ZIP methods / .7z: fallback to 7-Zip CLI
        $sevenZip = Get-7ZipCliPath
        if (-not $sevenZip) {
            throw "Extraction requires 7-Zip CLI, but it was not found. Bundle 7za.exe under '{app}\Tools\_deps\7zip\7za.exe' (recommended) or install 7-Zip system-wide."
        }

        Expand-ArchiveWith7Zip -SevenZipExe $sevenZip -Path $ZipPath -DestinationPath $Destination
    }
}


function Get-FirstExeInFolder {
    param(
        [Parameter(Mandatory)][string]$Folder,
        [string]$ExeNameHintRegex = 'SPP|Legion|Manager|Management'
    )

    if (-not (Test-Path $Folder)) { return $null }

    $all = Get-ChildItem -Path $Folder -Filter *.exe -Recurse -File -ErrorAction SilentlyContinue
    if (-not $all) { return $null }

    $hint = $all | Where-Object { $_.Name -match $ExeNameHintRegex } | Select-Object -First 1
    if ($hint) { return $hint.FullName }

    ($all | Select-Object -First 1).FullName
}

function Ensure-GitHubZipToolInstalled {
    param(
        [Parameter(Mandatory)][string]$Owner,
        [Parameter(Mandatory)][string]$Repo,
        [Parameter(Mandatory)][string]$InstallDir,

        # Strongly recommended if you know it:
        [string]$ExeRelativePath,

        # Asset selection (regex)
        [Parameter(Mandatory)][string]$AssetNameRegex
    )

    if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }

    # If caller provided an exact EXE path, honor it first
    if ($ExeRelativePath) {
        $exePath = Join-Path $InstallDir $ExeRelativePath
        if (Test-Path $exePath) { return $exePath }
    }
    # If caller did NOT provide an exact EXE path, we can try to reuse an existing install.
    # IMPORTANT: If ExeRelativePath is provided and InstallDir contains multiple tools, auto-picking "first exe"
    # can launch the wrong application.
    if (-not $ExeRelativePath) {
        $existingExe = Get-FirstExeInFolder -Folder $InstallDir
        if ($existingExe) { return $existingExe }
    }
    # Pull latest release + matching zip asset
    $info = Get-LatestReleaseAssetInfo -Owner $Owner -Repo $Repo -AssetNameRegex $AssetNameRegex

    $tempZip = Join-Path $env:TEMP $info.AssetName

    try {
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        Invoke-WebRequest -Uri $info.DownloadUrl -OutFile $tempZip -UseBasicParsing -ErrorAction Stop
    } catch {
        throw "Failed to download tool from GitHub. $($_.Exception.Message)"
    }

    if (-not (Test-Path $tempZip)) {
        throw "Download did not produce a file at: $tempZip"
    }

    try {
        Expand-ZipSafe -ZipPath $tempZip -Destination $InstallDir
    } catch {
        throw "Failed to extract archive '$($info.AssetName)' to '$InstallDir'. $($_.Exception.Message)"
    }

    # Resolve exe after extraction
    if ($ExeRelativePath) {
        $exePath = Join-Path $InstallDir $ExeRelativePath
        if (Test-Path $exePath) { return $exePath }
        throw "Install completed, but expected EXE was not found: $exePath"
    }

    $exeFound = Get-FirstExeInFolder -Folder $InstallDir
    if (-not $exeFound) {
        throw "Install completed, but no EXE was found under: $InstallDir"
    }

    $exeFound
}

function Set-UpdateFlowUi {
    param(
        [string]$Text,
        [int]$Percent = -1,          # -1 keeps current
        [bool]$Show = $true,
        [bool]$Indeterminate = $false
    )

    if (-not $Window) { return }

    $Window.Dispatcher.Invoke([action]{
        if ($TxtUpdateFlowStatus) {
            $TxtUpdateFlowStatus.Text = $Text
            $TxtUpdateFlowStatus.Visibility = if ($Show) { "Visible" } else { "Collapsed" }
        }
        if ($PbUpdateFlow) {
            $PbUpdateFlow.Visibility = if ($Show) { "Visible" } else { "Collapsed" }
            $PbUpdateFlow.IsIndeterminate = $Indeterminate
            if (-not $Indeterminate -and $Percent -ge 0) {
                if ($Percent -lt 0) { $Percent = 0 }
                if ($Percent -gt 100) { $Percent = 100 }
                $PbUpdateFlow.Value = $Percent
            }
        }
    })
}

function Set-SppV2UpdateUiState {
    param(
        [bool]$IsBusy,
        [string]$StatusText = ""
    )

    if (-not $Window) { return }

    $Window.Dispatcher.Invoke([action]{
        if ($BtnSppV2RepackUpdate) { $BtnSppV2RepackUpdate.IsEnabled = (-not $IsBusy) }

        if ($TxtSppV2UpdateStatus) {
            $TxtSppV2UpdateStatus.Text = $StatusText
            $TxtSppV2UpdateStatus.Visibility = $(if ([string]::IsNullOrWhiteSpace(($StatusText + ""))) { "Collapsed" } else { "Visible" })
        }

        if ($PbSppV2Update) {
            $PbSppV2Update.Visibility = $(if ($IsBusy) { "Visible" } else { "Collapsed" })
            $PbSppV2Update.IsIndeterminate = $IsBusy
            if (-not $IsBusy) { $PbSppV2Update.Value = 0 }
        }
    })
}


function Set-UpdateButtonsEnabled {
    param([bool]$Enabled)

    $Window.Dispatcher.Invoke([action]{
        if ($BtnCheckUpdates) { $BtnCheckUpdates.IsEnabled = $Enabled }
        if ($BtnUpdateNow)    { $BtnUpdateNow.IsEnabled    = $Enabled }
    })
}

function Request-GracefulWatchdogStop {
    # Writes stop signal for your service loop to gracefully stop roles
    try {
        New-Item -Path $StopSignalFile -ItemType File -Force | Out-Null
        Add-GuiLog "Stop signal written: $StopSignalFile"
    } catch {
        Add-GuiLog "WARNING: Failed writing stop signal: $_"
    }
}

function Stop-ServiceAndWait {
    param(
        [Parameter(Mandatory)][string]$Name,
        [int]$TimeoutSeconds = 45
    )

    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { return $true } # Treat as already stopped/not installed

    if ($svc.Status -eq "Stopped") { return $true }

    Request-GracefulWatchdogStop

    Stop-Service -Name $Name -ErrorAction Stop

    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        Start-Sleep -Milliseconds 500
        $svc.Refresh()
        if ($svc.Status -eq "Stopped") { return $true }
    }

    throw "Service '$Name' did not stop within ${TimeoutSeconds}s."
}

function Start-ServiceAndWait {
    param(
        [Parameter(Mandatory)][string]$Name,
        [int]$TimeoutSeconds = 30
    )

    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { throw "Service '$Name' is not installed." }

    if ($svc.Status -ne "Running") {
        Start-Service -Name $Name -ErrorAction Stop
    }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        Start-Sleep -Milliseconds 500
        $svc.Refresh()
        if ($svc.Status -eq "Running") { return $true }
    }

    throw "Service '$Name' did not reach Running state within ${TimeoutSeconds}s."
}

function Download-FileWithProgress {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$OutFile
    )

    # Ensure TLS 1.2 for GitHub
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

    if (Test-Path $OutFile) { Remove-Item $OutFile -Force -ErrorAction SilentlyContinue }

    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("User-Agent", "WoWWatchdog")

    $script:dlCompleted = $false
    $script:dlError     = $null

    $wc.add_DownloadProgressChanged({
        param($s, $e)
        Set-UpdateFlowUi -Text ("Downloading update. {0}%" -f $e.ProgressPercentage) -Percent $e.ProgressPercentage -Show $true -Indeterminate $false
    })

    $wc.add_DownloadFileCompleted({
        param($s, $e)
        if ($e.Error) { $script:dlError = $e.Error }
        $script:dlCompleted = $true
    })

    Set-UpdateFlowUi -Text "Starting download." -Percent 0 -Show $true -Indeterminate $true
    $wc.DownloadFileAsync([Uri]$Url, $OutFile)

    while (-not $script:dlCompleted) { Start-Sleep -Milliseconds 120 }

    if ($script:dlError) { throw "Download failed: $($script:dlError.Message)" }
    if (-not (Test-Path $OutFile)) { throw "Download did not create file: $OutFile" }

    return $true
}

function Run-InstallerAndWait {
    param(
        [Parameter(Mandatory)][string]$InstallerPath
    )

    if (-not (Test-Path $InstallerPath)) {
        throw "Installer not found: $InstallerPath"
    }

    $installerArgs = @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/SP-"
    )

    Set-UpdateFlowUi -Text "Running installer." -Percent 100 -Show $true -Indeterminate $true

    $p = Start-Process -FilePath $InstallerPath -ArgumentList $installerArgs -PassThru -Wait -ErrorAction Stop
    if ($p.ExitCode -ne 0) {
        throw "Installer failed with exit code $($p.ExitCode)."
    }

    return $true
}

function Read-UncPathFromUser {
    param(
        [string]$Prompt = "Enter a UNC path (example: \\server\share\folder):",
        [string]$DefaultValue = ""
    )

    try { Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue | Out-Null } catch { }

    $p = [Microsoft.VisualBasic.Interaction]::InputBox($Prompt, "UNC Path", ($DefaultValue + ""))
    $p = ($p + "").Trim()

    if ([string]::IsNullOrWhiteSpace($p)) { return $null }

    # Basic UNC validation: \\server\share or deeper
    if ($p -notmatch '^[\\]{2}[^\\]+\\[^\\]+') {
        [System.Windows.MessageBox]::Show(
            "That does not look like a valid UNC path.`r`nExample: \\server\share\folder",
            "Invalid UNC Path",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning
        ) | Out-Null
        return $null
    }

    return $p
}

# -------------------------------------------------
# XAML – Dark/Blue Theme
# -------------------------------------------------
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="WoW Watchdog"
        Width="900" Height="1200"
        WindowStartupLocation="CenterScreen"
        ResizeMode="CanResizeWithGrip"
        Background="Transparent"
        AllowsTransparency="True"
        WindowStyle="None">

<Window.Resources>

  <!-- Unified TextBox Style -->
  <Style TargetType="TextBox">
    <Setter Property="Background" Value="#FF0F141F"/>
    <Setter Property="Foreground" Value="White"/>
    <Setter Property="BorderBrush" Value="#FF345A8A"/>
    <Setter Property="CaretBrush" Value="White"/>
    <Setter Property="Padding" Value="6,3"/>
  </Style>

  <!-- ===============================
     Button Styles
     =============================== -->

<!-- Primary action (blue) -->
<Style x:Key="BtnPrimary" TargetType="Button">
  <Setter Property="Background" Value="#FF3478BF"/>
  <Setter Property="Foreground" Value="White"/>
  <Setter Property="BorderBrush" Value="#FF2B5E9A"/>
  <Setter Property="BorderThickness" Value="1"/>
  <Setter Property="Padding" Value="10,4"/>
</Style>

<!-- Start / positive (green) -->
<Style x:Key="BtnStart" TargetType="Button">
  <Setter Property="Background" Value="#FF2D7A3A"/>
  <Setter Property="Foreground" Value="White"/>
  <Setter Property="BorderBrush" Value="#FF1E5A2B"/>
  <Setter Property="BorderThickness" Value="1"/>
  <Setter Property="Padding" Value="10,4"/>
</Style>

<!-- Stop / destructive (red) -->
<Style x:Key="BtnStop" TargetType="Button">
  <Setter Property="Background" Value="#FF7A3A3A"/>
  <Setter Property="Foreground" Value="White"/>
  <Setter Property="BorderBrush" Value="#FF5A2626"/>
  <Setter Property="BorderThickness" Value="1"/>
  <Setter Property="Padding" Value="10,4"/>
</Style>

<!-- Neutral / secondary (dark blue-gray) -->
<Style x:Key="BtnSecondary" TargetType="Button">
  <Setter Property="Background" Value="#FF1B2A42"/>
  <Setter Property="Foreground" Value="White"/>
  <Setter Property="BorderBrush" Value="#FF2B3E5E"/>
  <Setter Property="BorderThickness" Value="1"/>
  <Setter Property="Padding" Value="10,4"/>
</Style>


  <!-- Unified ComboBox Style -->
  <Style TargetType="ComboBox">
  <Setter Property="Foreground" Value="White"/>
  <Setter Property="Background" Value="#FF0F141F"/>
  <Setter Property="BorderBrush" Value="#FF345A8A"/>
  <Setter Property="BorderThickness" Value="1"/>
  <Setter Property="Padding" Value="6,3"/>
  <Setter Property="Template">
    <Setter.Value>
      <ControlTemplate TargetType="ComboBox">
        <Grid>

          <!-- Outer border -->
          <Border x:Name="Border"
                  Background="{TemplateBinding Background}"
                  BorderBrush="{TemplateBinding BorderBrush}"
                  BorderThickness="{TemplateBinding BorderThickness}"
                  CornerRadius="2"/>

          <!-- COLLAPSED CONTENT -->
          <ContentPresenter x:Name="ContentSite"
                            Margin="8,3,24,3"
                            VerticalAlignment="Center"
                            HorizontalAlignment="Left"
                            Content="{TemplateBinding SelectionBoxItem}"
                            ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}"
                            TextElement.Foreground="{TemplateBinding Foreground}"/>

          <!-- Dropdown arrow -->
          <ToggleButton x:Name="ToggleButton"
                        IsChecked="{Binding IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}"
                        Focusable="False"
                        ClickMode="Press"
                        Background="Transparent"
                        BorderThickness="0"
                        HorizontalAlignment="Right"
                        Width="22">
            <Path Data="M 0 0 L 4 4 L 8 0 Z"
                  Fill="White"
                  VerticalAlignment="Center"
                  HorizontalAlignment="Center"/>
          </ToggleButton>

          <!-- Popup list -->
          <Popup x:Name="Popup"
                 Placement="Bottom"
                 IsOpen="{TemplateBinding IsDropDownOpen}"
                 AllowsTransparency="True"
                 Focusable="False"
                 PopupAnimation="Fade">
            <Border Background="#FF0F141F"
                    BorderBrush="#FF345A8A"
                    BorderThickness="1">
              <ScrollViewer>
                <ItemsPresenter/>
              </ScrollViewer>
            </Border>
          </Popup>

        </Grid>

        <ControlTemplate.Triggers>
          <Trigger Property="IsEnabled" Value="False">
            <Setter Property="TextElement.Foreground" Value="#FF777777"/>
          </Trigger>
        </ControlTemplate.Triggers>

      </ControlTemplate>
    </Setter.Value>
  </Setter>
</Style>

</Window.Resources>

  <Border CornerRadius="14"
          Background="#FF0D111A"
          BorderBrush="#FF2B3E5E"
          BorderThickness="1"
          SnapsToDevicePixels="True">

    <Border.Effect>
      <DropShadowEffect Color="Black" BlurRadius="20" ShadowDepth="4" Opacity="0.35"/>
    </Border.Effect>

    <Grid Margin="8">
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="*"/>
      </Grid.RowDefinitions>

      <!-- Title Bar -->
      <Border Grid.Row="0"
              CornerRadius="12"
              Padding="10,8"
              Background="#FF101829">
        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>

          <StackPanel Orientation="Horizontal">
            <TextBlock Text="WoW Watchdog"
                       Foreground="#FFBDDCFF"
                       FontWeight="Bold"
                       FontSize="16"
                       VerticalAlignment="Center"/>
            <TextBlock Text="  •  GUI + Watchdog Monitor"
                       Foreground="#FF86B5E5"
                       FontSize="12"
                       VerticalAlignment="Center"
                       Margin="8,2,0,0"/>
          </StackPanel>

          <Button x:Name="BtnMinimize"
                  Grid.Column="1"
                  Content="—"
                  Width="32" Height="28"
                  Margin="0,0,6,0"
                  Background="#FF1B2A42"
                  Foreground="White"
                  BorderBrush="#FF2B3E5E"/>

          <Button x:Name="BtnClose"
                  Grid.Column="2"
                  Content="X"
                  Width="32" Height="28"
                  Background="#FF3A1B1B"
                  Foreground="White"
                  BorderBrush="#FF5E2B2B"/>
        </Grid>
      </Border>

      <!-- Main -->
      <Grid Grid.Row="1" Margin="0,10,0,0">
        <TabControl Margin="0,0,0,0"
            Background="#FF0D111A"
            BorderBrush="#FF2B3E5E"
            Foreground="White"
            Padding="4">

  <!-- ================================================= -->
  <!-- TAB 1: Main                                       -->
  <!-- ================================================= -->
  <TabItem Header="Main">
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="*" MinHeight="420"/>
      <RowDefinition Height="6"/>
      <RowDefinition Height="300" MinHeight="180"/>
    </Grid.RowDefinitions>

    <ScrollViewer Grid.Row="0" VerticalScrollBarVisibility="Auto"
                  HorizontalScrollBarVisibility="Disabled">
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/> <!-- Controls -->
          <RowDefinition Height="Auto"/> <!-- Status -->
        </Grid.RowDefinitions>

        <!-- Controls -->
        <GroupBox Grid.Row="0" Margin="0,0,0,10" Foreground="White" HorizontalAlignment="Stretch">
          <GroupBox.Header>
            <TextBlock Text="Controls"
                       Foreground="#FFBDDCFF"
                       FontWeight="SemiBold"/>
          </GroupBox.Header>
          <GroupBox.Background>
            <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
              <GradientStop Color="#FF151B28" Offset="0.0" />
              <GradientStop Color="#FF111623" Offset="1.0" />
            </LinearGradientBrush>
          </GroupBox.Background>

          <Grid Margin="10">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/> <!-- Watchdog -->
              <RowDefinition Height="Auto"/> <!-- Service Control -->
              <RowDefinition Height="Auto"/> <!-- Stack Actions -->
            </Grid.RowDefinitions>

            <!-- Watchdog -->
            <StackPanel Grid.Row="0" Margin="0,0,0,12">
              <TextBlock Text="Watchdog"
                         Foreground="#FF86B5E5"
                         FontWeight="SemiBold"
                         Margin="0,0,0,6"/>
              <StackPanel Orientation="Horizontal">
                <Button x:Name="BtnStartWatchdog"
                        Content="Start Watchdog"
                        MinWidth="160"
                        Background="#FF2D7A3A"
                        Foreground="White"
                        Margin="0,0,10,0"/>
                <Button x:Name="BtnStopWatchdog"
                        Content="Stop Watchdog"
                        MinWidth="160"
                        Background="#FF7A3A3A"
                        Foreground="White"/>
              </StackPanel>
            </StackPanel>

            <!-- Service Control -->
            <StackPanel Grid.Row="1" Margin="0,0,0,12">
              <TextBlock Text="Service Control"
                         Foreground="#FF86B5E5"
                         FontWeight="SemiBold"
                         Margin="0,0,0,6"/>

              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="160"/>
                  <ColumnDefinition Width="Auto"/>
                  <ColumnDefinition Width="Auto"/>
                  <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/> <!-- header -->
                  <RowDefinition Height="Auto"/> <!-- MySQL -->
                  <RowDefinition Height="Auto"/> <!-- Auth -->
                  <RowDefinition Height="Auto"/> <!-- World -->
                </Grid.RowDefinitions>

                <!-- Column headers -->
                <TextBlock Grid.Row="0" Grid.Column="1" Text="Start" Foreground="White" Opacity="0.8" Margin="0,0,10,6" HorizontalAlignment="Center"/>
                <TextBlock Grid.Row="0" Grid.Column="2" Text="Stop" Foreground="White" Opacity="0.8" Margin="0,0,10,6" HorizontalAlignment="Center"/>
                <TextBlock Grid.Row="0" Grid.Column="3" Text="Restart" Foreground="White" Opacity="0.8" Margin="0,0,0,6" HorizontalAlignment="Center"/>

                <!-- MySQL -->
                <TextBlock Grid.Row="1" Grid.Column="0" Text="Database (MySQL)" Foreground="White" VerticalAlignment="Center" Margin="0,0,10,6"/>
                <Button x:Name="BtnStartMySQL" Grid.Row="1" Grid.Column="1" Content="Start" Width="90" Margin="0,0,10,6" Style="{StaticResource BtnStart}"/>
                <Button x:Name="BtnStopMySQL"  Grid.Row="1" Grid.Column="2" Content="Stop"  Width="90" Margin="0,0,10,6" Style="{StaticResource BtnStop}"/>
                <Button x:Name="BtnRestartMySQL" Grid.Row="1" Grid.Column="3" Content="Restart" Width="90" Margin="0,0,0,6" Style="{StaticResource BtnSecondary}"/>

                <!-- Auth -->
                <TextBlock Grid.Row="2" Grid.Column="0" Text="Auth Server" Foreground="White" VerticalAlignment="Center" Margin="0,0,10,6"/>
                <Button x:Name="BtnStartAuth" Grid.Row="2" Grid.Column="1" Content="Start" Width="90" Margin="0,0,10,6" Style="{StaticResource BtnStart}"/>
                <Button x:Name="BtnStopAuth"  Grid.Row="2" Grid.Column="2" Content="Stop"  Width="90" Margin="0,0,10,6" Style="{StaticResource BtnStop}"/>
                <Button x:Name="BtnRestartAuth" Grid.Row="2" Grid.Column="3" Content="Restart" Width="90" Margin="0,0,0,6" Style="{StaticResource BtnSecondary}"/>

                <!-- World -->
                <TextBlock Grid.Row="3" Grid.Column="0" Text="World Server" Foreground="White" VerticalAlignment="Center" Margin="0,0,10,0"/>
                <Button x:Name="BtnStartWorld" Grid.Row="3" Grid.Column="1" Content="Start" Width="90" Margin="0,0,10,0" Style="{StaticResource BtnStart}"/>
                <Button x:Name="BtnStopWorld"  Grid.Row="3" Grid.Column="2" Content="Stop"  Width="90" Margin="0,0,10,0" Style="{StaticResource BtnStop}"/>
                <Button x:Name="BtnRestartWorld" Grid.Row="3" Grid.Column="3" Content="Restart" Width="90" Margin="0,0,0,0" Style="{StaticResource BtnSecondary}"/>
              </Grid>
            </StackPanel>

            <!-- Stack Actions -->
            <StackPanel Grid.Row="2">
              <TextBlock Text="Stack Actions"
                         Foreground="#FF86B5E5"
                         FontWeight="SemiBold"
                         Margin="0,0,0,6"/>
              <StackPanel Orientation="Horizontal">
                <Button x:Name="BtnStartAll"
                        Content="Start Stack (Ordered)"
                        Width="180"
                        Margin="0,0,10,0"
                        Style="{StaticResource BtnStart}"/>

                <Button x:Name="BtnStopAll"
                        Content="Stop Stack"
                        Width="140"
                        Margin="0,0,10,0"
                        Style="{StaticResource BtnStop}"/>

                <Button x:Name="BtnRestartStack"
                        Content="Restart Stack"
                        Width="140"
                        Style="{StaticResource BtnSecondary}"/>
              </StackPanel>
            </StackPanel>
          </Grid>
        </GroupBox>

        <!-- Status -->
        <GroupBox Grid.Row="1" Margin="0,0,0,10" Foreground="White" HorizontalAlignment="Stretch">
          <GroupBox.Header>
            <TextBlock Text="Status"
                       Foreground="#FFBDDCFF"
                       FontWeight="SemiBold"/>
          </GroupBox.Header>
          <GroupBox.Background>
            <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
              <GradientStop Color="#FF151B28" Offset="0.0" />
              <GradientStop Color="#FF111623" Offset="1.0" />
            </LinearGradientBrush>
          </GroupBox.Background>

          <Grid Margin="10">
            <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/> <!-- Watchdog -->
            <RowDefinition Height="Auto"/> <!-- Service -->
            <RowDefinition Height="Auto"/> <!-- LEDs -->
            <RowDefinition Height="Auto"/> <!-- Online players -->
            <RowDefinition Height="Auto"/> <!-- Resource utilization -->
            <RowDefinition Height="Auto"/> <!-- World uptime (NEW) -->
            </Grid.RowDefinitions>

            <WrapPanel Grid.Row="0" Margin="0,0,0,6">
              <TextBlock Text="Watchdog:" Foreground="White" Margin="0,0,6,0"/>
              <TextBlock x:Name="TxtWatchdogStatus"
                         Text="Stopped"
                         Foreground="Orange"
                         FontWeight="Bold"/>
            </WrapPanel>

            <WrapPanel Grid.Row="1" Margin="0,0,0,8">
              <TextBlock Text="Service:"
                         Foreground="#FF86B5E5"
                         Margin="0,0,6,0"/>
              <TextBlock x:Name="TxtServiceStatus"
                         Text="Not installed"
                         Foreground="#FFFFB347"
                         FontWeight="SemiBold"/>
            </WrapPanel>

            <WrapPanel Grid.Row="2" Margin="0,0,0,8">
              <StackPanel Orientation="Horizontal" Margin="0,0,18,0">
                <Ellipse x:Name="EllipseMySQL" Width="14" Height="14" Margin="0,0,6,0"/>
                <TextBlock Text="MySQL" Foreground="White" VerticalAlignment="Center"/>
              </StackPanel>

              <StackPanel Orientation="Horizontal" Margin="0,0,18,0">
                <Ellipse x:Name="EllipseAuth" Width="14" Height="14" Margin="0,0,6,0"/>
                <TextBlock Text="Authserver" Foreground="White" VerticalAlignment="Center"/>
              </StackPanel>

              <StackPanel Orientation="Horizontal">
                <Ellipse x:Name="EllipseWorld" Width="14" Height="14" Margin="0,0,6,0"/>
                <TextBlock Text="Worldserver" Foreground="White" VerticalAlignment="Center"/>
              </StackPanel>
            </WrapPanel>

            <!-- Online Players moved into Status -->
            <WrapPanel Grid.Row="3">
              <TextBlock Text="Online Players:" Foreground="#FF86B5E5" Margin="0,0,6,0"/>
              <TextBlock x:Name="TxtOnlinePlayers"
                         Text="—"
                         FontSize="16"
                         FontWeight="Bold"
                         Foreground="LimeGreen"/>
            </WrapPanel>

            <!-- Resource Utilization (snapshot) -->
            <Grid Grid.Row="4" Margin="0,10,0,0">
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/> <!-- header -->
                <RowDefinition Height="Auto"/> <!-- mysql -->
                <RowDefinition Height="Auto"/> <!-- auth -->
                <RowDefinition Height="Auto"/> <!-- world -->
            </Grid.RowDefinitions>

            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="90"/>
                <ColumnDefinition Width="110"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>

            <TextBlock Grid.Row="0" Grid.Column="0" Grid.ColumnSpan="3"
                        Text="Resource Utilization (Snapshot)"
                        Foreground="#FF86B5E5"
                        Margin="0,0,0,6"/>

            <!-- MySQL -->
            <TextBlock Grid.Row="1" Grid.Column="0" Text="MySQL:" Foreground="White" Margin="0,0,8,4"/>
            <TextBlock Grid.Row="1" Grid.Column="1" x:Name="TxtUtilMySQLCpu" Text="CPU: —" Foreground="White" Margin="0,0,8,4"/>
            <TextBlock Grid.Row="1" Grid.Column="2" x:Name="TxtUtilMySQLMem" Text="RAM: —" Foreground="White" Margin="0,0,0,4"/>

            <!-- Authserver -->
            <TextBlock Grid.Row="2" Grid.Column="0" Text="Auth:" Foreground="White" Margin="0,0,8,4"/>
            <TextBlock Grid.Row="2" Grid.Column="1" x:Name="TxtUtilAuthCpu" Text="CPU: —" Foreground="White" Margin="0,0,8,4"/>
            <TextBlock Grid.Row="2" Grid.Column="2" x:Name="TxtUtilAuthMem" Text="RAM: —" Foreground="White" Margin="0,0,0,4"/>

            <!-- Worldserver -->
            <TextBlock Grid.Row="3" Grid.Column="0" Text="World:" Foreground="White"/>
            <TextBlock Grid.Row="3" Grid.Column="1" x:Name="TxtUtilWorldCpu" Text="CPU: —" Foreground="White" Margin="0,0,8,0"/>
            <TextBlock Grid.Row="3" Grid.Column="2" x:Name="TxtUtilWorldMem" Text="RAM: —" Foreground="White"/>
            </Grid>

            <!-- World Uptime -->
            <WrapPanel Grid.Row="5" Margin="0,10,0,0">
            <TextBlock Text="World Uptime:" Foreground="#FF86B5E5" Margin="0,0,6,0"/>
            <TextBlock x:Name="TxtWorldUptime"
                        Text="—"
                        FontWeight="SemiBold"
                        Foreground="White"/>
            </WrapPanel>
          </Grid>
        </GroupBox>

      </Grid>
    </ScrollViewer>

    <GridSplitter Grid.Row="1"
                  Height="6"
                  HorizontalAlignment="Stretch"
                  Background="#FF345A8A"
                  ShowsPreview="True"/>

    <!-- Live Log (Main tab only) -->
    <GroupBox Grid.Row="2" Foreground="White" HorizontalAlignment="Stretch" Margin="0,8,0,0">
  <GroupBox.Header>
    <TextBlock Text="Live Log"
               Foreground="#FFBDDCFF"
               FontWeight="SemiBold"/>
  </GroupBox.Header>

  <GroupBox.Background>
    <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
      <GradientStop Color="#FF151B28" Offset="0.0" />
      <GradientStop Color="#FF111623" Offset="1.0" />
    </LinearGradientBrush>
  </GroupBox.Background>

  <Grid Margin="10">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
    </Grid.RowDefinitions>

    <!-- Header row (text + button) -->
    <Grid Grid.Row="0" Margin="0,0,0,6">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>

      <TextBlock Grid.Column="0"
                 Text="watchdog.log (updates every second)"
                 Foreground="#FF86B5E5"/>

      <Button x:Name="BtnClearLog"
              Grid.Column="1"
              Content="Clear Log"
              MinWidth="100"
              Margin="10,0,0,0"
              Background="#FF1B2A42"
              Foreground="White"
              BorderBrush="#FF2B3E5E"/>
    </Grid>

    <!-- Log row -->
    <ScrollViewer Grid.Row="1"
                  VerticalScrollBarVisibility="Auto"
                  HorizontalScrollBarVisibility="Auto">
      <TextBox x:Name="TxtLiveLog"
               FontFamily="Consolas"
               FontSize="12"
               IsReadOnly="True"
               TextWrapping="NoWrap"
               Background="#FF0F141F"
               Foreground="#FFE6F2FF"
               BorderBrush="#FF345A8A"
               VerticalScrollBarVisibility="Disabled"
               HorizontalScrollBarVisibility="Disabled"/>
    </ScrollViewer>

  </Grid>
</GroupBox>
  </Grid>
</TabItem>

  <!-- ================================================= -->
  <!-- TAB 2: Configuration                              -->
  <!-- ================================================= -->
  <TabItem Header="Configuration">
    <ScrollViewer VerticalScrollBarVisibility="Auto"
                  HorizontalScrollBarVisibility="Disabled">
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/> <!-- Server Paths -->
          <RowDefinition Height="Auto"/> <!-- DB Settings -->
          <RowDefinition Height="Auto"/> <!-- NTFY -->
          <RowDefinition Height="Auto"/> <!-- Worldserver Telnet -->
          <RowDefinition Height="Auto"/> <!-- Save Config -->
        </Grid.RowDefinitions>

        <!-- Server Paths -->
        <GroupBox Grid.Row="0" Margin="0,0,0,10" Foreground="White" HorizontalAlignment="Stretch">
          <GroupBox.Header>
            <TextBlock Text="Server Paths"
                       Foreground="#FFBDDCFF"
                       FontWeight="SemiBold"/>
          </GroupBox.Header>
          <GroupBox.Background>
            <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
              <GradientStop Color="#FF151B28" Offset="0.0" />
              <GradientStop Color="#FF111623" Offset="1.0" />
            </LinearGradientBrush>
          </GroupBox.Background>

          <Grid Margin="10">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/> <!-- MySQL -->
              <RowDefinition Height="Auto"/> <!-- MySQL EXE -->
              <RowDefinition Height="Auto"/> <!-- Auth -->
              <RowDefinition Height="Auto"/> <!-- World -->
            </Grid.RowDefinitions>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>

            <TextBlock Grid.Row="0" Grid.Column="0" Text="MySQL start (.bat):" VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
            <TextBox x:Name="TxtMySQL" Grid.Row="0" Grid.Column="1" Margin="4,2"
                     Background="#FF0F141F" Foreground="White" BorderBrush="#FF345A8A"/>
            <Button x:Name="BtnBrowseMySQL" Grid.Row="0" Grid.Column="2" Content="Browse" MinWidth="80"
                    Background="#FF1B2A42" Foreground="White" BorderBrush="#FF2B3E5E" Margin="6,2,0,2"/>

            <TextBlock Grid.Row="1" Grid.Column="0" Text="mysql.exe:" VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
            <TextBox x:Name="TxtMySQLExe" Grid.Row="1" Grid.Column="1" Margin="4,2"
                     Background="#FF0F141F" Foreground="White" BorderBrush="#FF345A8A"/>
            <Button x:Name="BtnBrowseMySQLExe" Grid.Row="1" Grid.Column="2" Content="Browse" MinWidth="80"
                    Background="#FF1B2A42" Foreground="White" BorderBrush="#FF2B3E5E" Margin="6,2,0,2"/>

            <TextBlock Grid.Row="2" Grid.Column="0" Text="Authserver:" VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
            <TextBox x:Name="TxtAuth" Grid.Row="2" Grid.Column="1" Margin="4,2"
                     Background="#FF0F141F" Foreground="White" BorderBrush="#FF345A8A"/>
            <Button x:Name="BtnBrowseAuth" Grid.Row="2" Grid.Column="2" Content="Browse" MinWidth="80"
                    Background="#FF1B2A42" Foreground="White" BorderBrush="#FF2B3E5E" Margin="6,2,0,2"/>

            <TextBlock Grid.Row="3" Grid.Column="0" Text="Worldserver:" VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
            <TextBox x:Name="TxtWorld" Grid.Row="3" Grid.Column="1" Margin="4,2"
                     Background="#FF0F141F" Foreground="White" BorderBrush="#FF345A8A"/>
            <Button x:Name="BtnBrowseWorld" Grid.Row="3" Grid.Column="2" Content="Browse" MinWidth="80"
                    Background="#FF1B2A42" Foreground="White" BorderBrush="#FF2B3E5E" Margin="6,2,0,2"/>
          </Grid>
        </GroupBox>

        <!-- DB Settings -->
        <GroupBox Grid.Row="1"
                  Margin="0,0,0,10"
                  Foreground="White"
                  HorizontalAlignment="Stretch">
          <GroupBox.Header>
            <TextBlock Text="Database Settings"
                       Foreground="#FFBDDCFF"
                       FontWeight="SemiBold"/>
          </GroupBox.Header>

          <GroupBox.Background>
            <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
              <GradientStop Color="#FF151B28" Offset="0.0"/>
              <GradientStop Color="#FF111623" Offset="1.0"/>
            </LinearGradientBrush>
          </GroupBox.Background>

          <Grid Margin="10">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/> <!-- standout button row -->
              <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="110"/>
            </Grid.ColumnDefinitions>

            <!-- Host -->
            <TextBlock Grid.Row="0" Grid.Column="0" Text="Host:" VerticalAlignment="Center" Margin="0,0,6,0"/>
            <TextBox x:Name="TxtDbHost" Grid.Row="0" Grid.Column="1" Margin="0,2,6,2"/>

            <!-- Port -->
            <TextBlock Grid.Row="0" Grid.Column="2" Text="Port:" VerticalAlignment="Center" Margin="6,0,6,0"/>
            <TextBox x:Name="TxtDbPort" Grid.Row="0" Grid.Column="3" Margin="0,2,0,2"/>

            <!-- User -->
            <TextBlock Grid.Row="1" Grid.Column="0" Text="User:" VerticalAlignment="Center" Margin="0,0,6,0"/>
            <TextBox x:Name="TxtDbUser" Grid.Row="1" Grid.Column="1" Margin="0,2,6,2"/>

            <!-- DB Name -->
            <TextBlock Grid.Row="1" Grid.Column="2" Text="DB:" VerticalAlignment="Center" Margin="6,0,6,0"/>
            <TextBox x:Name="TxtDbNameChar" Grid.Row="1" Grid.Column="3" Margin="0,2,0,2"
                     ToolTip="Character database name (defaults to legion_characters)"/>

            <!-- Password -->
            <TextBlock Grid.Row="2" Grid.Column="0" Text="Password:" VerticalAlignment="Center" Margin="0,0,6,0"/>
            <PasswordBox x:Name="TxtDbPassword" Grid.Row="2" Grid.Column="1" Margin="0,2,6,2"/>

            <!-- Test DB -->
            <Button x:Name="BtnTestDb" Grid.Row="2" Grid.Column="3"
                    Content="Test DB" Width="110"
                    Background="#FF1B2A42" Foreground="White" BorderBrush="#FF2B3E5E"
                    Margin="0,2,0,2"/>

            <!-- Standout Save Password -->
            <Button x:Name="BtnSaveDbPassword"
                    Grid.Row="3" Grid.Column="0" Grid.ColumnSpan="4"
                    Content="Store Database Password (Encrypted)"
                    Height="34"
                    Margin="0,8,0,0"
                    Background="#FF3478BF"
                    Foreground="White"
                    BorderBrush="#FF2B5E9A"
                    BorderThickness="1"/>

            <TextBlock Grid.Row="4" Visibility="Collapsed"/>
          </Grid>
        </GroupBox>

        <!-- NTFY Notifications (moved here) -->
        <GroupBox Grid.Row="2" Margin="0,0,0,10" Foreground="White" HorizontalAlignment="Stretch">
          <GroupBox.Header>
            <TextBlock Text="NTFY Notifications"
                       Foreground="#FFBDDCFF"
                       FontWeight="SemiBold"/>
          </GroupBox.Header>

          <GroupBox.Background>
            <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
              <GradientStop Color="#FF151B28" Offset="0.0"/>
              <GradientStop Color="#FF111623" Offset="1.0"/>
            </LinearGradientBrush>
          </GroupBox.Background>

          <!-- (Unchanged: your entire existing NTFY grid) -->
          <Grid Margin="10">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>

            <!-- Expansion -->
            <TextBlock Grid.Row="0" Grid.Column="0" Text="Expansion:"
                       VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
            <StackPanel Grid.Row="0" Grid.Column="1" Orientation="Horizontal" Margin="4,2">
              <ComboBox x:Name="CmbExpansion"
                        MinWidth="140"
                        Background="#FF0F141F"
                        Foreground="White"
                        BorderBrush="#FF345A8A">
                <ComboBoxItem Content="Classic" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="TBC" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="WotLK" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="MoP" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="Legion" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="BFA" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="Shadowlands" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="Dragonflight" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="Custom" Background="#FF0F141F" Foreground="White"/>
              </ComboBox>

              <TextBox x:Name="TxtExpansionCustom"
                       MinWidth="160"
                       Margin="8,0,0,0"
                       Background="#FF0F141F"
                       Foreground="White"
                       BorderBrush="#FF345A8A"
                       Visibility="Collapsed"
                       ToolTip="Custom expansion label (used only when Expansion = Custom)"/>
            </StackPanel>

            <!-- NTFY Server -->
            <TextBlock Grid.Row="1" Grid.Column="0" Text="NTFY Server:"
                       VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
            <TextBox Grid.Row="1" Grid.Column="1"
                     x:Name="TxtNtfyServer"
                     Margin="4,2"
                     Background="#FF0F141F"
                     Foreground="White"
                     BorderBrush="#FF345A8A"/>

            <!-- Topic -->
            <TextBlock Grid.Row="2" Grid.Column="0" Text="Topic:"
                       VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
            <TextBox Grid.Row="2" Grid.Column="1"
                     x:Name="TxtNtfyTopic"
                     Margin="4,2"
                     Background="#FF0F141F"
                     Foreground="White"
                     BorderBrush="#FF345A8A"/>

            <!-- Tags -->
            <TextBlock Grid.Row="3" Grid.Column="0" Text="Tags:"
                       VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
            <TextBox Grid.Row="3" Grid.Column="1"
                     x:Name="TxtNtfyTags"
                     Margin="4,2"
                     Background="#FF0F141F"
                     Foreground="White"
                     BorderBrush="#FF345A8A"/>

            <!-- Auth Mode -->
            <TextBlock Grid.Row="4" Grid.Column="0" Text="Auth Mode:"
                       VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
            <ComboBox Grid.Row="4" Grid.Column="1"
                      x:Name="CmbNtfyAuthMode"
                      MinWidth="160"
                      Margin="4,2"
                      Background="#FF0F141F"
                      Foreground="White"
                      BorderBrush="#FF345A8A">
              <ComboBoxItem Content="None" IsSelected="True"/>
              <ComboBoxItem Content="Basic (User/Pass)"/>
              <ComboBoxItem Content="Token (Bearer)"/>
            </ComboBox>

            <!-- Username -->
            <TextBlock x:Name="LblNtfyUsername" Grid.Row="5" Grid.Column="0" Text="Username:"
                       VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0" Visibility="Collapsed"/>
            <TextBox Grid.Row="5" Grid.Column="1"
                     x:Name="TxtNtfyUsername"
                     Margin="4,2"
                     Background="#FF0F141F"
                     Foreground="White"
                     BorderBrush="#FF345A8A"
                     Visibility="Collapsed"/>

            <!-- Password -->
            <TextBlock x:Name="LblNtfyPassword" Grid.Row="6" Grid.Column="0" Text="Password:"
                       VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0" Visibility="Collapsed"/>
            <PasswordBox Grid.Row="6" Grid.Column="1"
                         x:Name="TxtNtfyPassword"
                         Margin="4,2"
                         Background="#FF0F141F"
                         Foreground="White"
                         BorderBrush="#FF345A8A"
                         Visibility="Collapsed"/>

            <!-- Token -->
            <TextBlock x:Name="LblNtfyToken" Grid.Row="7" Grid.Column="0" Text="Token:"
                       VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0" Visibility="Collapsed"/>
            <PasswordBox Grid.Row="7" Grid.Column="1"
                         x:Name="TxtNtfyToken"
                         Margin="4,2"
                         Background="#FF0F141F"
                         Foreground="White"
                         BorderBrush="#FF345A8A"
                         Visibility="Collapsed"/>

            <!-- Default Priority -->
            <TextBlock Grid.Row="8" Grid.Column="0" Text="Priority:"
                       VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
            <ComboBox Grid.Row="8" Grid.Column="1"
                      x:Name="CmbNtfyPriorityDefault"
                      MinWidth="90"
                      Background="#FF0F141F"
                      Foreground="White"
                      BorderBrush="#FF345A8A">
              <ComboBoxItem Content="1" Background="#FF0F141F" Foreground="White"/>
              <ComboBoxItem Content="2" Background="#FF0F141F" Foreground="White"/>
              <ComboBoxItem Content="3" Background="#FF0F141F" Foreground="White"/>
              <ComboBoxItem Content="4" Background="#FF0F141F" Foreground="White"/>
              <ComboBoxItem Content="5" Background="#FF0F141F" Foreground="White"/>
            </ComboBox>

            <!-- Services -->
            <Grid Grid.Row="9" Grid.Column="0" Grid.ColumnSpan="3" Margin="0,6,0,0">
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
              </Grid.RowDefinitions>

              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="Auto"/>
              </Grid.ColumnDefinitions>

              <TextBlock Grid.Row="0" Grid.Column="0" Text="Services:"
                         Foreground="White" VerticalAlignment="Center"/>

              <!-- MySQL -->
              <CheckBox Grid.Row="1" Grid.Column="0"
                        x:Name="ChkNtfyMySQL"
                        Content="MySQL"
                        Foreground="White"/>
              <ComboBox Grid.Row="1" Grid.Column="1"
                        x:Name="CmbPriMySQL"
                        MinWidth="90"
                        Background="#FF0F141F"
                        Foreground="White"
                        BorderBrush="#FF345A8A">
                <ComboBoxItem Content="Auto" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="1" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="2" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="3" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="4" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="5" Background="#FF0F141F" Foreground="White"/>
              </ComboBox>

              <!-- Authserver -->
              <CheckBox Grid.Row="2" Grid.Column="0"
                        x:Name="ChkNtfyAuthserver"
                        Content="Authserver"
                        Foreground="White"/>
              <ComboBox Grid.Row="2" Grid.Column="1"
                        x:Name="CmbPriAuthserver"
                        MinWidth="90"
                        Background="#FF0F141F"
                        Foreground="White"
                        BorderBrush="#FF345A8A">
                <ComboBoxItem Content="Auto" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="1" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="2" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="3" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="4" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="5" Background="#FF0F141F" Foreground="White"/>
              </ComboBox>

              <!-- Worldserver -->
              <CheckBox Grid.Row="3" Grid.Column="0"
                        x:Name="ChkNtfyWorldserver"
                        Content="Worldserver"
                        Foreground="White"/>
              <ComboBox Grid.Row="3" Grid.Column="1"
                        x:Name="CmbPriWorldserver"
                        MinWidth="90"
                        Background="#FF0F141F"
                        Foreground="White"
                        BorderBrush="#FF345A8A">
                <ComboBoxItem Content="Auto" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="1" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="2" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="3" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="4" Background="#FF0F141F" Foreground="White"/>
                <ComboBoxItem Content="5" Background="#FF0F141F" Foreground="White"/>
              </ComboBox>

              <!-- Triggers -->
              <StackPanel Grid.Row="0" Grid.Column="2" Grid.RowSpan="4" Margin="10,0,0,0">
                <CheckBox x:Name="ChkNtfyOnDown" Content="Send on DOWN" Foreground="White"/>
                <CheckBox x:Name="ChkNtfyOnUp" Content="Send on UP" Foreground="White" Margin="0,6,0,0"/>
                <Button x:Name="BtnTestNtfy" Content="Test Notification"
                        Margin="0,10,0,0"
                        Background="#FF3478BF"
                        Foreground="White"/>
              </StackPanel>

            </Grid>
          </Grid>
        </GroupBox>

        <!-- Save Config (prominent, bottom) -->
        
        <!-- Worldserver Telnet -->
        <GroupBox Grid.Row="3" Margin="0,0,0,10" Foreground="White" HorizontalAlignment="Stretch">
          <GroupBox.Header>
            <TextBlock Text="Worldserver Telnet"
                       Foreground="#FFBDDCFF"
                       FontWeight="SemiBold"/>
          </GroupBox.Header>

          <GroupBox.Background>
            <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
              <GradientStop Color="#FF151B28" Offset="0.0" />
              <GradientStop Color="#FF111623" Offset="1.0" />
            </LinearGradientBrush>
          </GroupBox.Background>

          <Grid Margin="10">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="120"/>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="60"/>
              <ColumnDefinition Width="110"/>
            </Grid.ColumnDefinitions>

            <!-- Host / Port -->
            <TextBlock Grid.Row="0" Grid.Column="0"
                       Text="Host/IP:"
                       Foreground="White"
                       VerticalAlignment="Center"
                       Margin="0,0,6,0"/>

            <TextBox x:Name="TxtWorldTelnetHost"
                     Grid.Row="0" Grid.Column="1"
                     Margin="0,2,8,2"
                     Background="#FF0F141F"
                     Foreground="White"
                     BorderBrush="#FF345A8A"/>

            <TextBlock Grid.Row="0" Grid.Column="2"
                       Text="Port:"
                       Foreground="White"
                       VerticalAlignment="Center"
                       Margin="0,0,6,0"/>

            <TextBox x:Name="TxtWorldTelnetPort"
                     Grid.Row="0" Grid.Column="3"
                     Margin="0,2,0,2"
                     Background="#FF0F141F"
                     Foreground="White"
                     BorderBrush="#FF345A8A"/>

            <!-- Username -->
            <TextBlock Grid.Row="1" Grid.Column="0"
                       Text="Username:"
                       Foreground="White"
                       VerticalAlignment="Center"
                       Margin="0,0,6,0"/>

            <TextBox x:Name="TxtWorldTelnetUser"
                     Grid.Row="1" Grid.Column="1" Grid.ColumnSpan="3"
                     Margin="0,2,0,2"
                     Background="#FF0F141F"
                     Foreground="White"
                     BorderBrush="#FF345A8A"/>

            <!-- Password -->
            <TextBlock Grid.Row="2" Grid.Column="0"
                       Text="Password:"
                       Foreground="White"
                       VerticalAlignment="Center"
                       Margin="0,0,6,0"/>

            <PasswordBox x:Name="TxtWorldTelnetPassword"
                         Grid.Row="2" Grid.Column="1" Grid.ColumnSpan="3"
                         Margin="0,2,0,2"
                         Background="#FF0F141F"
                         Foreground="White"
                         BorderBrush="#FF345A8A"/>

            <!-- Stored status -->
            <TextBlock Grid.Row="3" Grid.Column="0"
                       Text="Stored:"
                       Foreground="#FF86B5E5"
                       VerticalAlignment="Center"
                       Margin="0,0,6,0"/>

            <TextBlock x:Name="LblWorldTelnetPasswordStatus"
                       Grid.Row="3" Grid.Column="1" Grid.ColumnSpan="3"
                       Text="Password not set"
                       Foreground="#FFFFD24D"
                       VerticalAlignment="Center"/>

            <!-- Hint -->
            <TextBlock Grid.Row="4" Grid.Column="0" Grid.ColumnSpan="4"
                       Text="Note: Password is stored encrypted in ProgramData and is not shown after restart. To change it, enter a new password and click Save Configuration."
                       Foreground="#FF86B5E5"
                       TextWrapping="Wrap"
                       Margin="0,6,0,0"/>
          </Grid>
        </GroupBox>

<GroupBox Grid.Row="4" Foreground="White" HorizontalAlignment="Stretch" Margin="0,0,0,10">
          <GroupBox.Header>
            <TextBlock Text="Save"
                       Foreground="#FFBDDCFF"
                       FontWeight="SemiBold"/>
          </GroupBox.Header>
          <GroupBox.Background>
            <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
              <GradientStop Color="#FF151B28" Offset="0.0"/>
              <GradientStop Color="#FF111623" Offset="1.0"/>
            </LinearGradientBrush>
          </GroupBox.Background>

          <StackPanel Margin="10">
            <TextBlock Text="Save configuration changes (paths, database settings, NTFY settings)."
                       Foreground="#FF86B5E5"
                       Margin="0,0,0,8"/>
            <Button x:Name="BtnSaveConfig"
                    Content="Save Configuration"
                    Height="38"
                    Background="#FF3478BF"
                    Foreground="White"
                    BorderBrush="#FF2B5E9A"
                    BorderThickness="1"/>
          </StackPanel>
        </GroupBox>

      </Grid>
    </ScrollViewer>
  </TabItem>

<!-- ================================================= -->
<!-- TAB 3: Tools                                      -->
<!-- ================================================= -->
<TabItem Header="Tools">
  <Grid Margin="12">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>  <!-- Launchers -->
      <RowDefinition Height="Auto"/>  <!-- DB Backup/Restore -->
      <RowDefinition Height="Auto"/>  <!-- Repack Backup -->
      <RowDefinition Height="*"/>     <!-- Status / future -->
    </Grid.RowDefinitions>

    <!-- Launchers -->
    <GroupBox Grid.Row="0" Margin="0,0,0,10" Foreground="White" HorizontalAlignment="Stretch">
      <GroupBox.Header>
        <TextBlock Text="Launchers" Foreground="#FFBDDCFF" FontWeight="SemiBold"/>
      </GroupBox.Header>
      <GroupBox.Background>
        <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
          <GradientStop Color="#FF151B28" Offset="0.0"/>
          <GradientStop Color="#FF111623" Offset="1.0"/>
        </LinearGradientBrush>
      </GroupBox.Background>

      <Grid Margin="10">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>

        <!-- Row 0: SPP Legion V2 Manager -->
        <Button x:Name="BtnLaunchSppManager"
                Grid.Row="0"
                Grid.Column="0"
                Content="SPP Legion V2 Manager"
                MinWidth="220"
                Height="40"
                Margin="0,0,12,0"
                Style="{StaticResource BtnPrimary}"/>

        <TextBlock Grid.Row="0"
                   Grid.Column="1"
                   TextWrapping="Wrap"
                   Foreground="#FF86B5E5"
                   VerticalAlignment="Center">
          <Hyperlink NavigateUri="https://github.com/skeezerbean">
            If not already installed by the launcher, the latest release will be downloaded. Credit to Skeezerbean.
          </Hyperlink>
        </TextBlock>

        <!-- Row 1: BattleShopEditor -->
        <Button x:Name="BtnBattleShopEditor"
                Grid.Row="1"
                Grid.Column="0"
                Content="BattleShopEditor"
                MinWidth="220"
                Height="40"
                Margin="0,8,12,0"
                Style="{StaticResource BtnPrimary}"/>

        <TextBlock Grid.Row="1"
                   Grid.Column="1"
                   Margin="0,8,0,0"
                   TextWrapping="Wrap"
                   Foreground="#FF86B5E5"
                   VerticalAlignment="Center">
          Downloads and extracts BattleShopEditor if missing, then launches it.
        </TextBlock>
      </Grid>
    </GroupBox>

    <!-- Database Backup / Restore -->
    <GroupBox Grid.Row="1" Margin="0,0,0,10" Foreground="White" HorizontalAlignment="Stretch">
      <GroupBox.Header>
        <TextBlock Text="Database Backup / Restore" Foreground="#FFBDDCFF" FontWeight="SemiBold"/>
      </GroupBox.Header>
      <GroupBox.Background>
        <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
          <GradientStop Color="#FF151B28" Offset="0.0"/>
          <GradientStop Color="#FF111623" Offset="1.0"/>
        </LinearGradientBrush>
      </GroupBox.Background>

      <Grid Margin="10">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/> <!-- Backup folder -->
          <RowDefinition Height="Auto"/> <!-- Backup options -->
          <RowDefinition Height="Auto"/> <!-- Backup button -->
          <RowDefinition Height="Auto"/> <!-- Divider -->
          <RowDefinition Height="Auto"/> <!-- Restore file -->
          <RowDefinition Height="Auto"/> <!-- Detected DBs -->
          <RowDefinition Height="Auto"/> <!-- Confirmation -->
          <RowDefinition Height="Auto"/> <!-- Restore button -->
        </Grid.RowDefinitions>

        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="180"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="110"/>
        </Grid.ColumnDefinitions>

        <!-- BACKUP -->
        <TextBlock Grid.Row="0" Grid.Column="0"
                   VerticalAlignment="Center"
                   Foreground="#FF86B5E5"
                   Text="Backup folder:"/>

        <TextBox x:Name="TxtDbBackupFolder"
                 Grid.Row="0" Grid.Column="1"
                 Margin="8,2,8,6"
                 MinWidth="320"/>

        <Button x:Name="BtnBrowseDbBackupFolder"
                Grid.Row="0" Grid.Column="2"
                Margin="0,2,0,6"
                Content="Browse"
                MinHeight="28"
                Style="{StaticResource BtnSecondary}"/>

        <StackPanel Grid.Row="1" Grid.Column="1" Grid.ColumnSpan="2"
                    Orientation="Horizontal"
                    Margin="0,0,0,6">
          <CheckBox x:Name="ChkDbBackupCompress"
                    Content="Compress (.zip)"
                    Foreground="White"
                    VerticalAlignment="Center"
                    Margin="0,0,18,0"/>

          <TextBlock Text="Retention (days):"
                     Foreground="#FF86B5E5"
                     VerticalAlignment="Center"
                     Margin="0,0,8,0"/>

          <TextBox x:Name="TxtDbBackupRetentionDays"
                   Width="60"
                   Text="14"/>
        </StackPanel>

        <Button x:Name="BtnRunDbBackup"
                Grid.Row="2" Grid.Column="2"
                Content="Run Backup"
                MinHeight="30"
                Style="{StaticResource BtnPrimary}"/>

        <!-- Status / progress (initially hidden) -->
        <StackPanel Grid.Row="2" Grid.Column="0" Grid.ColumnSpan="2" Margin="0,2,10,0">
          <TextBlock x:Name="TxtDbBackupStatus"
                     Foreground="#FF86B5E5"
                     Text=" "
                     Visibility="Collapsed"/>
          <ProgressBar x:Name="PbDbBackup"
                       Height="12"
                       IsIndeterminate="True"
                       Visibility="Collapsed"/>
        </StackPanel>

        <Separator Grid.Row="3" Grid.Column="0" Grid.ColumnSpan="3"
                   Margin="0,10,0,10"
                   Background="#FF2B3E5E"/>

        <!-- RESTORE -->
        <TextBlock Grid.Row="4" Grid.Column="0"
                   VerticalAlignment="Center"
                   Foreground="#FF86B5E5"
                   Text="Restore .sql/.zip file:"/>

        <TextBox x:Name="TxtDbRestoreFile"
                 Grid.Row="4" Grid.Column="1"
                 Margin="8,2,8,6"
                 MinWidth="320"/>

        <Button x:Name="BtnBrowseDbRestoreFile"
                Grid.Row="4" Grid.Column="2"
                Margin="0,2,0,6"
                Content="Browse"
                MinHeight="28"
                Style="{StaticResource BtnSecondary}"/>

        <TextBlock Grid.Row="5" Grid.Column="0"
                   VerticalAlignment="Center"
                   Foreground="#FF86B5E5"
                   Text="Databases in file:"/>

        <TextBox x:Name="TxtDbRestoreDatabases"
                 Grid.Row="5" Grid.Column="1"
                 Margin="8,2,8,6"
                 MinWidth="320"
                 IsReadOnly="True"
                 Text="(Detected at restore time)"
                 TextWrapping="Wrap"
                 AcceptsReturn="True"
                 VerticalScrollBarVisibility="Auto"/>

        <TextBlock Grid.Row="5" Grid.Column="2"
                   VerticalAlignment="Center"
                   Foreground="#FF86B5E5"
                   Text="(Multi-DB restore)"/>

        <CheckBox x:Name="ChkDbRestoreConfirm"
                  Grid.Row="6" Grid.Column="0" Grid.ColumnSpan="3"
                  Margin="0,6,0,8"
                  Foreground="#FFFFB347"
                  Content="I understand this will overwrite data in the databases contained in the file."/>

        <!-- Status / progress (initially hidden) -->
        <StackPanel Grid.Row="7" Grid.Column="0" Grid.ColumnSpan="2"
                    Margin="0,2,10,0">
          <TextBlock x:Name="TxtDbRestoreStatus"
                     Foreground="#FF86B5E5"
                     Text=" "
                     Visibility="Collapsed"/>
          <ProgressBar x:Name="PbDbRestore"
                       Height="12"
                       IsIndeterminate="True"
                       Visibility="Collapsed"/>
        </StackPanel>

        <Button x:Name="BtnRunDbRestore"
                Grid.Row="7" Grid.Column="2"
                Content="Run Restore"
                MinHeight="30"
                Style="{StaticResource BtnStop}"/>

      </Grid>
    </GroupBox>


    <!-- Repack Backup -->
    <GroupBox Grid.Row="2" Margin="0,0,0,10" Foreground="White" HorizontalAlignment="Stretch">
      <GroupBox.Header>
        <TextBlock Text="Repack Backup" Foreground="#FFBDDCFF" FontWeight="SemiBold"/>
      </GroupBox.Header>
      <GroupBox.Background>
        <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
          <GradientStop Color="#FF151B28" Offset="0.0"/>
          <GradientStop Color="#FF0F141F" Offset="1.0"/>
        </LinearGradientBrush>
      </GroupBox.Background>

      <Grid Margin="10">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/> <!-- Source -->
          <RowDefinition Height="Auto"/> <!-- Destination -->
          <RowDefinition Height="Auto"/> <!-- Buttons -->
          <RowDefinition Height="Auto"/> <!-- Progress -->
          <RowDefinition Height="Auto"/> <!-- Status -->
        </Grid.RowDefinitions>

        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="180"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="110"/>
        </Grid.ColumnDefinitions>

        <TextBlock Grid.Row="0" Grid.Column="0"
                   VerticalAlignment="Center"
                   Foreground="#FF86B5E5"
                   Text="Repack folder:"/>

        <TextBox x:Name="TxtRepackRoot"
                 Grid.Row="0" Grid.Column="1"
                 Margin="8,2,8,6"
                 MinWidth="320"/>

        <Button x:Name="BtnBrowseRepackRoot"
                Grid.Row="0" Grid.Column="2"
                Margin="0,2,0,6"
                Content="Browse"
                MinHeight="28"
                Style="{StaticResource BtnSecondary}"/>

        <TextBlock Grid.Row="1" Grid.Column="0"
                   VerticalAlignment="Center"
                   Foreground="#FF86B5E5"
                   Text="Backup destination:"/>

        <TextBox x:Name="TxtRepackBackupDest"
                 Grid.Row="1" Grid.Column="1"
                 Margin="8,2,8,6"
                 MinWidth="320"/>

        <StackPanel Grid.Row="1" Grid.Column="2" Margin="0,2,0,6">
          <Button x:Name="BtnBrowseRepackBackupDest"
                  Content="Browse"
                  MinHeight="28"
                  Margin="0,0,0,6"
                  Style="{StaticResource BtnSecondary}"/>
          <Button x:Name="BtnOpenRepackBackupDest"
                  Content="Open"
                  MinHeight="28"
                  Style="{StaticResource BtnSecondary}"/>
        </StackPanel>

        <StackPanel Grid.Row="2" Grid.Column="0" Grid.ColumnSpan="3"
                    Orientation="Horizontal"
                    Margin="0,8,0,0">
          <Button x:Name="BtnRunFullBackup"
                  Content="Full Backup"
                  MinWidth="120"
                  Margin="0,0,8,0"
                  Style="{StaticResource BtnPrimary}"/>

          <Button x:Name="BtnRunConfigBackup"
                  Content="Config Backup"
                  MinWidth="140"
                  Style="{StaticResource BtnSecondary}"/>

          <TextBlock Text="(Full backup stops World/Auth/MySQL, zips repack, then restarts.)"
                     Foreground="White"
                     VerticalAlignment="Center"
                     Margin="12,0,0,0"/>
        </StackPanel>

        <ProgressBar x:Name="PbRepackBackup"
                     Grid.Row="3" Grid.Column="0" Grid.ColumnSpan="3"
                     Height="18"
                     Margin="0,10,0,0"
                     IsIndeterminate="True"
                     Visibility="Collapsed"/>

        <TextBlock x:Name="TxtRepackBackupStatus"
                   Grid.Row="4" Grid.Column="0" Grid.ColumnSpan="3"
                   Foreground="#FF86B5E5"
                   TextWrapping="Wrap"
                   Margin="0,8,0,0"
                   Visibility="Collapsed"/>
      </Grid>
    </GroupBox>

    <!-- Optional: status text -->
    <TextBlock Grid.Row="3"
               x:Name="TxtToolsStatus"
               Foreground="#FF86B5E5"
               TextWrapping="Wrap"/>
  </Grid>
</TabItem>

  
<!-- ================================================= -->
<!-- TAB 4: Worldserver Console                         -->
<!-- ================================================= -->
<TabItem Header="Worldserver Console">
  <Grid Margin="12">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
    </Grid.RowDefinitions>

    <!-- Connection -->
    <GroupBox Grid.Row="0" Margin="0,0,0,10" Foreground="White" HorizontalAlignment="Stretch">
      <GroupBox.Header>
        <TextBlock Text="Telnet Connection" Foreground="#FFBDDCFF" FontWeight="SemiBold"/>
      </GroupBox.Header>

      <GroupBox.Background>
        <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
          <GradientStop Color="#FF151B28" Offset="0.0"/>
          <GradientStop Color="#FF111623" Offset="1.0"/>
        </LinearGradientBrush>
      </GroupBox.Background>

      <Grid Margin="10">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>

        <Button x:Name="BtnTelnetConnect"
                Grid.Column="0"
                Content="Connect"
                MinWidth="110"
                Height="32"
                Margin="0,0,8,0"
                Style="{StaticResource BtnPrimary}"/>

        <Button x:Name="BtnTelnetDisconnect"
                Grid.Column="1"
                Content="Disconnect"
                MinWidth="110"
                Height="32"
                Margin="0,0,14,0"
                Style="{StaticResource BtnSecondary}"/>

        <TextBlock Grid.Column="2"
                   Text="Target:"
                   Foreground="#FF86B5E5"
                   VerticalAlignment="Center"
                   Margin="0,0,6,0"/>

        <TextBlock x:Name="TxtTelnetTarget"
                   Grid.Column="3"
                   Text="—"
                   Foreground="White"
                   VerticalAlignment="Center"/>

        <TextBlock x:Name="LblTelnetStatus"
                   Grid.Column="4"
                   Text="Disconnected"
                   Foreground="#FFFFD24D"
                   VerticalAlignment="Center"/>

      </Grid>
    </GroupBox>

    <!-- Output + Worldserver Log -->
    <Grid Grid.Row="1" Margin="0,0,0,10">
      <Grid.RowDefinitions>
        <RowDefinition Height="*"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="6"/>
        <RowDefinition Height="*"/>
      </Grid.RowDefinitions>

      <GroupBox Grid.Row="0" Margin="0" Foreground="White" HorizontalAlignment="Stretch">
      <GroupBox.Header>
        <TextBlock Text="Console Output" Foreground="#FFBDDCFF" FontWeight="SemiBold"/>
      </GroupBox.Header>

      <GroupBox.Background>
        <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
          <GradientStop Color="#FF151B28" Offset="0.0"/>
          <GradientStop Color="#FF111623" Offset="1.0"/>
        </LinearGradientBrush>
      </GroupBox.Background>

      <Grid Margin="10">
        <Grid.RowDefinitions>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <TextBox x:Name="TxtTelnetOutput"
                 Grid.Row="0"
                 VerticalAlignment="Stretch"
                 MinHeight="220"
                 FontFamily="Consolas"
                 FontSize="13"
                 Background="#FF0F141F"
                 Foreground="White"
                 BorderBrush="#FF345A8A"
                 IsReadOnly="True"
                 AcceptsReturn="True"
                 TextWrapping="NoWrap"
                 VerticalScrollBarVisibility="Auto"
                 HorizontalScrollBarVisibility="Auto"/>
      </Grid>
    </GroupBox>
    <!-- Command -->
    <GroupBox Grid.Row="1" Margin="0,10,0,10" Foreground="White" HorizontalAlignment="Stretch">
      <GroupBox.Header>
        <TextBlock Text="Command" Foreground="#FFBDDCFF" FontWeight="SemiBold"/>
      </GroupBox.Header>

      <GroupBox.Background>
        <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
          <GradientStop Color="#FF151B28" Offset="0.0"/>
          <GradientStop Color="#FF111623" Offset="1.0"/>
        </LinearGradientBrush>
      </GroupBox.Background>

      <Grid Margin="10">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>

        <TextBox x:Name="TxtTelnetCommand"
                 Grid.Column="0"
                 FontFamily="Consolas"
                 Background="#FF0F141F"
                 Foreground="White"
                 BorderBrush="#FF345A8A"
                 Margin="0,0,10,0"
                 MinHeight="28"/>

        <Button x:Name="BtnTelnetSend"
                Grid.Column="1"
                Content="Send"
                MinWidth="110"
                Height="30"
                Style="{StaticResource BtnPrimary}"/>
      </Grid>
    </GroupBox>

  



      <GridSplitter Grid.Row="2"
                    Height="6"
                    HorizontalAlignment="Stretch"
                    VerticalAlignment="Stretch"
                    Background="#FF345A8A"
                    ShowsPreview="True"/>

      <GroupBox Grid.Row="3" Margin="0" Foreground="White" HorizontalAlignment="Stretch">
  <GroupBox.Header>
    <TextBlock Text="Worldserver Log Output" Foreground="#FFBDDCFF" FontWeight="SemiBold"/>
  </GroupBox.Header>

  <GroupBox.Background>
    <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
      <GradientStop Color="#FF151B28" Offset="0.0"/>
      <GradientStop Color="#FF111623" Offset="1.0"/>
    </LinearGradientBrush>
  </GroupBox.Background>

  <Grid Margin="10">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
    </Grid.RowDefinitions>

    <Grid Grid.Row="0" Margin="0,0,0,8" Panel.ZIndex="10">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>

      <CheckBox x:Name="ChkWorldLogTail"
                Grid.Column="0"
                Content="Tail log"
                Foreground="White"
                Margin="0,0,10,0"
                VerticalAlignment="Center"/>

      <TextBox x:Name="TxtWorldLogPath"
               Grid.Column="1"
               IsReadOnly="True"
               Background="#FF0F141F"
               Foreground="White"
               BorderBrush="#FF345A8A"
               Margin="0,0,10,0"
               MinHeight="26"/>

      <Button x:Name="BtnBrowseWorldLog"
              Grid.Column="2"
              Content="Browse…"
              Width="90"
              MinHeight="28"
              Margin="0,0,10,0"
              Style="{StaticResource BtnSecondary}"
              Panel.ZIndex="20"
              IsEnabled="True"
              IsHitTestVisible="True"/>

      <Button x:Name="BtnClearWorldLog"
              Grid.Column="3"
              Content="Clear"
              Style="{StaticResource BtnSecondary}"/>
    </Grid>

    <TextBox x:Name="TxtWorldLogOutput"
             Grid.Row="1"
             VerticalAlignment="Stretch"
             MinHeight="180"
             FontFamily="Consolas"
             FontSize="13"
             Background="#FF0F141F"
             Foreground="White"
             BorderBrush="#FF345A8A"
             IsReadOnly="True"
             AcceptsReturn="True"
             TextWrapping="NoWrap"
             VerticalScrollBarVisibility="Auto"
             HorizontalScrollBarVisibility="Auto"/>
  </Grid>
</GroupBox>
    </Grid>
</Grid>
</TabItem>

<!-- ================================================= -->
  <!-- TAB 4: Updates                                   -->
  <!-- ================================================= -->
  <TabItem Header="Updates">
    <ScrollViewer VerticalScrollBarVisibility="Auto"
                  HorizontalScrollBarVisibility="Disabled">

      <Grid Margin="12">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <TextBlock Grid.Row="0"
                   Text="Application Updates"
                   FontSize="16"
                   FontWeight="SemiBold"
                   Foreground="#FFBDDCFF"
                   Margin="0,0,0,10"/>

        <!-- Update Status -->
        <GroupBox Grid.Row="1"
                  Margin="0,0,0,10"
                  Foreground="White"
                  HorizontalAlignment="Stretch">

          <GroupBox.Header>
            <TextBlock Text="Version Status"
                       Foreground="#FFBDDCFF"
                       FontWeight="SemiBold"/>
          </GroupBox.Header>

          <GroupBox.Background>
            <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
              <GradientStop Color="#FF151B28" Offset="0.0"/>
              <GradientStop Color="#FF111623" Offset="1.0"/>
            </LinearGradientBrush>
          </GroupBox.Background>

          <Grid Margin="10">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <!-- Version info -->
            <WrapPanel Grid.Row="0" Margin="0,0,0,8">
              <TextBlock Text="Current Version:"
                         Foreground="#FF86B5E5"
                         Margin="0,0,6,0"/>

              <TextBlock x:Name="TxtCurrentVersion"
                         Text="—"
                         FontWeight="SemiBold"
                         Foreground="White"/>

              <TextBlock Text="   Latest Version:"
                         Foreground="#FF86B5E5"
                         Margin="16,0,6,0"/>

              <TextBlock x:Name="TxtLatestVersion"
                         Text="—"
                         FontWeight="SemiBold"
                         Foreground="White"/>
            </WrapPanel>

            <!-- Buttons -->
            <StackPanel Grid.Row="1"
                        Orientation="Horizontal">

              <Button x:Name="BtnCheckUpdates"
                      Content="Check for Updates"
                      MinWidth="160"
                      Margin="0,0,10,0"
                      Background="#FF1B2A42"
                      Foreground="White"
                      BorderBrush="#FF2B3E5E"/>

              <Button x:Name="BtnUpdateNow"
                      Content="Update Now"
                      MinWidth="140"
                      Background="#FF3478BF"
                      Foreground="White"
                      Visibility="Collapsed"/>
            </StackPanel>

        <!-- Progress / status (initially hidden) -->
        <StackPanel Grid.Row="1" Margin="0,12,0,0">

        <TextBlock x:Name="TxtUpdateFlowStatus"
                    Text=""
                    Foreground="#FF86B5E5"
                    TextWrapping="Wrap"
                    Visibility="Collapsed"
                    Margin="0,0,0,6"/>

        <ProgressBar x:Name="PbUpdateFlow"
                    Height="16"
                    Minimum="0"
                    Maximum="100"
                    Value="0"
                    Visibility="Collapsed"/>
        </StackPanel>

          </Grid>
        </GroupBox>


        <!-- SPP V2 Legion Repack Update -->
        <GroupBox Grid.Row="2"
                  Margin="0,0,0,10"
                  Foreground="White"
                  HorizontalAlignment="Stretch">

          <GroupBox.Header>
            <TextBlock Text="SPP V2 Legion Repack Update"
                       Foreground="#FFBDDCFF"
                       FontWeight="SemiBold"/>
          </GroupBox.Header>

          <GroupBox.Background>
            <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
              <GradientStop Color="#FF151B28" Offset="0.0"/>
              <GradientStop Color="#FF111623" Offset="1.0"/>
            </LinearGradientBrush>
          </GroupBox.Background>

          <Grid Margin="10">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <TextBlock Grid.Row="0"
                       TextWrapping="Wrap"
                       Foreground="#FF86B5E5">
Stops World/Auth/MySQL, creates a full repack backup, runs the SPP V2 updater (wget + 7za + Website\Update.bat), then restarts services (MySQL -> Auth -> World). Long process, plan accordingly for down time.
            </TextBlock>

            <StackPanel Grid.Row="1"
                        Orientation="Horizontal"
                        Margin="0,10,0,0">
              <Button x:Name="BtnSppV2RepackUpdate"
                      Content="Run SPP V2 Repack Update"
                      MinWidth="230"
                      Style="{StaticResource BtnPrimary}"/>

              <TextBlock x:Name="TxtSppV2UpdateTarget"
                         Text="Target: (set Repack folder on Tools tab)"
                         Margin="12,3,0,0"
                         Foreground="#FF86B5E5"
                         VerticalAlignment="Center"/>
            </StackPanel>

            <StackPanel Grid.Row="2" Margin="0,10,0,0">
              <TextBlock x:Name="TxtSppV2UpdateStatus"
                         Text=""
                         Foreground="#FF86B5E5"
                         Visibility="Collapsed"
                         TextWrapping="Wrap"/>
              <ProgressBar x:Name="PbSppV2Update"
                           Height="16"
                           Minimum="0"
                           Maximum="100"
                           Value="0"
                           Visibility="Collapsed"/>
            </StackPanel>

          </Grid>
        </GroupBox>
        <!-- Notes -->
        <TextBlock Grid.Row="3"
                   TextWrapping="Wrap"
                   Foreground="#FF86B5E5">
This application checks GitHub releases to determine if a newer version is available.
Updates are applied in-place and may restart services if required.
        </TextBlock>

      </Grid>
    </ScrollViewer>
  </TabItem>

</TabControl>
</Grid>
    </Grid>
  </Border>
</Window>
"@

[xml]$xamlXml = $xaml
$xmlReader     = New-Object System.Xml.XmlNodeReader $xamlXml
try {
    [xml]$xamlXml = $xaml
    $xmlReader = New-Object System.Xml.XmlNodeReader $xamlXml
    $Window = [Windows.Markup.XamlReader]::Load($xmlReader)
} catch {
    [System.Windows.MessageBox]::Show(
        "Failed to load GUI XAML:`n`n$($_)",
        "WoW Watchdog",
        'OK',
        'Error'
    )
    return
}

$Window.AddHandler(
    [System.Windows.Documents.Hyperlink]::RequestNavigateEvent,
    [System.Windows.Navigation.RequestNavigateEventHandler]{
        param($uiSender, $uiEventArgs)

        try {
        Start-Process $uiEventArgs.Uri.AbsoluteUri
        $uiEventArgs.Handled = $true

        } catch {
            [System.Windows.MessageBox]::Show(
                "Failed to open link: $($e.Uri.AbsoluteUri)`n$($_.Exception.Message)",
                "Link Error", "OK", "Error"
            ) | Out-Null
        }
    }
)

# -------------------------------------------------
# Apply program icon
# -------------------------------------------------
$IconPath = Join-Path $ScriptDir "WoWWatcher.ico"
$LegacyIconPath = Join-Path $ScriptDir "MoPWatcher.ico"
if (-not (Test-Path $IconPath) -and (Test-Path $LegacyIconPath)) { $IconPath = $LegacyIconPath }
if (Test-Path $IconPath) {
    try {
        $Window.Icon = (New-Object System.Windows.Media.Imaging.BitmapImage([Uri]$IconPath))
    } catch { }
}

# -------------------------------------------------
# Drag window via title bar
# -------------------------------------------------
$Window.Add_MouseLeftButtonDown({
    if ($_.ButtonState -eq "Pressed") {
        $Window.DragMove()
    }
})

function Assert-Control {
    param(
        [Parameter(Mandatory)]$Window,
        [Parameter(Mandatory)][string]$Name
    )
    $c = $Window.FindName($Name)
    if ($null -eq $c) { throw "Missing XAML control: $Name" }
    return $c
}

$BtnLaunchSppManager = Assert-Control -Window $Window -Name "BtnLaunchSppManager"

# -------------------------------------------------
# Get controls
# -------------------------------------------------
$BtnMinimize        = $Window.FindName("BtnMinimize")
$BtnClose           = $Window.FindName("BtnClose")

$TxtMySQL           = $Window.FindName("TxtMySQL")
$TxtMySQLExe       = $Window.FindName("TxtMySQLExe")
$BtnBrowseMySQLExe = $Window.FindName("BtnBrowseMySQLExe")

$TxtMySQLExe.Text = $Config.MySQLExe

$TxtAuth            = $Window.FindName("TxtAuth")
$TxtWorld           = $Window.FindName("TxtWorld")

$BtnBrowseMySQL     = $Window.FindName("BtnBrowseMySQL")
$BtnBrowseAuth      = $Window.FindName("BtnBrowseAuth")
$BtnBrowseWorld     = $Window.FindName("BtnBrowseWorld")

$BtnSaveConfig      = $Window.FindName("BtnSaveConfig")
$BtnStartWatchdog   = $Window.FindName("BtnStartWatchdog")
$BtnStopWatchdog    = $Window.FindName("BtnStopWatchdog")

$EllipseMySQL       = $Window.FindName("EllipseMySQL")
$EllipseAuth        = $Window.FindName("EllipseAuth")
$EllipseWorld       = $Window.FindName("EllipseWorld")

$TxtWatchdogStatus  = $Window.FindName("TxtWatchdogStatus")
$TxtLiveLog         = $Window.FindName("TxtLiveLog")

$BtnBattleShopEditor = Assert-Control $Window "BtnBattleShopEditor"

# NTFY controls
$CmbExpansion          = $Window.FindName("CmbExpansion")
$TxtExpansionCustom    = $Window.FindName("TxtExpansionCustom")

$TxtNtfyServer         = $Window.FindName("TxtNtfyServer")
$TxtNtfyTopic          = $Window.FindName("TxtNtfyTopic")
$CmbNtfyAuthMode       = $Window.FindName("CmbNtfyAuthMode")
$TxtNtfyTags           = $Window.FindName("TxtNtfyTags")
$TxtNtfyUsername       = $Window.FindName("TxtNtfyUsername")
$TxtNtfyPassword       = $Window.FindName("TxtNtfyPassword")
$TxtNtfyToken          = $Window.FindName("TxtNtfyToken")
$LblNtfyUsername       = $Window.FindName("LblNtfyUsername")
$LblNtfyPassword       = $Window.FindName("LblNtfyPassword")
$LblNtfyToken          = $Window.FindName("LblNtfyToken")

$CmbNtfyPriorityDefault= $Window.FindName("CmbNtfyPriorityDefault")

$ChkNtfyMySQL          = $Window.FindName("ChkNtfyMySQL")
$ChkNtfyAuthserver     = $Window.FindName("ChkNtfyAuthserver")
$ChkNtfyWorldserver    = $Window.FindName("ChkNtfyWorldserver")

$CmbPriMySQL           = $Window.FindName("CmbPriMySQL")
$CmbPriAuthserver      = $Window.FindName("CmbPriAuthserver")
$CmbPriWorldserver     = $Window.FindName("CmbPriWorldserver")

$ChkNtfyOnDown         = $Window.FindName("ChkNtfyOnDown")
$ChkNtfyOnUp           = $Window.FindName("ChkNtfyOnUp")
$BtnTestNtfy           = $Window.FindName("BtnTestNtfy")

$BtnStartMySQL  = $Window.FindName("BtnStartMySQL")
$BtnStopMySQL   = $Window.FindName("BtnStopMySQL")
$BtnStartAuth   = $Window.FindName("BtnStartAuth")
$BtnStopAuth    = $Window.FindName("BtnStopAuth")
$BtnStartWorld  = $Window.FindName("BtnStartWorld")
$BtnStopWorld   = $Window.FindName("BtnStopWorld")
$BtnRestartMySQL = $Window.FindName("BtnRestartMySQL")
$BtnRestartAuth  = $Window.FindName("BtnRestartAuth")
$BtnRestartWorld = $Window.FindName("BtnRestartWorld")

$BtnStartAll    = $Window.FindName("BtnStartAll")
$BtnStopAll     = $Window.FindName("BtnStopAll")
$BtnRestartStack = $Window.FindName("BtnRestartStack")

$BtnClearLog    = $Window.FindName("BtnClearLog")

# Server Info: DB controls
$TxtDbHost        = $Window.FindName("TxtDbHost")
$TxtDbPort        = $Window.FindName("TxtDbPort")
$TxtDbUser        = $Window.FindName("TxtDbUser")
$TxtDbNameChar    = $Window.FindName("TxtDbNameChar")
$TxtDbPassword    = $Window.FindName("TxtDbPassword")
$BtnSaveDbPassword= $Window.FindName("BtnSaveDbPassword")
$BtnTestDb        = $Window.FindName("BtnTestDb")

# Tools tab - DB Backup/Restore controls (MATCH XAML)
$TxtDbBackupFolder       = Assert-Control $Window "TxtDbBackupFolder"
$BtnBrowseDbBackupFolder = Assert-Control $Window "BtnBrowseDbBackupFolder"
$ChkDbBackupCompress     = Assert-Control $Window "ChkDbBackupCompress"
$TxtDbBackupRetentionDays= Assert-Control $Window "TxtDbBackupRetentionDays"
$BtnRunDbBackup          = Assert-Control $Window "BtnRunDbBackup"
$TxtDbBackupStatus       = $Window.FindName("TxtDbBackupStatus")
$PbDbBackup              = $Window.FindName("PbDbBackup")
$PbDbRestore             = Assert-Control $Window "PbDbRestore"
$TxtDbRestoreDatabases   = Assert-Control $Window "TxtDbRestoreDatabases"

# Tools tab - Repack Backup controls (MATCH XAML)
$TxtRepackRoot           = Assert-Control $Window "TxtRepackRoot"
$BtnBrowseRepackRoot     = Assert-Control $Window "BtnBrowseRepackRoot"
$TxtRepackBackupDest     = Assert-Control $Window "TxtRepackBackupDest"
$BtnBrowseRepackBackupDest = Assert-Control $Window "BtnBrowseRepackBackupDest"
$BtnOpenRepackBackupDest = Assert-Control $Window "BtnOpenRepackBackupDest"
$BtnRunFullBackup        = Assert-Control $Window "BtnRunFullBackup"
$BtnRunConfigBackup      = Assert-Control $Window "BtnRunConfigBackup"
$TxtRepackBackupStatus   = $Window.FindName("TxtRepackBackupStatus")
$PbRepackBackup          = $Window.FindName("PbRepackBackup")


$TxtDbRestoreFile        = Assert-Control $Window "TxtDbRestoreFile"
$BtnBrowseDbRestoreFile  = Assert-Control $Window "BtnBrowseDbRestoreFile"
$ChkDbRestoreConfirm     = Assert-Control $Window "ChkDbRestoreConfirm"
$BtnRunDbRestore         = Assert-Control $Window "BtnRunDbRestore"
$TxtDbRestoreStatus      = Assert-Control $Window "TxtDbRestoreStatus"

$TxtUtilMySQLCpu  = Assert-Control $Window "TxtUtilMySQLCpu"
$TxtUtilMySQLMem  = Assert-Control $Window "TxtUtilMySQLMem"
$TxtUtilAuthCpu   = Assert-Control $Window "TxtUtilAuthCpu"
$TxtUtilAuthMem   = Assert-Control $Window "TxtUtilAuthMem"
$TxtUtilWorldCpu  = Assert-Control $Window "TxtUtilWorldCpu"
$TxtUtilWorldMem  = Assert-Control $Window "TxtUtilWorldMem"
$TxtWorldUptime   = Assert-Control $Window "TxtWorldUptime"


# Configuration: Worldserver Telnet
$TxtWorldTelnetHost          = Assert-Control $Window "TxtWorldTelnetHost"
$TxtWorldTelnetPort          = Assert-Control $Window "TxtWorldTelnetPort"
$TxtWorldTelnetUser          = Assert-Control $Window "TxtWorldTelnetUser"
$TxtWorldTelnetPassword      = Assert-Control $Window "TxtWorldTelnetPassword"
$LblWorldTelnetPasswordStatus= Assert-Control $Window "LblWorldTelnetPasswordStatus"

# Tab: Worldserver Console
$BtnTelnetConnect    = Assert-Control $Window "BtnTelnetConnect"
$BtnTelnetDisconnect = Assert-Control $Window "BtnTelnetDisconnect"
$TxtTelnetTarget     = Assert-Control $Window "TxtTelnetTarget"
$LblTelnetStatus     = Assert-Control $Window "LblTelnetStatus"
$TxtTelnetOutput     = Assert-Control $Window "TxtTelnetOutput"
$TxtTelnetCommand    = Assert-Control $Window "TxtTelnetCommand"
$BtnTelnetSend       = Assert-Control $Window "BtnTelnetSend"

# Worldserver Log Tail (Console Tab)
$ChkWorldLogTail     = Assert-Control $Window "ChkWorldLogTail"
$TxtWorldLogPath     = Assert-Control $Window "TxtWorldLogPath"
$BtnBrowseWorldLog   = Assert-Control $Window "BtnBrowseWorldLog"
$BtnClearWorldLog    = Assert-Control $Window "BtnClearWorldLog"
$TxtWorldLogOutput   = Assert-Control $Window "TxtWorldLogOutput"
# -------------------------------------------------
# Worldserver log Browse binding (early + multi-event)
# -------------------------------------------------
if (-not $script:WorldLogBrowseLastTick) { $script:WorldLogBrowseLastTick = 0 }

function Invoke-WorldLogBrowseOnce {
    try {
        $now = [Environment]::TickCount
        $delta = $now - $script:WorldLogBrowseLastTick
        if ($delta -lt 400 -and $delta -gt -400) { return }
        $script:WorldLogBrowseLastTick = $now
    } catch { }

    try {
        Browse-WorldLogPath
    } catch {
        $em = $_.Exception.Message
        try { Add-GuiLog ("ERROR: World log browse failed: {0}" -f $em) } catch { }
        try { Append-WorldLogOutput ("[World log] ERROR: Browse failed: {0}`r`n" -f $em) } catch { }
    }
}

# Primary: normal Click event
try { $BtnBrowseWorldLog.Add_Click({ Invoke-WorldLogBrowseOnce }) } catch { }

# Fallbacks: preview mouse up on button and on the path box (some WPF templates swallow Click)
try {
    $BtnBrowseWorldLog.add_PreviewMouseLeftButtonUp({
        param($s,$e)
        try { Invoke-WorldLogBrowseOnce } catch { }
        try { $e.Handled = $true } catch { }
    })
} catch { }

try {
    $TxtWorldLogPath.add_PreviewMouseLeftButtonUp({
        param($s,$e)
        try { Invoke-WorldLogBrowseOnce } catch { }
        try { $e.Handled = $true } catch { }
    })
} catch { }

# Tab: Update
$TxtCurrentVersion = $Window.FindName("TxtCurrentVersion")
$TxtLatestVersion  = $Window.FindName("TxtLatestVersion")
$BtnCheckUpdates   = $Window.FindName("BtnCheckUpdates")
$BtnUpdateNow      = $Window.FindName("BtnUpdateNow")
$TxtUpdateFlowStatus = $Window.FindName("TxtUpdateFlowStatus")
$PbUpdateFlow        = $Window.FindName("PbUpdateFlow")


$BtnSppV2RepackUpdate = $Window.FindName("BtnSppV2RepackUpdate")
$TxtSppV2UpdateTarget = $Window.FindName("TxtSppV2UpdateTarget")
$TxtSppV2UpdateStatus = $Window.FindName("TxtSppV2UpdateStatus")
$PbSppV2Update        = $Window.FindName("PbSppV2Update")


$BtnLaunchSppManager = $Window.FindName("BtnLaunchSppManager")

# -------------------------------------------------
# Global WPF safety net: log unhandled UI exceptions
# -------------------------------------------------
try {
    # Ensure WPF app object exists
    if (-not [System.Windows.Application]::Current) {
        $null = New-Object System.Windows.Application
    }

    # Only attach once (avoid duplicate logs if script re-loads)
    if (-not $script:DispatcherUnhandledExceptionHooked) {
        $script:DispatcherUnhandledExceptionHooked = $true

        [System.Windows.Application]::Current.add_DispatcherUnhandledException({
            param($sender, $e)

            try {
                $ex = $e.Exception
                $msg = if ($ex) { $ex.ToString() } else { "Unknown Dispatcher exception (no Exception object)." }

                # Your log function
                Add-GuiLog "UNHANDLED UI EXCEPTION: $msg"

                # Optional: show a minimal user prompt (comment out if you prefer silent logging)
                try {
                    [System.Windows.MessageBox]::Show(
                        "An unexpected UI error occurred. Details were written to the log.",
                        "WoW Watchdog",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Error
                    ) | Out-Null
                } catch { }
            }
            catch { }

            # Prevent the app from crashing to desktop
            $e.Handled = $true
        })
    }
}
catch {
    # As a last resort, don't crash if logging setup fails
}

$TxtCurrentVersion.Text = $AppVersion.ToString()

function Get-CommonParentPath {
    param([string[]]$Paths)

    $dirs = @()

    foreach ($p in $Paths) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }

        try {
            $pp = [System.IO.Path]::GetFullPath($p)
        } catch {
            $pp = $p
        }

        # If it's a file path, use its parent directory
        try {
            if (Test-Path -LiteralPath $pp -PathType Leaf) {
                $pp = Split-Path -Parent $pp
            } elseif (Test-Path -LiteralPath $pp -PathType Container) {
                # directory as-is
            } else {
                # best-effort: if it has an extension, treat as file path
                if ([System.IO.Path]::HasExtension($pp)) {
                    $pp = Split-Path -Parent $pp
                }
            }
        } catch { }

        if (-not [string]::IsNullOrWhiteSpace($pp)) {
            $dirs += $pp
        }
    }

    if (-not $dirs -or $dirs.Count -lt 1) { return "" }

    $split = $dirs | ForEach-Object { ($_ -replace '/', '\').TrimEnd('\') -split '\\' }
    $minLen = ($split | ForEach-Object { $_.Count } | Measure-Object -Minimum).Minimum

    $common = @()
    for ($i = 0; $i -lt $minLen; $i++) {
        $seg = $split[0][$i]
        $allSame = $true
        foreach ($arr in $split) {
            if ($arr[$i] -ne $seg) { $allSame = $false; break }
        }
        if (-not $allSame) { break }
        $common += $seg
    }

    if (-not $common -or $common.Count -lt 1) { return "" }

    # Rebuild Windows path
    $root = ($common -join '\')
    if ($root -match '^[A-Za-z]:$') { $root += '\' }
    return $root
}

# Backup destinations (default: ProgramData\WoWWatchdog\backups; user-selectable and persisted)
$script:DefaultBackupDir = Join-Path $DataDir "backups"

# Repack backup destination: Config.RepackBackupFolder > default
$script:RepackBackupDir = $script:DefaultBackupDir
try {
    $rb = [string]$Config.RepackBackupFolder
    if (-not [string]::IsNullOrWhiteSpace($rb)) { $script:RepackBackupDir = $rb }
} catch { }

if (-not (Test-Path -LiteralPath $script:RepackBackupDir)) {
    New-Item -ItemType Directory -Path $script:RepackBackupDir -Force | Out-Null
}
try { $TxtRepackBackupDest.Text = $script:RepackBackupDir } catch { }

# DB backup destination: Config.DbBackupFolder > default
try {
    $dbb = [string]$Config.DbBackupFolder
    if ([string]::IsNullOrWhiteSpace($dbb)) { $dbb = $script:DefaultBackupDir }
    if ([string]::IsNullOrWhiteSpace(($TxtDbBackupFolder.Text + "").Trim())) {
        $TxtDbBackupFolder.Text = $dbb
    }
} catch {
    if ([string]::IsNullOrWhiteSpace(($TxtDbBackupFolder.Text + "").Trim())) {
        $TxtDbBackupFolder.Text = $script:DefaultBackupDir
    }
}
# Default repack root: Config.RepackRoot, else infer from configured paths
try {
    if ([string]::IsNullOrWhiteSpace(($TxtRepackRoot.Text + ""))) {
        $candidate = ""
        try { $candidate = [string]$Config.RepackRoot } catch { $candidate = "" }

        if ([string]::IsNullOrWhiteSpace($candidate)) {
            $candidate = Get-CommonParentPath -Paths @(
                [string]$Config.MySQL,
                [string]$Config.Authserver,
                [string]$Config.Worldserver
            )
        }

        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            $TxtRepackRoot.Text = $candidate
        }
    }
} catch { }



if ([string]::IsNullOrWhiteSpace($TxtDbBackupFolder.Text)) {
    $TxtDbBackupFolder.Text = (Join-Path $DataDir "backups")
}
if ([string]::IsNullOrWhiteSpace($TxtDbBackupRetentionDays.Text)) {
    $TxtDbBackupRetentionDays.Text = "14"
}
if ($ChkDbBackupCompress) { $ChkDbBackupCompress.IsChecked = $true }
if ($ChkDbRestoreConfirm) { $ChkDbRestoreConfirm.IsChecked = $false }

# ---- Hard defaults based on repack bundle ----
$DefaultMySqlDump = 'C:\wowsrv\database\bin\mysqldump.exe'
$DefaultMySqlExe  = 'C:\wowsrv\database\bin\mysql.exe'
$DefaultSchemas   = @('legion_auth','legion_characters','legion_hotfixes','legion_world')


function script:Set-DbBackupUiState {
    param(
        [bool]$IsBusy,
        [string]$StatusText = $null
    )

    if ($null -ne $StatusText) {
        $TxtDbBackupStatus.Text = $StatusText
        $TxtDbBackupStatus.Visibility = "Visible"
    }

    $PbDbBackup.Visibility = if ($IsBusy) { "Visible" } else { "Collapsed" }

    if (-not $IsBusy -and [string]::IsNullOrWhiteSpace(($TxtDbBackupStatus.Text + "").Trim())) {
        $TxtDbBackupStatus.Visibility = "Collapsed"
    }

    $BtnRunDbBackup.IsEnabled = -not $IsBusy
    $BtnRunDbRestore.IsEnabled = -not $IsBusy
    $BtnBrowseDbBackupFolder.IsEnabled = -not $IsBusy
    $BtnBrowseDbRestoreFile.IsEnabled = -not $IsBusy
    $ChkDbBackupCompress.IsEnabled = -not $IsBusy
    $TxtDbBackupRetentionDays.IsEnabled = -not $IsBusy
    $TxtDbBackupFolder.IsEnabled = -not $IsBusy
    $TxtDbRestoreFile.IsEnabled = -not $IsBusy
    $ChkDbRestoreConfirm.IsEnabled = -not $IsBusy
}

$script:UiRunspace = [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace

function Invoke-UiSafe {
    param([Parameter(Mandatory)][scriptblock]$Action)

    try {
        if ($null -ne $Window -and $null -ne $Window.Dispatcher `
            -and -not $Window.Dispatcher.HasShutdownStarted `
            -and -not $Window.Dispatcher.HasShutdownFinished) {

            $null = $Window.Dispatcher.BeginInvoke([System.Action]{
                try { & $Action } catch { }
            })
        } else {
            try { & $Action } catch { }
        }
    } catch { }
}




function Get-DbConfig {
    # Host/port/user come from config schema used elsewhere
    $dbHost = [string]$Config.DbHost
    if ([string]::IsNullOrWhiteSpace($dbHost)) { $dbHost = "127.0.0.1" }

    $port = 3306
    try { $port = [int]$Config.DbPort } catch { $port = 3306 }
    if ($port -lt 1 -or $port -gt 65535) { $port = 3306 }

    $user = [string]$Config.DbUser
    if ([string]::IsNullOrWhiteSpace($user)) { $user = "root" }

    # mysql.exe comes from Config.MySQLExe (already used by player count)
    $mysqlExe = [string]$Config.MySQLExe
    if ([string]::IsNullOrWhiteSpace($mysqlExe)) { $mysqlExe = $DefaultMySqlExe }

    # Derive mysqldump.exe from mysql.exe folder if possible
    $mysqldumpExe = $DefaultMySqlDump
    try {
        if ($mysqlExe -and (Test-Path -LiteralPath $mysqlExe)) {
            $candidate = Join-Path (Split-Path -Parent $mysqlExe) "mysqldump.exe"
            if (Test-Path -LiteralPath $candidate) { $mysqldumpExe = $candidate }
        }
    } catch { }

    # Password from DPAPI secrets store (key is derived from Host/Port/User via Get-DbSecretKey)
    $pwdPlain  = Get-DbSecretPassword

    $pwdSecure = $null
    if (-not [string]::IsNullOrWhiteSpace($pwdPlain)) {
        $pwdSecure = ConvertTo-SecureString -String $pwdPlain -AsPlainText -Force
    }

    return [pscustomobject]@{
        DbHost         = $dbHost
        Port           = $port
        User           = $user
        PasswordSecure = $pwdSecure
        MySqlExe       = $mysqlExe
        MySqlDump      = $mysqldumpExe
    }
}

$BtnBattleShopEditor.Add_Click({
    try {
        # Match your existing "tools install base" approach
        # Example only; replace with your current base tools path variable/pattern:
        $toolRoot = $script:ToolsDir

        $exe = Ensure-UrlZipToolInstalled `
            -ZipUrl "https://cdn.discordapp.com/attachments/576868080165322752/1399580989738586263/BattleShopEditor-v1008.zip?ex=6961121e&is=695fc09e&hm=09ad969d9045ae0db36e6afbe4bb62b11e70efb09fc5fba5e04ddd0a49dd007b&" `
            -InstallDir $toolRoot `
            -ExeRelativePath "BattleShopEditor\BattleShopEditor.exe" `
            -ToolName "BattleShopEditor" `
            -TempZipFileName "BattleShopEditor-v1008.zip"

        Start-Process -FilePath $exe -WorkingDirectory (Split-Path -Parent $exe) | Out-Null
    } catch {
        try {
            Add-GuiLog "BattleShopEditor: $($_.Exception.Message)"
        } catch { }

        try {
            [System.Windows.MessageBox]::Show($_.Exception.Message, "BattleShopEditor", "OK", "Error") | Out-Null
        } catch {}
    }
})


function Persist-ConfigFile {
    try {
        $Config | ConvertTo-Json -Depth 6 | Set-Content -Path $ConfigPath -Encoding UTF8
    } catch {
        try { Add-GuiLog "WARN: Failed to persist config: $($_.Exception.Message)" } catch { }
    }
}

function Persist-BackupFolderSettings {
    try {
        $db = ($TxtDbBackupFolder.Text + "").Trim()
        $rp = ($TxtRepackBackupDest.Text + "").Trim()

        if ([string]::IsNullOrWhiteSpace($db)) { $db = $script:DefaultBackupDir }
        if ([string]::IsNullOrWhiteSpace($rp)) { $rp = $script:DefaultBackupDir }

        $Config.DbBackupFolder = $db
        $Config.RepackBackupFolder = $rp

        Persist-ConfigFile
    } catch {
        try { Add-GuiLog "WARN: Failed to persist backup folder settings: $($_.Exception.Message)" } catch { }
    }
}

# -------- Browse: Backup folder --------
$BtnBrowseDbBackupFolder.Add_Click({
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue | Out-Null

        $current = ($TxtDbBackupFolder.Text + "").Trim()

        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = "Select a folder for DB backups (UNC paths supported, e.g. \\server\share\folder)"
        $dlg.ShowNewFolderButton = $true

        # Prefer selecting an existing local path; UNC selection may be flaky in elevated context.
        if (-not [string]::IsNullOrWhiteSpace($current) -and (Test-Path -LiteralPath $current -ErrorAction SilentlyContinue)) {
            $dlg.SelectedPath = $current
        }

        if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $TxtDbBackupFolder.Text = $dlg.SelectedPath
            Persist-BackupFolderSettings
            return
        }

        # User cancelled folder picker: offer UNC entry fallback
        $unc = Read-UncPathFromUser -DefaultValue $current
        if ($unc) {
            $TxtDbBackupFolder.Text = $unc
            Persist-BackupFolderSettings
            Add-GuiLog "DB backup folder set to UNC path: $unc"
        }

    } catch {
        Add-GuiLog "Backup folder browse failed: $($_.Exception.Message)"
    }
})

# -------- Browse: Repack root folder --------
# Persist backup folder changes even if the user does not click "Save Configuration"
try {
    $TxtDbBackupFolder.Add_LostFocus({
        try { Persist-BackupFolderSettings } catch { }
    })
} catch { }

# -------- Browse: Repack backup destination --------
$BtnBrowseRepackBackupDest.Add_Click({
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue | Out-Null
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = "Select a folder for Repack backups"

        $cur = ($TxtRepackBackupDest.Text + "").Trim()
        if (-not [string]::IsNullOrWhiteSpace($cur) -and (Test-Path -LiteralPath $cur)) {
            $dlg.SelectedPath = $cur
        }

        if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $TxtRepackBackupDest.Text = $dlg.SelectedPath
            $script:RepackBackupDir = $dlg.SelectedPath
            Persist-BackupFolderSettings
        }
    } catch {
        Add-GuiLog "Repack backup destination browse failed: $($_.Exception.Message)"
    }
})

try {
    $TxtRepackBackupDest.Add_LostFocus({
        try {
            $script:RepackBackupDir = ($TxtRepackBackupDest.Text + "").Trim()
            Persist-BackupFolderSettings
        } catch { }
    })
} catch { }


$BtnBrowseRepackRoot.Add_Click({
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue | Out-Null
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = "Select the root folder to back up (entire repack)"
        $cur = ($TxtRepackRoot.Text + "").Trim()
        if (-not [string]::IsNullOrWhiteSpace($cur) -and (Test-Path -LiteralPath $cur)) { $dlg.SelectedPath = $cur }

        if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $TxtRepackRoot.Text = $dlg.SelectedPath
        }
    } catch {
        Add-GuiLog "Repack folder browse failed: $($_.Exception.Message)"
    }
})

# -------- Open: Repack backup destination --------
$BtnOpenRepackBackupDest.Add_Click({
    try {
        $p = ($TxtRepackBackupDest.Text + "").Trim()
        if ([string]::IsNullOrWhiteSpace($p)) { $p = $script:RepackBackupDir }
        if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }

        Start-Process -FilePath "explorer.exe" -ArgumentList @($p) | Out-Null
    } catch {
        Add-GuiLog "Open backup destination failed: $($_.Exception.Message)"
    }
})

# -------- Browse: Restore file --------
$BtnBrowseDbRestoreFile.Add_Click({
    try {
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Filter = "SQL or ZIP (*.sql;*.zip)|*.sql;*.zip|SQL files (*.sql)|*.sql|ZIP files (*.zip)|*.zip|All files (*.*)|*.*"
        $dlg.Title  = "Select a .sql file to restore"
        if ($dlg.ShowDialog() -eq $true) {
            $TxtDbRestoreFile.Text = $dlg.FileName
        }
    } catch {
        Add-GuiLog "Restore file browse failed: $($_.Exception.Message)"
    }
})

# -------------------------------------------------
# DB Backup UI state helper (must be in global scope)
# -------------------------------------------------
function Set-DbBackupUiState {
    param(
        [Parameter(Mandatory)][bool]$IsBusy,
        [string]$StatusText = $null
    )

    try {
        if ($null -ne $StatusText) {
            $TxtDbBackupStatus.Text = $StatusText
            $TxtDbBackupStatus.Visibility = "Visible"
        }

        $PbDbBackup.Visibility = if ($IsBusy) { "Visible" } else { "Collapsed" }

        if (-not $IsBusy -and [string]::IsNullOrWhiteSpace(($TxtDbBackupStatus.Text + "").Trim())) {
            $TxtDbBackupStatus.Visibility = "Collapsed"
        }

        # Disable controls that could conflict while running
        $BtnRunDbBackup.IsEnabled           = -not $IsBusy
        $BtnRunDbRestore.IsEnabled          = -not $IsBusy
        $BtnBrowseDbBackupFolder.IsEnabled  = -not $IsBusy
        $BtnBrowseDbRestoreFile.IsEnabled   = -not $IsBusy
        $ChkDbBackupCompress.IsEnabled      = -not $IsBusy
        $TxtDbBackupRetentionDays.IsEnabled = -not $IsBusy
        $TxtDbBackupFolder.IsEnabled        = -not $IsBusy
        $TxtDbRestoreFile.IsEnabled         = -not $IsBusy
        $ChkDbRestoreConfirm.IsEnabled      = -not $IsBusy
    }
    catch {
        # Never let UI toggling kill the app
        try { Add-GuiLog "Backup UI state update failed: $($_.Exception.Message)" } catch { }
    }
}

function Restore-DatabaseMulti {
    param(
        [Parameter(Mandatory)][string]$MySqlPath,
        [Parameter(Mandatory)][string]$DbHost,
        [Parameter(Mandatory)][int]$Port,
        [Parameter(Mandatory)][string]$User,

        [Parameter()][pscredential]$Credential,

        [Parameter(Mandatory)][string]$InputFile,  # .sql OR .zip
        [switch]$CreateIfMissing,
        [switch]$Force,
        [string]$ExtraArgs = ""
    )

    if (-not (Test-Path -LiteralPath $MySqlPath)) { throw "mysql.exe not found: $MySqlPath" }
    if (-not (Test-Path -LiteralPath $InputFile)) { throw "Restore file not found: $InputFile" }

    $allowed = @("legion_auth","legion_characters","legion_hotfixes","legion_world")

    # MySQL identifier quoting uses backticks. In PowerShell, build them safely:
    $bt = [char]96
    function Quote-MySqlIdent([string]$name) { return ($bt + $name + $bt) }

    # Helper: start mysql.exe with MYSQL_PWD if available
    function Start-MySqlProcess([string]$arguments) {
        $psiX = New-Object System.Diagnostics.ProcessStartInfo
        $psiX.FileName = $MySqlPath
        $psiX.Arguments = $arguments
        $psiX.UseShellExecute = $false
        $psiX.RedirectStandardOutput = $true
        $psiX.RedirectStandardError  = $true
        $psiX.CreateNoWindow = $true

        $pwdPtrLocal = [IntPtr]::Zero
        try {
            if ($Credential -and $Credential.Password) {
                $pwdPtrLocal = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
                $plainPwdLocal = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pwdPtrLocal)
                if (-not [string]::IsNullOrWhiteSpace($plainPwdLocal)) {
                    $psiX.EnvironmentVariables["MYSQL_PWD"] = $plainPwdLocal
                }
            }

            $p = [Diagnostics.Process]::Start($psiX)
            return @{ Proc = $p; Ptr = $pwdPtrLocal }
        }
        catch {
            if ($pwdPtrLocal -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pwdPtrLocal) }
            throw
        }
    }

    # ---- Resolve SQL path (supports .zip containing one .sql) ----
    $sqlPath = $null
    $tempDir = $null

    try {
        $ext = ([IO.Path]::GetExtension($InputFile)).ToLowerInvariant()
        if ($ext -eq ".zip") {
            $tempDir = Join-Path $env:TEMP ("WoWWatcherRestore_" + ([Guid]::NewGuid().ToString("N")))
            New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

            Expand-Archive -LiteralPath $InputFile -DestinationPath $tempDir -Force

            $sqls = Get-ChildItem -Path $tempDir -Recurse -File -Filter *.sql -ErrorAction SilentlyContinue
            if (-not $sqls -or $sqls.Count -lt 1) { throw "ZIP does not contain a .sql file." }
            if ($sqls.Count -gt 1) { throw "ZIP contains multiple .sql files; please use a ZIP with exactly one SQL." }

            $sqlPath = $sqls[0].FullName
        }
        else {
            $sqlPath = $InputFile
        }

        if (-not (Test-Path -LiteralPath $sqlPath)) { throw "SQL file not found: $sqlPath" }

        # ---- Detect which DBs are in the dump (HEAD ONLY; no 900MB RAM load) ----
        $headBytes = 8MB
        $enc = [System.Text.Encoding]::UTF8

        $rawHead = $null
        $fsHead = [System.IO.File]::Open($sqlPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $buf = New-Object byte[] $headBytes
            $read = $fsHead.Read($buf, 0, $buf.Length)
            if ($read -lt 1) { throw "SQL file is empty." }
            $rawHead = $enc.GetString($buf, 0, $read)
        }
        finally {
            $fsHead.Dispose()
        }

        $dbsSet = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)

        foreach ($m in [regex]::Matches($rawHead, '(?im)^\s*USE\s+`?([a-z0-9_]+)`?\s*;', 'IgnoreCase,Multiline')) {
            [void]$dbsSet.Add($m.Groups[1].Value)
        }
        foreach ($m in [regex]::Matches($rawHead, '(?im)^\s*CREATE\s+DATABASE(?:\s+IF\s+NOT\s+EXISTS)?\s+`?([a-z0-9_]+)`?', 'IgnoreCase,Multiline')) {
            [void]$dbsSet.Add($m.Groups[1].Value)
        }

        $dbList = @($dbsSet | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
        if ($dbList.Count -lt 1) {
            throw "Could not detect databases in SQL file header (no USE/CREATE DATABASE found early in file)."
        }

        $disallowed = @($dbList | Where-Object { $allowed -notcontains $_ })
        if ($disallowed.Count -gt 0) {
            throw ("Restore file contains unsupported database name(s): {0}. Allowed: {1}" -f ($disallowed -join ", "), ($allowed -join ", "))
        }

        # ---- Pre-create or force-recreate each DB ----
        foreach ($d in $dbList) {
            $q = Quote-MySqlIdent $d

            if ($CreateIfMissing) {
                $createQuery = "CREATE DATABASE IF NOT EXISTS $q CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
                $cmdArgs = "--host=$DbHost --port=$Port --user=$User --batch --skip-column-names -e `"$createQuery`""

                $r = Start-MySqlProcess $cmdArgs
                try {
                    $errC = $r.Proc.StandardError.ReadToEnd()
                    $r.Proc.WaitForExit()
                    if ($r.Proc.ExitCode -ne 0) { throw "Failed to ensure DB exists ($d): $errC" }
                } finally {
                    if ($r.Ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($r.Ptr) }
                }
            }

            if ($Force) {
                $dropQuery = "DROP DATABASE IF EXISTS $q; CREATE DATABASE $q CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
                $cmdArgs = "--host=$DbHost --port=$Port --user=$User --batch --skip-column-names -e `"$dropQuery`""

                $r = Start-MySqlProcess $cmdArgs
                try {
                    $errD = $r.Proc.StandardError.ReadToEnd()
                    $r.Proc.WaitForExit()
                    if ($r.Proc.ExitCode -ne 0) { throw "Failed to drop/recreate DB ($d): $errD" }
                } finally {
                    if ($r.Ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($r.Ptr) }
                }
            }
        }

        # ---- Import entire SQL into mysql (NO --database, let USE statements drive) ----
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $MySqlPath

        $restoreArgs = @("--host=$DbHost","--port=$Port","--user=$User")
        if ($ExtraArgs) { $restoreArgs += ($ExtraArgs -split "\s+" | Where-Object { $_ }) }

        $psi.Arguments = ($restoreArgs -join " ")
        $psi.UseShellExecute = $false
        $psi.RedirectStandardInput  = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.CreateNoWindow = $true

        $pwdPtr = [IntPtr]::Zero
        try {
            if ($Credential -and $Credential.Password) {
                $pwdPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
                $plainPwd = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pwdPtr)
                if (-not [string]::IsNullOrWhiteSpace($plainPwd)) {
                    $psi.EnvironmentVariables["MYSQL_PWD"] = $plainPwd
                }
            }

            $proc = New-Object System.Diagnostics.Process
            $proc.StartInfo = $psi
            if (-not $proc.Start()) { throw "Failed to start mysql.exe for restore." }

            # Stream the SQL file to mysql stdin (no giant in-memory string)
            $src = [System.IO.File]::Open($sqlPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try {
                $dst = $proc.StandardInput.BaseStream
                $buffer = New-Object byte[] (1024 * 1024) # 1MB
                while (($n = $src.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $dst.Write($buffer, 0, $n)
                }
                $dst.Flush()
            }
            finally {
                try { $src.Dispose() } catch { }
                try { $proc.StandardInput.Close() } catch { }
            }

            $stderr = $proc.StandardError.ReadToEnd()
            $proc.WaitForExit()

            if ($proc.ExitCode -ne 0) {
                throw ("mysql restore failed (exit {0}): {1}" -f $proc.ExitCode, ($stderr.Trim()))
            }

            return [pscustomobject]@{
                Ok     = $true
                DbList = $dbList
                SqlPath= $sqlPath
            }
        }
        finally {
            if ($pwdPtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pwdPtr) }
            Remove-Variable plainPwd -ErrorAction SilentlyContinue
        }
    }
    finally {
        if ($tempDir -and (Test-Path -LiteralPath $tempDir)) {
            try { Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue } catch { }
        }
    }
}

# -------------------------------------------------
# DB Restore UI state helper (global scope)
# -------------------------------------------------

function Set-DbRestoreUiState {
    param(
        [Parameter(Mandatory)][bool]$IsBusy,
        [string]$StatusText = $null
    )

    try {
        if ($null -ne $StatusText) {
            $TxtDbRestoreStatus.Text = $StatusText
            $TxtDbRestoreStatus.Visibility = "Visible"
        }

        # Must be a value, not a scriptblock
        $PbDbRestore.Visibility = $(if ($IsBusy) { "Visible" } else { "Collapsed" })

        if (-not $IsBusy) {
            $t = ($TxtDbRestoreStatus.Text + "").Trim()
            if ([string]::IsNullOrWhiteSpace($t)) {
                $TxtDbRestoreStatus.Visibility = "Collapsed"
            }
        }

        # Restore controls
        $BtnRunDbRestore.IsEnabled        = -not $IsBusy
        $BtnBrowseDbRestoreFile.IsEnabled = -not $IsBusy
        $TxtDbRestoreFile.IsEnabled       = -not $IsBusy
        $ChkDbRestoreConfirm.IsEnabled    = -not $IsBusy

        # Optional: lock backup during restore
        $BtnRunDbBackup.IsEnabled           = -not $IsBusy
        $BtnBrowseDbBackupFolder.IsEnabled  = -not $IsBusy
        $TxtDbBackupFolder.IsEnabled        = -not $IsBusy
        $ChkDbBackupCompress.IsEnabled      = -not $IsBusy
        $TxtDbBackupRetentionDays.IsEnabled = -not $IsBusy
    }
    catch {
        try { Add-GuiLog "Restore UI state update failed: $($_.Exception.Message)" } catch { }
    }
}

function Set-RepackBackupUiState {
    param(
        [Parameter(Mandatory)][bool]$IsBusy,
        [string]$StatusText = $null
    )

    try {
        if ($TxtRepackBackupStatus) {
            if ($null -ne $StatusText) {
                $TxtRepackBackupStatus.Text = $StatusText
                $TxtRepackBackupStatus.Visibility = "Visible"
            }
        }

        if ($PbRepackBackup) {
            $PbRepackBackup.Visibility = $(if ($IsBusy) { "Visible" } else { "Collapsed" })
        }

        if (-not $IsBusy -and $TxtRepackBackupStatus) {
            $t = ($TxtRepackBackupStatus.Text + "").Trim()
            if ([string]::IsNullOrWhiteSpace($t)) {
                $TxtRepackBackupStatus.Visibility = "Collapsed"
            }
        }

        $BtnRunFullBackup.IsEnabled    = -not $IsBusy
        $BtnRunConfigBackup.IsEnabled  = -not $IsBusy
        $BtnBrowseRepackRoot.IsEnabled = -not $IsBusy
        $BtnBrowseRepackBackupDest.IsEnabled = -not $IsBusy
        $BtnOpenRepackBackupDest.IsEnabled = -not $IsBusy
        $TxtRepackRoot.IsEnabled       = -not $IsBusy
        $TxtRepackBackupDest.IsEnabled = -not $IsBusy
    } catch { }
}



# -------- Run Backup (PS 5.1 safe async runspace + UI progress; AsyncCallback) --------
$BtnRunDbBackup.Add_Click({
    try {
        Set-DbBackupUiState -IsBusy $true -StatusText "Starting backup… please wait."
        Add-GuiLog "Backup: Initializing…"

        # Capture inputs on UI thread
        $db = Get-DbConfig

        $outFolder = ($TxtDbBackupFolder.Text + "").Trim()
        if ([string]::IsNullOrWhiteSpace($outFolder)) { throw "Backup folder is empty." }

        $retentionDays = 0
        [void][int]::TryParse(($TxtDbBackupRetentionDays.Text + ""), [ref]$retentionDays)

        $doZip = [bool]$ChkDbBackupCompress.IsChecked

        $candidateSchemas = @(
            $DefaultSchemas |
            Where-Object { $_ -and $_.ToString().Trim() } |
            ForEach-Object { $_.ToString().Trim() }
        )

        if (-not (Test-Path -LiteralPath $outFolder)) {
            New-Item -ItemType Directory -Path $outFolder -Force | Out-Null
        }

        if (-not (Test-Path -LiteralPath $db.MySqlDump)) { throw "mysqldump.exe not found at: $($db.MySqlDump)" }
        if (-not (Test-Path -LiteralPath $db.MySqlExe))  { throw "mysql.exe not found at: $($db.MySqlExe) (needed for access probing)" }

        # Build PSCredential only if password present
        $cred = $null
        if ($db.PasswordSecure -and $db.PasswordSecure.Length -gt 0) {
            $cred = [pscredential]::new($db.User, $db.PasswordSecure)
        }

        # UI status immediately
        $TxtDbBackupStatus.Text = "Backup running…"
        $TxtDbBackupStatus.Visibility = "Visible"

        $disp = $Window.Dispatcher

        # ---- Dedicated background runspace ----
        $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
        $rs.ApartmentState = 'MTA'
        $rs.ThreadOptions  = 'ReuseThread'
        $rs.Open()

        $ps = [System.Management.Automation.PowerShell]::Create()
        $ps.Runspace = $rs

        # Script executed in background runspace (NO UI objects referenced here)
        $script = {
            param($state)

            function Convert-SecureStringToPlain([Security.SecureString]$sec) {
                if ($null -eq $sec -or $sec.Length -eq 0) { return $null }
                $bstr = [IntPtr]::Zero
                try {
                    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
                    return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                }
                finally {
                    if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
                }
            }

            function Test-DbAccess {
                param(
                    [Parameter(Mandatory)][string]$MySqlExePath,
                    [Parameter(Mandatory)][string]$DbHost,
                    [Parameter(Mandatory)][int]$Port,
                    [Parameter(Mandatory)][string]$User,
                    [Parameter()][string]$PlainPwd,
                    [Parameter(Mandatory)][string]$DatabaseName
                )

                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = $MySqlExePath
                $psi.Arguments = "--host=$DbHost --port=$Port --user=$User --database=$DatabaseName --batch --skip-column-names -e `"SELECT 1;`""
                $psi.UseShellExecute = $false
                $psi.RedirectStandardOutput = $true
                $psi.RedirectStandardError  = $true
                $psi.CreateNoWindow = $true

                if (-not [string]::IsNullOrWhiteSpace($PlainPwd)) {
                    $psi.EnvironmentVariables["MYSQL_PWD"] = $PlainPwd
                }

                $p = [Diagnostics.Process]::Start($psi)
                $null = $p.StandardOutput.ReadToEnd()
                $err  = $p.StandardError.ReadToEnd()
                $p.WaitForExit()

                if ($p.ExitCode -eq 0) { return @{ Ok = $true; Err = $null } }
                return @{ Ok = $false; Err = ($err.Trim()) }
            }

            function Backup-DatabaseInline {
                param(
                    [Parameter(Mandatory)][string]$MySqlDumpPath,
                    [Parameter(Mandatory)][string]$DbHost,
                    [Parameter(Mandatory)][int]$Port,
                    [Parameter(Mandatory)][string]$User,
                    [Parameter()][string]$PlainPwd,
                    [Parameter(Mandatory)][string[]]$Databases,
                    [Parameter(Mandatory)][string]$OutputFolder,
                    [string]$FilePrefix = "Backup",
                    [switch]$Compress,
                    [int]$RetentionDays = 0,
                    [string]$ExtraArgs = ""
                )

                if (-not (Test-Path -LiteralPath $MySqlDumpPath)) { throw "mysqldump.exe not found: $MySqlDumpPath" }
                if (-not (Test-Path -LiteralPath $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
                if (-not $Databases -or $Databases.Count -lt 1) { throw "No databases specified for backup." }

                $ts = Get-Date -Format "yyyyMMdd-HHmmss"
                $dbList = ($Databases | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join "_"
                $baseName = "{0}_{1}_{2}" -f $FilePrefix, $dbList, $ts
                $sqlPath = Join-Path $OutputFolder ($baseName + ".sql")

                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = $MySqlDumpPath

                $backupArgs = @("--host=$DbHost","--port=$Port","--user=$User")
                if ($ExtraArgs) { $backupArgs += ($ExtraArgs -split "\s+" | Where-Object { $_ }) }

                $backupArgs += "--databases"
                $backupArgs += $Databases

                $psi.Arguments = ($backupArgs -join " ")
                $psi.UseShellExecute = $false
                $psi.RedirectStandardOutput = $true
                $psi.RedirectStandardError  = $true
                $psi.CreateNoWindow = $true

                if (-not [string]::IsNullOrWhiteSpace($PlainPwd)) {
                    $psi.EnvironmentVariables["MYSQL_PWD"] = $PlainPwd
                }

                $proc = New-Object System.Diagnostics.Process
                $proc.StartInfo = $psi
                if (-not $proc.Start()) { throw "Failed to start mysqldump.exe" }

                $fs = [System.IO.File]::Open($sqlPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
                try {
                    $sw = New-Object System.IO.StreamWriter($fs, [System.Text.Encoding]::UTF8)
                    try { $sw.Write($proc.StandardOutput.ReadToEnd()) }
                    finally { $sw.Flush(); $sw.Dispose() }
                } finally { $fs.Dispose() }

                $stderr = $proc.StandardError.ReadToEnd()
                $proc.WaitForExit()

                if ($proc.ExitCode -ne 0) {
                    throw ("mysqldump failed (exit {0}): {1}" -f $proc.ExitCode, ($stderr.Trim()))
                }

                $finalPath = $sqlPath
                if ($Compress) {
                    $zipPath = Join-Path $OutputFolder ($baseName + ".zip")
                    if (Test-Path -LiteralPath $zipPath) { Remove-Item $zipPath -Force -ErrorAction SilentlyContinue }
                    Compress-Archive -Path $sqlPath -DestinationPath $zipPath -Force
                    Remove-Item $sqlPath -Force -ErrorAction SilentlyContinue
                    $finalPath = $zipPath
                }

                if ($RetentionDays -gt 0) {
                    $cutoff = (Get-Date).AddDays(-$RetentionDays)
                    Get-ChildItem -Path $OutputFolder -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.LastWriteTime -lt $cutoff -and ($_.Extension -in ".sql",".zip") } |
                        ForEach-Object { try { Remove-Item $_.FullName -Force -ErrorAction Stop } catch { } }
                }

                return $finalPath
            }

            try {
                $plainPwd = $null
                if ($state.Cred -and $state.Cred.Password) {
                    $plainPwd = Convert-SecureStringToPlain $state.Cred.Password
                }

                $skipped = @()
                $accessible = New-Object System.Collections.Generic.List[string]

                foreach ($schema in $state.CandidateSchemas) {
                    $r = Test-DbAccess -MySqlExePath $state.Db.MySqlExe -DbHost $state.Db.DbHost -Port $state.Db.Port -User $state.Db.User -PlainPwd $plainPwd -DatabaseName $schema
                    if ($r.Ok) { $accessible.Add($schema) }
                    else {
                        $msg = $r.Err
                        if ([string]::IsNullOrWhiteSpace($msg)) { $msg = "Not accessible." }
                        $skipped += "Skipping '$schema' (not accessible). $msg"
                    }
                }

                if ($accessible.Count -lt 1) { throw "No accessible databases found. Nothing to back up." }

                $final = Backup-DatabaseInline `
                    -MySqlDumpPath $state.Db.MySqlDump `
                    -DbHost $state.Db.DbHost `
                    -Port $state.Db.Port `
                    -User $state.Db.User `
                    -PlainPwd $plainPwd `
                    -Databases $accessible.ToArray() `
                    -OutputFolder $state.OutFolder `
                    -FilePrefix "Legion" `
                    -Compress:($state.DoZip) `
                    -RetentionDays $state.RetentionDays `
                    -ExtraArgs "--single-transaction --routines --events --triggers --quick --default-character-set=utf8mb4"

                [pscustomobject]@{
                    Ok         = $true
                    FinalPath  = $final
                    Accessible = $accessible.ToArray()
                    Skipped    = $skipped
                }
            }
            catch {
                [pscustomobject]@{ Ok = $false; Error = $_.Exception.Message }
            }
        }

        $state = @{
            Db               = $db
            Cred             = $cred
            OutFolder        = $outFolder
            RetentionDays    = $retentionDays
            DoZip            = $doZip
            CandidateSchemas = $candidateSchemas
        }

        $null = $ps.AddScript($script).AddArgument($state)

# Start async pipeline
$async = $ps.BeginInvoke()

# Store a job bag in script-scope so the timer always has the right references
$script:DbBackupJob = [pscustomobject]@{
    PS        = $ps
    RS        = $rs
    Async     = $async
    Dispatcher= $disp
}

# Ensure we don't accumulate old timers/handlers
try {
    if ($script:DbBackupTimer) {
        $script:DbBackupTimer.Stop()
        $script:DbBackupTimer = $null
    }
} catch { }

$script:DbBackupTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:DbBackupTimer.Interval = [TimeSpan]::FromMilliseconds(250)

$script:DbBackupTimer.Add_Tick({
    # Always guard timer tick; never let exceptions bubble
    try {
        $job = $script:DbBackupJob
        if (-not $job) { return }

        # IMPORTANT: Use the wait handle, not IsCompleted (more reliable in PS 5.1)
        if (-not $job.Async.AsyncWaitHandle.WaitOne(0)) { return }

        # Stop timer immediately to prevent re-entrancy
        try { $script:DbBackupTimer.Stop() } catch { }

        $result = $null
        try {
            $result = $job.PS.EndInvoke($job.Async) | Select-Object -First 1
        }
        catch {
            $endErr = $_.Exception.Message
            try {
                Add-GuiLog "DB backup failed (EndInvoke): $endErr"
                try { $TxtDbBackupStatus.Text = "Backup failed." } catch { }
            } finally {
                try { Set-DbBackupUiState -IsBusy $false -StatusText "Backup failed." } catch { }
            }

            # Cleanup
            try { $job.PS.Dispose() } catch { }
            try { $job.RS.Close() } catch { }
            try { $job.RS.Dispose() } catch { }
            $script:DbBackupJob = $null
            return
        }

        # Process results on UI thread (we are already on UI thread via DispatcherTimer)
        try {
            if ($result -and $result.Ok) {
                foreach ($line in ($result.Skipped | Where-Object { $_ })) {
                    Add-GuiLog "Backup: $line"
                }
                Add-GuiLog ("Backup: Completed. Output: {0}" -f $result.FinalPath)
                $TxtDbBackupStatus.Text = "Backup completed."
            }
            else {
                $err = if ($result) { $result.Error } else { "Unknown error." }
                Add-GuiLog "DB backup failed: $err"
                $TxtDbBackupStatus.Text = "Backup failed."
            }
        }
        finally {
            # Always unlock UI
            try { Set-DbBackupUiState -IsBusy $false -StatusText ($TxtDbBackupStatus.Text + "") } catch { }

            # Cleanup runspace/PowerShell
            try { $job.PS.Dispose() } catch { }
            try { $job.RS.Close() } catch { }
            try { $job.RS.Dispose() } catch { }

            $script:DbBackupJob = $null
        }
    }
    catch {
        # Last-chance guard: never let timer tick exceptions bubble
        try { Add-GuiLog "DB backup failed (timer outer): $($_.Exception.Message)" } catch { }
        try { Set-DbBackupUiState -IsBusy $false -StatusText "Backup failed." } catch { }

        # Best-effort cleanup
        try {
            $job = $script:DbBackupJob
            if ($job) {
                try { $job.PS.Dispose() } catch { }
                try { $job.RS.Close() } catch { }
                try { $job.RS.Dispose() } catch { }
            }
        } catch { }
        $script:DbBackupJob = $null

        try { $script:DbBackupTimer.Stop() } catch { }
    }
})

$script:DbBackupTimer.Start()

    }
    catch {
        Add-GuiLog "DB backup failed: $($_.Exception.Message)"
        try { Set-DbBackupUiState -IsBusy $false -StatusText "Backup failed." } catch { }
    }
})

# -------- Run Restore (PS 5.1 safe async runspace + UI progress) --------
$BtnRunDbRestore.Add_Click({
    try {
        # Lock UI + show progress immediately
        Set-DbRestoreUiState -IsBusy $true -StatusText "Starting restore… please wait."
        Add-GuiLog "Restore: Initializing…"

        # Force WPF to render the above changes before we do anything else
        try {
            $null = $Window.Dispatcher.Invoke([System.Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
        } catch { }

        $db = Get-DbConfig

        $inputFile = ($TxtDbRestoreFile.Text + "").Trim()
        if ([string]::IsNullOrWhiteSpace($inputFile) -or -not (Test-Path -LiteralPath $inputFile)) {
            Add-GuiLog "Restore: Please select a valid .sql or .zip file."
            Set-DbRestoreUiState -IsBusy $false -StatusText "Restore cancelled."
            return
        }

        if (-not $ChkDbRestoreConfirm.IsChecked) {
            Add-GuiLog "Restore: Confirmation checkbox is not checked. Restore cancelled."
            Set-DbRestoreUiState -IsBusy $false -StatusText "Restore cancelled."
            return
        }

        if (-not (Test-Path -LiteralPath $db.MySqlExe)) {
            Add-GuiLog "Restore: mysql.exe not found at: $($db.MySqlExe)"
            Set-DbRestoreUiState -IsBusy $false -StatusText "Restore failed."
            return
        }

        $cred = $null
        if ($db.PasswordSecure -and $db.PasswordSecure.Length -gt 0) {
            $cred = [pscredential]::new($db.User, $db.PasswordSecure)
        }

        # ---- Dedicated background runspace ----
        $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
        $rs.ApartmentState = 'MTA'
        $rs.ThreadOptions  = 'ReuseThread'
        $rs.Open()

        $ps = [System.Management.Automation.PowerShell]::Create()
        $ps.Runspace = $rs

        # IMPORTANT: the runspace does NOT automatically know your functions
        $fnRestore = ${function:Restore-DatabaseMulti}.Ast.Extent.Text
        $null = $ps.AddScript($fnRestore)

        $worker = {
            param($state)

            try {
                $r = Restore-DatabaseMulti `
                    -MySqlPath $state.MySqlPath `
                    -DbHost $state.DbHost `
                    -Port $state.Port `
                    -User $state.User `
                    -Credential $state.Cred `
                    -InputFile $state.InputFile `
                    -CreateIfMissing:($state.CreateIfMissing) `
                    -Force:($state.Force) `
                    -ExtraArgs $state.ExtraArgs

                # If Restore-DatabaseMulti returns only $true, DbList will be null (that's OK)
                $dbList = $null
                if ($r -is [pscustomobject] -and $r.PSObject.Properties.Match("DbList").Count -gt 0) {
                    $dbList = @($r.DbList | ForEach-Object { "$_" })
                }

                [pscustomobject]@{ Ok=$true; DbList=$dbList }
            }
            catch {
                [pscustomobject]@{ Ok=$false; Error=$_.Exception.Message }
            }
        }

        $state = @{
            MySqlPath       = $db.MySqlExe
            DbHost          = $db.DbHost
            Port            = $db.Port
            User            = $db.User
            Cred            = $cred
            InputFile       = $inputFile
            CreateIfMissing = $true
            Force           = $true
            ExtraArgs       = "--default-character-set=utf8mb4"
        }

        $null  = $ps.AddScript($worker).AddArgument($state)
        $async = $ps.BeginInvoke()

        # Store job for timer
        $script:DbRestoreJob = [pscustomobject]@{
            PS    = $ps
            RS    = $rs
            Async = $async
        }

        # Stop any prior timer
        try {
            if ($script:DbRestoreTimer) {
                $script:DbRestoreTimer.Stop()
                $script:DbRestoreTimer = $null
            }
        } catch { }

        $script:DbRestoreTimer = New-Object System.Windows.Threading.DispatcherTimer
        $script:DbRestoreTimer.Interval = [TimeSpan]::FromMilliseconds(250)

        $script:DbRestoreTimer.Add_Tick({
            try {
                $job = $script:DbRestoreJob
                if (-not $job) { return }

                if (-not $job.Async.AsyncWaitHandle.WaitOne(0)) { return }

                # stop first to prevent re-entrancy
                try { $script:DbRestoreTimer.Stop() } catch { }

                $result = $null
                try {
                    $result = $job.PS.EndInvoke($job.Async) | Select-Object -First 1
                }
                catch {
                    Add-GuiLog "DB restore failed (EndInvoke): $($_.Exception.Message)"
                    Set-DbRestoreUiState -IsBusy $false -StatusText "Restore failed."
                    return
                }
                finally {
                    # Always cleanup the runspace
                    try { $job.PS.Dispose() } catch { }
                    try { $job.RS.Close() } catch { }
                    try { $job.RS.Dispose() } catch { }
                    $script:DbRestoreJob = $null
                }

                # UI-thread updates
                if ($result -and $result.Ok) {
                    if ($result.DbList) {
                        $TxtDbRestoreDatabases.Text = ($result.DbList -join ", ")
                    }
                    Add-GuiLog ("Restore: Completed. Databases: {0}" -f (($TxtDbRestoreDatabases.Text + "").Trim()))
                    Set-DbRestoreUiState -IsBusy $false -StatusText "Restore completed."
                }
                else {
                    $err = if ($result) { $result.Error } else { "Unknown error." }
                    Add-GuiLog "DB restore failed: $err"
                    Set-DbRestoreUiState -IsBusy $false -StatusText "Restore failed."
                }
            }
            catch {
                Add-GuiLog "DB restore failed (timer outer): $($_.Exception.Message)"
                try { Set-DbRestoreUiState -IsBusy $false -StatusText "Restore failed." } catch { }
                try { $script:DbRestoreTimer.Stop() } catch { }
                $script:DbRestoreJob = $null
            }
        })

        $script:DbRestoreTimer.Start()

        # Update status text (still locked)
        Set-DbRestoreUiState -IsBusy $true -StatusText "Restore running…"
    }
    catch {
        Add-GuiLog "DB restore failed: $($_.Exception.Message)"
        try { Set-DbRestoreUiState -IsBusy $false -StatusText "Restore failed." } catch { }
    }
})



# -------------------------------------------------
# Tools: Repack Backup (Full + Config)
# -------------------------------------------------
$script:RepackBackupJob   = $null
$script:RepackBackupTimer = $null

$BtnRunFullBackup.Add_Click({
    try {
        if ($script:RepackBackupJob -and -not $script:RepackBackupJob.Async.IsCompleted) {
            Add-GuiLog "Repack Backup: A backup job is already running."
            return
        }

        Set-RepackBackupUiState -IsBusy $true -StatusText "Starting full backup…"

        $source = ($TxtRepackRoot.Text + "").Trim()
        if ([string]::IsNullOrWhiteSpace($source) -or -not (Test-Path -LiteralPath $source -PathType Container)) {
            throw "Repack folder is invalid. Set a valid root folder first."
        }

        $destDir = ($TxtRepackBackupDest.Text + "").Trim()
        if ([string]::IsNullOrWhiteSpace($destDir)) { $destDir = $script:RepackBackupDir }
        if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }

        $state = [pscustomobject]@{
            Mode       = "Full"
            DataDir    = $DataDir
            BackupDir  = $destDir
            SourceDir  = $source
            ServerName = [string]$Config.ServerName
            AuthExe    = [string]$Config.Authserver
            WorldExe   = [string]$Config.Worldserver
            MySqlCmd   = [string]$Config.MySQL
        }

        $rs = [runspacefactory]::CreateRunspace()
        $rs.ApartmentState = "MTA"
        $rs.ThreadOptions = "ReuseThread"
        $rs.Open()

        $ps = [powershell]::Create()
        $ps.Runspace = $rs

        $ps.AddScript({
            param($state)

            $log = New-Object System.Collections.Generic.List[string]
            function Add-BackupLog([string]$m) {
                $log.Add(("{0} - {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $m)) | Out-Null
            }
            function Ensure-Dir([string]$p) {
                if (-not (Test-Path -LiteralPath $p)) {
                    New-Item -ItemType Directory -Path $p -Force | Out-Null
                }
            }

            function Send-Command([string]$name) {
                New-Item -Path (Join-Path $state.DataDir $name) -ItemType File -Force | Out-Null
                Add-BackupLog "Command sent: $name"
            }

            function Get-ProcNameNoExt([string]$p) {
                if ([string]::IsNullOrWhiteSpace($p)) { return "" }
                try { return [System.IO.Path]::GetFileNameWithoutExtension($p) } catch { return "" }
            }

            $aliases = @{
                "MySQL"       = @("mysqld","mariadbd")
                "Authserver"  = @("authserver","bnetserver")
                "Worldserver" = @("worldserver")
            }

            $a = Get-ProcNameNoExt $state.AuthExe
            $w = Get-ProcNameNoExt $state.WorldExe
            if ($a -and -not ($aliases["Authserver"] -contains $a)) { $aliases["Authserver"] += $a }
            if ($w -and -not ($aliases["Worldserver"] -contains $w)) { $aliases["Worldserver"] += $w }

            function Get-RoleProcess([string]$role) {
                foreach ($n in $aliases[$role]) {
                    try {
                        $p = Get-Process -Name $n -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($p) { return $p }
                    } catch { }
                }
                return $null
            }

            function Wait-RoleDown([string]$role, [int]$timeoutSec = 120) {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                while ($sw.Elapsed.TotalSeconds -lt $timeoutSec) {
                    if (-not (Get-RoleProcess $role)) { Add-BackupLog "$role is stopped."; return $true }
                    Start-Sleep -Milliseconds 500
                }
                return $false
            }

            function Wait-RoleUp([string]$role, [int]$timeoutSec = 180) {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                while ($sw.Elapsed.TotalSeconds -lt $timeoutSec) {
                    if (Get-RoleProcess $role) { Add-BackupLog "$role is running."; return $true }
                    Start-Sleep -Milliseconds 500
                }
                return $false
            }

            function Start-RoleDirect([string]$role) {
                if (Get-RoleProcess $role) {
                    Add-BackupLog "$role already running (direct start not needed)."
                    return $true
                }

                try {
                    switch ($role) {
                        "MySQL" {
                            $cmd = ($state.MySqlCmd + "").Trim()
                            if ([string]::IsNullOrWhiteSpace($cmd) -or -not (Test-Path -LiteralPath $cmd)) {
                                Add-BackupLog "WARN: MySQL start command not configured or not found: $cmd"
                                return $false
                            }

                            $wd = Split-Path -Parent $cmd
                            $ext = ([System.IO.Path]::GetExtension($cmd) + "").ToLowerInvariant()

                            if ($ext -in @(".bat",".cmd")) {
                                Start-Process -FilePath "cmd.exe" -ArgumentList @("/c", "`"$cmd`"") -WorkingDirectory $wd -WindowStyle Hidden | Out-Null
                            } else {
                                Start-Process -FilePath $cmd -WorkingDirectory $wd | Out-Null
                            }
                            Add-BackupLog "Direct-start invoked for MySQL using: $cmd"
                        }
                        "Authserver" {
                            $exe = ($state.AuthExe + "").Trim()
                            if ([string]::IsNullOrWhiteSpace($exe) -or -not (Test-Path -LiteralPath $exe)) {
                                Add-BackupLog "WARN: Authserver executable not found: $exe"
                                return $false
                            }
                            $wd = Split-Path -Parent $exe
                            Start-Process -FilePath $exe -WorkingDirectory $wd | Out-Null
                            Add-BackupLog "Direct-start invoked for Authserver: $exe"
                        }
                        "Worldserver" {
                            $exe = ($state.WorldExe + "").Trim()
                            if ([string]::IsNullOrWhiteSpace($exe) -or -not (Test-Path -LiteralPath $exe)) {
                                Add-BackupLog "WARN: Worldserver executable not found: $exe"
                                return $false
                            }
                            $wd = Split-Path -Parent $exe
                            Start-Process -FilePath $exe -WorkingDirectory $wd | Out-Null
                            Add-BackupLog "Direct-start invoked for Worldserver: $exe"
                        }
                    }
                    return $true
                } catch {
                    Add-BackupLog "WARN: Direct-start failed for ${role}: $($_.Exception.Message)"
                    return $false
                }
            }

            $zipPath = $null
            $err = $null
            $restartErr = $null
            $restartIssues = New-Object System.Collections.Generic.List[string]
            $stopped = @{
                "MySQL"       = $false
                "Authserver"  = $false
                "Worldserver" = $false
            }

            Ensure-Dir $state.BackupDir

            $holdDir = Join-Path $state.DataDir "holds"
            Ensure-Dir $holdDir

            function Set-Hold([string]$role, [bool]$held) {
                $p = Join-Path $holdDir "$role.hold"
                if ($held) {
                    New-Item -Path $p -ItemType File -Force | Out-Null
                    Add-BackupLog "$role HOLD set."
                } else {
                    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
                    Add-BackupLog "$role HOLD cleared."
                }
            }

            try {
                Add-BackupLog "Full backup requested. Source: $($state.SourceDir)"

                # Prevent auto-restarts during backup
                Set-Hold "Worldserver" $true
                Set-Hold "Authserver"  $true
                Set-Hold "MySQL"       $true

                # Stop in required order: World -> Auth -> MySQL
                Send-Command "command.stop.world"
                if (-not (Wait-RoleDown "Worldserver" 120)) { throw "Worldserver did not stop within 120s." }
                $stopped["Worldserver"] = $true

                Send-Command "command.stop.auth"
                if (-not (Wait-RoleDown "Authserver" 120)) { throw "Authserver did not stop within 120s." }
                $stopped["Authserver"] = $true

                Send-Command "command.stop.mysql"
                if (-not (Wait-RoleDown "MySQL" 180)) { throw "MySQL did not stop within 180s." }
                $stopped["MySQL"] = $true

                Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue | Out-Null

                $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $safeName = ($state.ServerName + "").Trim()
                if ([string]::IsNullOrWhiteSpace($safeName)) { $safeName = "Repack" }
                $zipName = "{0}_FullBackup_{1}.zip" -f ($safeName -replace '[^\w\-]+','_'), $stamp
                $zipPath = Join-Path $state.BackupDir $zipName

                if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue }
                Add-BackupLog "Creating zip: $zipPath"
                [System.IO.Compression.ZipFile]::CreateFromDirectory($state.SourceDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)
                Add-BackupLog "Zip created successfully."
            } catch {
                $err = $_.Exception.Message
                Add-BackupLog "ERROR: $err"
            } finally {
                # Always clear holds so the user isn't stranded
                try {
                    Set-Hold "MySQL"       $false
                    Set-Hold "Authserver"  $false
                    Set-Hold "Worldserver" $false
                } catch {
                    Add-BackupLog "WARN: Failed to clear HOLDs: $($_.Exception.Message)"
                }

                # Attempt restart if we stopped anything (best-effort + direct-start fallback)
                if ($stopped["MySQL"] -or $stopped["Authserver"] -or $stopped["Worldserver"]) {
                    try {
                        Add-BackupLog "Restart sequence: MySQL -> Authserver -> Worldserver"

                        function Restart-Role([string]$role, [string]$cmdName, [int]$timeoutSec) {
                            Send-Command $cmdName
                            if (Wait-RoleUp $role $timeoutSec) { return $true }

                            Add-BackupLog "WARN: ${role} did not start via command within ${timeoutSec}s; trying direct start."
                            $directOk = Start-RoleDirect $role
                            if ($directOk) {
                                if (Wait-RoleUp $role $timeoutSec) { return $true }
                                Add-BackupLog "WARN: ${role} direct start invoked, but process did not become/stay running."
                            } else {
                                Add-BackupLog "WARN: ${role} direct start not available (not configured / not found)."
                            }

                            $restartIssues.Add("${role} failed to start") | Out-Null
                            return $false
                        }

                        [void](Restart-Role "MySQL"       "command.start.mysql" 90)
                        [void](Restart-Role "Authserver"  "command.start.auth"  90)
                        [void](Restart-Role "Worldserver" "command.start.world" 90)

                        if ($restartIssues.Count -gt 0) {
                            $restartErr = ($restartIssues.ToArray() -join "; ")
                            Add-BackupLog "WARN: Restart sequence completed with issues: $restartErr"
                        } else {
                            Add-BackupLog "Restart sequence complete."
                        }
                    } catch {
                        $restartErr = $_.Exception.Message
                        Add-BackupLog "WARN: Restart sequence encountered an unexpected error: $restartErr"
                    }
                }
            }

            # Treat the ZIP creation as the primary success criterion.
            # Restart issues should not mark the backup itself as failed.
            if ($err) {
                return [pscustomobject]@{
                    Ok=$false
                    Mode=$state.Mode
                    ZipPath=$zipPath
                    RestartOk=$false
                    RestartError=$restartErr
                    Error=$err
                    VerboseLogPath = $verboseLogPath
                    Steps=$log.ToArray()
                }
            }

            if (-not $zipPath -or -not (Test-Path -LiteralPath $zipPath)) {
                $err = "Backup zip was not created."
                return [pscustomobject]@{
                    Ok=$false
                    Mode=$state.Mode
                    ZipPath=$zipPath
                    RestartOk=$false
                    RestartError=$restartErr
                    Error=$err
                    Steps=$log.ToArray()
                }
            }

            return [pscustomobject]@{
                Ok=$true
                Mode=$state.Mode
                ZipPath=$zipPath
                RestartOk=([string]::IsNullOrWhiteSpace(($restartErr + "")))
                RestartError=$restartErr
                Steps=$log.ToArray()
            }
        }).AddArgument($state) | Out-Null


        $async = $ps.BeginInvoke()
        $script:RepackBackupJob = [pscustomobject]@{ PowerShell=$ps; Async=$async; Runspace=$rs }

        try { if ($script:RepackBackupTimer) { $script:RepackBackupTimer.Stop() } } catch { }
        $script:RepackBackupTimer = New-Object System.Windows.Threading.DispatcherTimer
        $script:RepackBackupTimer.Interval = [TimeSpan]::FromMilliseconds(250)

        $script:RepackBackupTimer.add_Tick({
            try {
                if (-not $script:RepackBackupJob) { return }
                if (-not $script:RepackBackupJob.Async.IsCompleted) { return }

                $result = $script:RepackBackupJob.PowerShell.EndInvoke($script:RepackBackupJob.Async)

                try { $script:RepackBackupJob.PowerShell.Dispose() } catch { }
                try { $script:RepackBackupJob.Runspace.Close() } catch { }
                try { $script:RepackBackupJob.Runspace.Dispose() } catch { }
                $script:RepackBackupJob = $null

                $script:RepackBackupTimer.Stop()

                if ($result -and $result.Steps) { foreach ($l in $result.Steps) { Add-GuiLog $l } }

                if ($result -and $result.Ok) {
                    $zip = $result.ZipPath
                    $restartOk = $true
                    $restartErr = $null
                    try {
                        if ($result.PSObject.Properties.Match("RestartOk").Count -gt 0) { $restartOk = [bool]$result.RestartOk }
                        if ($result.PSObject.Properties.Match("RestartError").Count -gt 0) { $restartErr = $result.RestartError }
                    } catch { }

                    if (-not $restartOk -and -not [string]::IsNullOrWhiteSpace(($restartErr + ""))) {
                        Add-GuiLog "WARN: Full backup created successfully: $zip"
                        Add-GuiLog "WARN: Restart phase reported issues: $restartErr"
                        Set-RepackBackupUiState -IsBusy $false -StatusText ("Full backup complete: " + $zip + "`r`nRestart warning: " + $restartErr)
                    } else {
                        Add-GuiLog "Full backup complete: $zip"
                        Set-RepackBackupUiState -IsBusy $false -StatusText ("Full backup complete: " + $zip)
                    }
                } else {
                    $msg = if ($result) { $result.Error } else { "Unknown error." }
                    Add-GuiLog "ERROR: Full backup failed: $msg"
                    Set-RepackBackupUiState -IsBusy $false -StatusText ("Full backup failed: " + $msg)
                }
            } catch {
                Add-GuiLog "ERROR: Full backup completion handler failed: $_"
                Set-RepackBackupUiState -IsBusy $false -StatusText "Full backup failed (unexpected UI error)."
                try { $script:RepackBackupTimer.Stop() } catch { }
                $script:RepackBackupJob = $null
            }
        })

        $script:RepackBackupTimer.Start()
    } catch {
        Add-GuiLog "ERROR: Full backup failed to start: $($_.Exception.Message)"
        Set-RepackBackupUiState -IsBusy $false -StatusText ("Full backup failed to start: " + $_.Exception.Message)
    }
})

$BtnRunConfigBackup.Add_Click({
    try {
        if ($script:RepackBackupJob -and -not $script:RepackBackupJob.Async.IsCompleted) {
            Add-GuiLog "Config Backup: A backup job is already running."
            return
        }

        Set-RepackBackupUiState -IsBusy $true -StatusText "Starting config backup…"

        $destDir = ($TxtRepackBackupDest.Text + "").Trim()
        if ([string]::IsNullOrWhiteSpace($destDir)) { $destDir = $script:RepackBackupDir }
        if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }

        $state = [pscustomobject]@{
            Mode       = "Config"
            BackupDir  = $destDir
            ServerName = [string]$Config.ServerName
            AuthExe    = [string]$Config.Authserver
            WorldExe   = [string]$Config.Worldserver
        }

        $rs = [runspacefactory]::CreateRunspace()
        $rs.ApartmentState = "MTA"
        $rs.ThreadOptions = "ReuseThread"
        $rs.Open()

        $ps = [powershell]::Create()
        $ps.Runspace = $rs

        $ps.AddScript({
            param($state)

            $log = New-Object System.Collections.Generic.List[string]
            function Add-BackupLog([string]$m) { $log.Add(("{0} - {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $m)) | Out-Null }
            function Ensure-Dir([string]$p) { if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null } }

            try {
                Ensure-Dir $state.BackupDir

                $confDir = ""
                if ($state.WorldExe -and (Test-Path -LiteralPath $state.WorldExe -PathType Leaf)) {
                    $confDir = Split-Path -Parent $state.WorldExe
                } elseif ($state.AuthExe -and (Test-Path -LiteralPath $state.AuthExe -PathType Leaf)) {
                    $confDir = Split-Path -Parent $state.AuthExe
                }

                if ([string]::IsNullOrWhiteSpace($confDir) -or -not (Test-Path -LiteralPath $confDir -PathType Container)) {
                    throw "Unable to resolve config directory. Ensure Authserver/Worldserver paths are configured and valid."
                }

                $worldConf = Join-Path $confDir "worldserver.conf"
                $bnetConf  = Join-Path $confDir "bnetserver.conf"

                if (-not (Test-Path -LiteralPath $worldConf -PathType Leaf)) { throw "Missing file: $worldConf" }
                if (-not (Test-Path -LiteralPath $bnetConf  -PathType Leaf)) { throw "Missing file: $bnetConf" }

                Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue | Out-Null

                $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $safeName = ($state.ServerName + "").Trim()
                if ([string]::IsNullOrWhiteSpace($safeName)) { $safeName = "Repack" }
                $zipName = "{0}_ConfigBackup_{1}.zip" -f ($safeName -replace '[^\w\-]+','_'), $stamp
                $zipPath = Join-Path $state.BackupDir $zipName

                $temp = Join-Path ([System.IO.Path]::GetTempPath()) ("WoWWatchdog_ConfigBackup_" + [guid]::NewGuid().ToString("N"))
                Ensure-Dir $temp

                Copy-Item -LiteralPath $worldConf -Destination (Join-Path $temp "worldserver.conf") -Force
                Copy-Item -LiteralPath $bnetConf  -Destination (Join-Path $temp "bnetserver.conf")  -Force

                if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue }
                Add-BackupLog "Creating zip: $zipPath"
                [System.IO.Compression.ZipFile]::CreateFromDirectory($temp, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

                try { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue } catch { }

                return [pscustomobject]@{ Ok=$true; Mode=$state.Mode; ZipPath=$zipPath; Steps=$log.ToArray() }
            } catch {
                $err = $_.Exception.Message
                Add-BackupLog "ERROR: $err"
                return [pscustomobject]@{ Ok=$false; Mode=$state.Mode; Error=$err; Steps=$log.ToArray() }
            }
        }).AddArgument($state) | Out-Null

        $async = $ps.BeginInvoke()
        $script:RepackBackupJob = [pscustomobject]@{ PowerShell=$ps; Async=$async; Runspace=$rs }

        try { if ($script:RepackBackupTimer) { $script:RepackBackupTimer.Stop() } } catch { }
        $script:RepackBackupTimer = New-Object System.Windows.Threading.DispatcherTimer
        $script:RepackBackupTimer.Interval = [TimeSpan]::FromMilliseconds(250)

        $script:RepackBackupTimer.add_Tick({
            try {
                if (-not $script:RepackBackupJob) { return }
                if (-not $script:RepackBackupJob.Async.IsCompleted) { return }

                $result = $script:RepackBackupJob.PowerShell.EndInvoke($script:RepackBackupJob.Async)

                try { $script:RepackBackupJob.PowerShell.Dispose() } catch { }
                try { $script:RepackBackupJob.Runspace.Close() } catch { }
                try { $script:RepackBackupJob.Runspace.Dispose() } catch { }
                $script:RepackBackupJob = $null

                $script:RepackBackupTimer.Stop()

                if ($result -and $result.Steps) { foreach ($l in $result.Steps) { Add-GuiLog $l } }

                if ($result -and $result.Ok) {
                    Add-GuiLog "Config backup complete: $($result.ZipPath)"
                    Set-RepackBackupUiState -IsBusy $false -StatusText "Config backup complete: $($result.ZipPath)"
                } else {
                    $msg = if ($result) { $result.Error } else { "Unknown error." }
                    Add-GuiLog "ERROR: Config backup failed: $msg"
                    Set-RepackBackupUiState -IsBusy $false -StatusText ("Config backup failed: " + $msg)
                }
            } catch {
                Add-GuiLog "ERROR: Config backup completion handler failed: $_"
                Set-RepackBackupUiState -IsBusy $false -StatusText "Config backup failed (unexpected UI error)."
                try { $script:RepackBackupTimer.Stop() } catch { }
                $script:RepackBackupJob = $null
            }
        })

        $script:RepackBackupTimer.Start()
    } catch {
        Add-GuiLog "ERROR: Config backup failed to start: $($_.Exception.Message)"
        Set-RepackBackupUiState -IsBusy $false -StatusText ("Config backup failed to start: " + $_.Exception.Message)
    }
})


# =================================================
# Broad Helpers (UI, Identity, Roles, NTFY)
# Paste after controls are assigned.
# =================================================

function Invoke-Ui {
    param([Parameter(Mandatory)][scriptblock]$Action)
    if ($null -eq $Window) { & $Action; return }
    try { $Window.Dispatcher.Invoke([action]$Action) } catch { & $Action }
}

function Get-TextSafe {
    param($Control, [string]$Default = "")
    try {
        if ($null -eq $Control) { return $Default }
        # TextBox
        if ($Control.PSObject.Properties.Match("Text").Count -gt 0) {
            $t = [string]$Control.Text
            if ([string]::IsNullOrWhiteSpace($t)) { return $Default }
            return $t
        }
        return $Default
    } catch { return $Default }
}

function Get-PasswordSecure {
    param(
        [Parameter(Mandatory)]
        [System.Windows.Controls.PasswordBox]$PwdBox
    )

    try {
        $sec = $PwdBox.SecurePassword
        if ($null -eq $sec -or $sec.Length -eq 0) { return $null }
        return $sec
    } catch {
        return $null
    }
}



function Get-ComboSelectedText {
    param([System.Windows.Controls.ComboBox]$Combo, [string]$Default = "")
    try {
        if ($null -eq $Combo -or $null -eq $Combo.SelectedItem) { return $Default }
        $item = $Combo.SelectedItem
        if ($item -is [System.Windows.Controls.ComboBoxItem]) {
            $c = [string]$item.Content
            if ([string]::IsNullOrWhiteSpace($c)) { return $Default }
            return $c
        }
        $s = [string]$item
        if ([string]::IsNullOrWhiteSpace($s)) { return $Default }
        return $s
    } catch { return $Default }
}

function Get-PrimaryIPv4Safe {
    try {
        $ip = Get-NetIPAddress -AddressFamily IPv4 -InterfaceOperationalStatus Up -ErrorAction Stop |
            Where-Object { $_.IPAddress -and $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254*" } |
            Select-Object -First 1 -ExpandProperty IPAddress
        if ($ip) { return $ip }
    } catch { }
    return "Unknown"
}

function Get-WowIdentity {
    # Cached identity + server name resolution
    if (-not $global:WowWatchdogIdentity) {
        $global:WowWatchdogIdentity = [pscustomobject]@{
            Hostname  = $env:COMPUTERNAME
            IPAddress = (Get-PrimaryIPv4Safe)
        }
    }

    $serverName = ""
    try { $serverName = [string]$Config.ServerName } catch { $serverName = "" }
    if ([string]::IsNullOrWhiteSpace($serverName)) { $serverName = $global:WowWatchdogIdentity.Hostname }

    [pscustomobject]@{
        ServerName = $serverName
        Hostname   = $global:WowWatchdogIdentity.Hostname
        IPAddress  = $global:WowWatchdogIdentity.IPAddress
    }
}

function Get-ExpansionLabel {
    $exp = Get-ComboSelectedText -Combo $CmbExpansion -Default "Unknown"
    if ($exp -eq "Custom") {
        $custom = (Get-TextSafe -Control $TxtExpansionCustom -Default "Custom").Trim()
        if (-not [string]::IsNullOrWhiteSpace($custom)) { return $custom }
        return "Custom"
    }
    if ([string]::IsNullOrWhiteSpace($exp)) { return "Unknown" }
    return $exp
}

function Get-NtfyEndpoint {
    $server = (Get-TextSafe -Control $TxtNtfyServer).Trim().TrimEnd('/')
    $topic  = (Get-TextSafe -Control $TxtNtfyTopic).Trim().Trim('/')
    if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($topic)) { return $null }
    return "$server/$topic"
}

function Get-NtfyPriorityForService {
    param([Parameter(Mandatory)][ValidateSet("MySQL","Authserver","Worldserver","Test")][string]$ServiceName)

    $prio = 4
    $globalPrioStr = Get-ComboSelectedText -Combo $CmbNtfyPriorityDefault -Default "4"
    [void][int]::TryParse($globalPrioStr, [ref]$prio)
    if ($prio -lt 1 -or $prio -gt 5) { $prio = 4 }

    # Service override
    $override = "Auto"
    switch ($ServiceName) {
        "MySQL"       { $override = Get-ComboSelectedText -Combo $CmbPriMySQL -Default "Auto" }
        "Authserver"  { $override = Get-ComboSelectedText -Combo $CmbPriAuthserver -Default "Auto" }
        "Worldserver" { $override = Get-ComboSelectedText -Combo $CmbPriWorldserver -Default "Auto" }
        default       { $override = "Auto" }
    }

    if ($override -and $override -ne "Auto") {
        $o = 0
        if ([int]::TryParse($override, [ref]$o) -and $o -ge 1 -and $o -le 5) { $prio = $o }
    }
    return $prio
}

function Normalize-NtfyTag {
    param([string]$Tag)

    if ([string]::IsNullOrWhiteSpace($Tag)) { return $null }

    $t = $Tag.Trim().ToLowerInvariant()

    # Replace whitespace with hyphens and remove characters that commonly break header parsing
    $t = [regex]::Replace($t, '\s+', '-')
    $t = [regex]::Replace($t, '[^a-z0-9_-]', '')

    # Collapse repeated separators
    $t = [regex]::Replace($t, '-{2,}', '-')
    $t = [regex]::Replace($t, '_{2,}', '_')

    $t = $t.Trim('-', '_')
    if ($t.Length -eq 0) { return $null }
    return $t
}

function Get-NtfyTags {
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][string]$StateTag  # "up"/"down"/"test"
    )

    $tags = New-Object System.Collections.Generic.List[string]

    # User-specified tags (comma-separated)
    $raw = (Get-TextSafe -Control $TxtNtfyTags).Trim()
    if (-not [string]::IsNullOrWhiteSpace($raw)) {
        foreach ($t in ($raw -split ",")) {
            $tt = Normalize-NtfyTag ($t.Trim())
            if ($tt) { [void]$tags.Add($tt) }
        }
    }

    # Auto-tags (normalized to avoid proxy/server header parsing issues)
    $exp = Normalize-NtfyTag (Get-ExpansionLabel)
    $svc = Normalize-NtfyTag $ServiceName
    $st  = Normalize-NtfyTag $StateTag

    foreach ($x in @("wow", $exp, $svc, $st)) {
        $nx = Normalize-NtfyTag $x
        if ($nx) { [void]$tags.Add($nx) }
    }

    (($tags | Where-Object { $_ } | Select-Object -Unique) -join ",")
}

function Send-NtfyMessage {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Body,
        [Parameter(Mandatory)][int]$Priority,
        [Parameter(Mandatory)][string]$TagsCsv
    )

    $url = Get-NtfyEndpoint
    if (-not $url) { return $false }

    $headers = @{
    "Title"    = (([string]$Title) -replace "[\r\n]+", " ").Trim()
    "Priority" = "$Priority"
}
if (-not [string]::IsNullOrWhiteSpace($TagsCsv)) {
    $headers["Tags"] = (([string]$TagsCsv) -replace "[\r\n]+", "").Trim()
}

    $mode     = (Get-SelectedComboContent $CmbNtfyAuthMode).Trim()
    $username = (Get-TextSafe -Control $TxtNtfyUsername)

    # Prefer the live UI boxes, but fall back to the DPAPI secrets store (so auth survives app restarts)
    $passwordSecure = Get-PasswordSecure -PwdBox $TxtNtfyPassword
    if ($null -eq $passwordSecure -or $passwordSecure.Length -eq 0) {
        $plain = Get-NtfySecret -Kind "BasicPassword"
        if (-not [string]::IsNullOrWhiteSpace($plain)) {
            $passwordSecure = ConvertTo-SecureString -String $plain -AsPlainText -Force
        }
    }

    $tokenSecure = Get-PasswordSecure -PwdBox $TxtNtfyToken
    if ($null -eq $tokenSecure -or $tokenSecure.Length -eq 0) {
        $plain = Get-NtfySecret -Kind "Token"
        if (-not [string]::IsNullOrWhiteSpace($plain)) {
            $tokenSecure = ConvertTo-SecureString -String $plain -AsPlainText -Force
        }
    }

    $cred = $null
    if ($mode -eq "Basic (User/Pass)" -and
        -not [string]::IsNullOrWhiteSpace($username) -and
        $passwordSecure -and $passwordSecure.Length -gt 0) {

        $cred = [pscredential]::new($username, $passwordSecure)
    }

    $authHeaders = Get-NtfyAuthHeaders `
        -Mode $mode `
        -Credential $cred `
        -TokenSecure $tokenSecure

    foreach ($k in $authHeaders.Keys) { $headers[$k] = $authHeaders[$k] }

    # Send with simple retry for transient failures (timeouts, 429, 5xx)
    $maxAttempts = 3
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Invoke-RestMethod -Uri $url -Method Post -Body $Body -Headers $headers -ContentType "text/plain; charset=utf-8" -ErrorAction Stop | Out-Null
            return $true
        }
        catch {
            $ex = $_.Exception
            $status = $null
            $respText = $null

            try {
                if ($ex -and $ex.Response) {
                    # HttpWebResponse
                    $status = [int]$ex.Response.StatusCode
                    try {
                        $stream = $ex.Response.GetResponseStream()
                        if ($stream) {
                            $reader = New-Object System.IO.StreamReader($stream)
                            $respText = $reader.ReadToEnd()
                            $reader.Dispose()
                        }
                    } catch { }
                }
            } catch { }

            $isTransient = $false
            if ($null -eq $status) { $isTransient = $true }
            elseif ($status -eq 429) { $isTransient = $true }
            elseif ($status -ge 500 -and $status -le 599) { $isTransient = $true }

            if ($attempt -lt $maxAttempts -and $isTransient) {
                Start-Sleep -Seconds (2 * $attempt)
                continue
            }

            $detail = $ex.Message
            if ($status) { $detail = "HTTP $status - $detail" }
            if (-not [string]::IsNullOrWhiteSpace($respText)) { $detail = "$detail :: $respText" }

            throw "NTFY send failed after $attempt attempt(s): $detail"
        }
    }

    return $false
}

function Role-IsHeld {
    param([Parameter(Mandatory)][ValidateSet("MySQL","Authserver","Worldserver")][string]$Role)
    try {
        $p = Get-HoldFilePath -Role $Role
        return (Test-Path -LiteralPath $p)
    } catch { return $false }
}

function Update-UpdateIndicator {
    try {
        $rel = Get-LatestGitHubRelease -Owner $RepoOwner -Repo $RepoName
        $latest = Parse-ReleaseVersion $rel.tag_name

        $TxtLatestVersion.Text = $latest.ToString()

        if ($latest -gt $AppVersion) {
            $TxtLatestVersion.Foreground = [System.Windows.Media.Brushes]::LimeGreen
            $BtnUpdateNow.Visibility = "Visible"
            Add-GuiLog "Update available: $AppVersion -> $latest"
        } else {
            $TxtLatestVersion.Foreground = [System.Windows.Media.Brushes]::White
            $BtnUpdateNow.Visibility = "Collapsed"
            Add-GuiLog "No update available (current: $AppVersion, latest: $latest)."
        }

        # Store release JSON so Update Now can reuse it without re-querying
        $script:LatestReleaseInfo = $rel
    }
    catch {
        Add-GuiLog "ERROR: Update check failed: $_"
    }
}

$BtnCheckUpdates.Add_Click({ Update-UpdateIndicator })
# -------------------------------------------------
# Updates: SPP V2 Legion Repack Update
# -------------------------------------------------
$script:SppV2UpdateJob   = $null
$script:SppV2UpdateTimer = $null

function Start-SppV2RepackUpdate {
    try {
        if ($script:SppV2UpdateJob -and -not $script:SppV2UpdateJob.Async.IsCompleted) {
            Add-GuiLog "SPP Update: A job is already running."
            return
        }

        # Resolve paths from Tools tab
        $repackRoot = ($TxtRepackRoot.Text + "").Trim()
        if ([string]::IsNullOrWhiteSpace($repackRoot) -or -not (Test-Path -LiteralPath $repackRoot -PathType Container)) {
            throw "Repack folder is invalid. Set a valid repack root on the Tools tab first."
        }

        $backupDir = ($TxtRepackBackupDest.Text + "").Trim()
        if ([string]::IsNullOrWhiteSpace($backupDir)) { $backupDir = $script:RepackBackupDir }
        if (-not (Test-Path -LiteralPath $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }

        if ($TxtSppV2UpdateTarget) {
            $TxtSppV2UpdateTarget.Text = "Target: " + $repackRoot
        }

        Set-SppV2UpdateUiState -IsBusy $true -StatusText "Starting SPP V2 repack update…"
        
        # TESTING ONLY: disable backup while validating update flow
        $skipBackup = $false

        $state = [pscustomobject]@{
            DataDir       = $DataDir
            BackupDir     = $backupDir
            SourceDir     = $repackRoot
            ServerName    = [string]$Config.ServerName
            AuthExe       = [string]$Config.Authserver
            WorldExe      = [string]$Config.Worldserver
            MySqlCmd      = [string]$Config.MySQL
            SkipBackup    = [bool]$skipBackup

            UpdateUrl     = "http://mdicsdildoemporium.com/dicpics/legion_update//Update.tmp"
            UpdatePass    = "https://spp-forum.de/games/document.txt"
            SuppressMissingMySqlPopup = $true
            UpdateBatTimeoutSec       = 1800
            UpdateBatHeartbeatSec     = 10
        }

        $rs = [runspacefactory]::CreateRunspace()
        $rs.ApartmentState = "MTA"
        $rs.ThreadOptions  = "ReuseThread"
        $rs.Open()

        $ps = [powershell]::Create()
        $ps.Runspace = $rs

        $null = $ps.AddScript({
            param($state)

            $log = New-Object System.Collections.Generic.List[string]

            # Persistent per-run verbose log file (so you can watch progress live)
            $updateLogDir = Join-Path $state.DataDir "update-logs"
            if (-not (Test-Path -LiteralPath $updateLogDir)) {
                try { New-Item -ItemType Directory -Path $updateLogDir -Force | Out-Null } catch { }
            }
            $verboseLogPath = Join-Path $updateLogDir ("spp_update_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

            function Add-Step([string]$m) {
                $line = ("{0} - {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $m)
                $log.Add($line)
                try { Add-Content -LiteralPath $verboseLogPath -Value $line -Encoding UTF8 } catch { }
            }

            Add-Step ("Verbose log: " + $verboseLogPath)
            function Ensure-Dir([string]$p) { if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null } }

            function Send-Command([string]$name) {
                New-Item -Path (Join-Path $state.DataDir $name) -ItemType File -Force | Out-Null
                Add-Step "Command sent: $name"
            }

            function Get-ProcNameNoExt([string]$p) {
                if ([string]::IsNullOrWhiteSpace($p)) { return "" }
                try { return [System.IO.Path]::GetFileNameWithoutExtension($p) } catch { return "" }
            }

            $aliases = @{
                "MySQL"       = @("mysqld","mariadbd")
                "Authserver"  = @("authserver","bnetserver")
                "Worldserver" = @("worldserver")
            }

            $a = Get-ProcNameNoExt $state.AuthExe
            $w = Get-ProcNameNoExt $state.WorldExe
            if ($a -and -not ($aliases["Authserver"] -contains $a)) { $aliases["Authserver"] += $a }
            if ($w -and -not ($aliases["Worldserver"] -contains $w)) { $aliases["Worldserver"] += $w }

            $holdDir = Join-Path $state.DataDir "holds"
            Ensure-Dir $holdDir

            function Set-Hold([string]$role, [bool]$held) {
                $p = Join-Path $holdDir "$role.hold"
                if ($held) {
                    New-Item -Path $p -ItemType File -Force | Out-Null
                    Add-Step "$role HOLD set."
                } else {
                    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
                    Add-Step "$role HOLD cleared."
                }
            }

            function Get-RoleProcess([string]$role) {
                $names = $aliases[$role]
                if (-not $names) { return $null }
                foreach ($n in $names) {
                    try {
                        $p = Get-Process -Name $n -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($p) { return $p }
                    } catch { }
                }
                return $null
            }

            function Wait-RoleDown([string]$role, [int]$timeoutSec) {
                $sw = [diagnostics.stopwatch]::StartNew()
                while ($sw.Elapsed.TotalSeconds -lt $timeoutSec) {
                    if (-not (Get-RoleProcess $role)) { return $true }
                    Start-Sleep -Milliseconds 500
                }
                return $false
            }

            function Wait-RoleUp([string]$role, [int]$timeoutSec) {
                $sw = [diagnostics.stopwatch]::StartNew()
                while ($sw.Elapsed.TotalSeconds -lt $timeoutSec) {
                    if (Get-RoleProcess $role) { return $true }
                    Start-Sleep -Milliseconds 500
                }
                return $false
            }

                        function Resolve-RoleExe([string]$role, [string]$exe) {
                $exe = ($exe + "").Trim().Trim('"')
                if ([string]::IsNullOrWhiteSpace($exe)) { return $null }

                try { $exe = [Environment]::ExpandEnvironmentVariables($exe) } catch { }

                # If a directory was supplied, try common server binaries.
                if (Test-Path -LiteralPath $exe -PathType Container) {
                    if ($role -eq "MySQL") {
                        foreach ($cand in @("mysqld.exe","mariadbd.exe")) {
                            $p = Join-Path $exe $cand
                            if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
                        }
                    }
                    return $null
                }

                # If role is MySQL and config points to mysql.exe (client), derive mysqld.exe from the same folder.
                if ($role -eq "MySQL") {
                    try {
                        $leaf = [System.IO.Path]::GetFileName($exe)
                        if ($leaf -and $leaf.Equals("mysql.exe", [StringComparison]::OrdinalIgnoreCase)) {
                            $dir = Split-Path -Parent $exe
                            foreach ($cand in @("mysqld.exe","mariadbd.exe")) {
                                $p = Join-Path $dir $cand
                                if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
                            }
                        }
                    } catch { }
                }

                if (Test-Path -LiteralPath $exe -PathType Leaf) { return $exe }

                # If no extension, try .exe to avoid ShellExecute popups (e.g., "Windows cannot find ...\mysqld").
                try {
                    if ([string]::IsNullOrWhiteSpace([System.IO.Path]::GetExtension($exe))) {
                        $exe2 = $exe + ".exe"
                        if (Test-Path -LiteralPath $exe2 -PathType Leaf) { return $exe2 }
                    }
                } catch { }

                return $null
            }

function Start-RoleDirect([string]$role) {
                $exe = $null
                switch ($role) {
                    "MySQL"       { $exe = $state.MySqlCmd }
                    "Authserver"  { $exe = $state.AuthExe }
                    "Worldserver" { $exe = $state.WorldExe }
                }

                if ([string]::IsNullOrWhiteSpace($exe)) {
                    Add-Step "WARN: $role direct-start skipped (path not set)."
                    return $false
                }

                $resolved = Resolve-RoleExe $role $exe
                if (-not $resolved) {
                    Add-Step "WARN: $role direct-start skipped (not found: $exe)."
                    return $false
                }

                try {
                    Start-Process -FilePath $resolved -WorkingDirectory (Split-Path -Parent $resolved) -WindowStyle Hidden | Out-Null
                    Add-Step "$role direct-start invoked."
                    return $true
                } catch {
                    Add-Step ("WARN: $role direct-start failed: " + $_.Exception.Message)
                    return $false
                }
            }



            function Restart-Role([string]$role, [string]$cmdName, [int]$timeoutSec) {
                Set-Hold $role $false
                Send-Command $cmdName

                if (Wait-RoleUp $role $timeoutSec) {
                    Add-Step "$role started."
                    return $true
                }

                Add-Step "WARN: $role did not come up via watchdog command; trying direct-start."
                if (Start-RoleDirect $role) {
                    if (Wait-RoleUp $role $timeoutSec) {
                        Add-Step "$role started (direct)."
                        return $true
                    }
                }

                Add-Step "ERROR: $role failed to start."
                return $false
            }

            $zipPath = $null
            $restartErr = $null

            try {
                Add-Step "SPP V2 repack update requested. Source: $($state.SourceDir)"
                Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue | Out-Null

                # Holds prevent watchdog from auto-restarting during stop/update
                Set-Hold "Worldserver" $true
                Set-Hold "Authserver"  $true
                Set-Hold "MySQL"       $true

                # Stop in order: World -> Auth -> MySQL
                Send-Command "command.stop.world"
                if (-not (Wait-RoleDown "Worldserver" 120)) { throw "Worldserver did not stop within 120s." }

                Send-Command "command.stop.auth"
                if (-not (Wait-RoleDown "Authserver" 120)) { throw "Authserver did not stop within 120s." }

                Send-Command "command.stop.mysql"
                if (-not (Wait-RoleDown "MySQL" 180)) { throw "MySQL did not stop within 180s." }

                # Full repack backup
                if (-not $state.SkipBackup) {
                    # Full repack backup
                    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
                    $safeName = ($state.ServerName + "").Trim()
                    if ([string]::IsNullOrWhiteSpace($safeName)) { $safeName = "Repack" }
                    $safeName = ($safeName -replace '[^\w\-]+','_')
                    $zipPath = Join-Path $state.BackupDir ("{0}_SPPUpdateBackup_{1}.zip" -f $safeName, $stamp)

                    Add-Step "Creating backup zip: $zipPath"
                    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue }
                    [System.IO.Compression.ZipFile]::CreateFromDirectory($state.SourceDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $true)
                    Add-Step "Backup created: $zipPath"
                }
                else {
                    $zipPath = $null
                    Add-Step "Backup skipped (testing mode)."
                }

                # Run updater commands in repack folder
                Add-Step "Running SPP V2 updater in: $($state.SourceDir)"
                Push-Location $state.SourceDir
                try {
                    foreach ($f in @("update.tmp","Update.vbs")) {
                        $fp = Join-Path $state.SourceDir $f
                        if (Test-Path -LiteralPath $fp) { Remove-Item -LiteralPath $fp -Force -ErrorAction SilentlyContinue; Add-Step "Removed: $f" }
                    }

                    $wget = Join-Path $state.SourceDir "tools\wget.exe"
                    $seven = Join-Path $state.SourceDir "tools\7za.exe"
                    if (-not (Test-Path -LiteralPath $wget))  { throw "Missing tools\wget.exe at: $wget" }
                    if (-not (Test-Path -LiteralPath $seven)) { throw "Missing tools\7za.exe at: $seven" }

                    Add-Step "Downloading update: $($state.UpdateUrl)"
                    $out = & $wget "-N" "--no-check-certificate" $state.UpdateUrl 2>&1
                    foreach ($l in $out) { if ($l) { Add-Step ("wget: " + $l) } }

                    Start-Sleep -Seconds 1

                    $tmp = Join-Path $state.SourceDir "Update.tmp"
                    if (-not (Test-Path -LiteralPath $tmp)) { throw "Update.tmp was not downloaded." }

                    Add-Step "Extracting Update.tmp"
                    $out2 = & $seven "x" $tmp ("-p" + $state.UpdatePass) "-aoa" 2>&1
                    foreach ($l in $out2) { if ($l) { Add-Step ("7za: " + $l) } }

                    Start-Sleep -Seconds 1

                        $bat = Join-Path $state.SourceDir "Website\Update.bat"
    if (Test-Path -LiteralPath $bat) {
        Add-Step "Running Website\Update.bat (capturing stdout/stderr; popup suppression; timeout + heartbeat)"

        $wd = (Split-Path -Parent $bat)

        $stamp2 = Get-Date -Format "yyyyMMdd_HHmmss"
        $outFile = Join-Path $updateLogDir ("update_bat_stdout_{0}.log" -f $stamp2)
        $errFile = Join-Path $updateLogDir ("update_bat_stderr_{0}.log" -f $stamp2)
        $inFile  = Join-Path $updateLogDir ("update_bat_stdin_{0}.txt" -f $stamp2)

        # Empty stdin file prevents common "pause"/prompt hangs (similar to: <nul)
        try { Set-Content -LiteralPath $inFile -Value "" -Encoding ASCII -Force } catch { }

        $timeoutSec = 0
        try { $timeoutSec = [int]$state.UpdateBatTimeoutSec } catch { $timeoutSec = 0 }
        if ($timeoutSec -lt 30) { $timeoutSec = 1800 } # 30 minutes default

        $heartbeatSec = 10
        try {
            if ($state.PSObject.Properties.Match("UpdateBatHeartbeatSec").Count -gt 0) {
                $heartbeatSec = [int]$state.UpdateBatHeartbeatSec
            }
        } catch { }
        if ($heartbeatSec -lt 2) { $heartbeatSec = 10 }

        Add-Step ("Starting Update.bat with timeout {0}s; heartbeat {1}s; stdout: {2}; stderr: {3}" -f $timeoutSec, $heartbeatSec, $outFile, $errFile)

        # ----------------------------
        # Popup suppressor (best-effort)
        # ----------------------------
        $dlg = $null
        try {
            if ($state.PSObject.Properties.Match("SuppressMissingMySqlPopup").Count -gt 0 -and [bool]$state.SuppressMissingMySqlPopup) {
                Add-Type -Namespace Win32 -Name User32 -MemberDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class User32 {
  public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
  [DllImport("user32.dll")] public static extern int GetWindowTextLength(IntPtr hWnd);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
}
"@ -ErrorAction SilentlyContinue | Out-Null

                $stop = $false
                $rx = New-Object System.Text.RegularExpressions.Regex('(?i)(windows cannot find|\\(mysql|mysqld|mariadbd)(\.exe)?$|mysql\.exe|mysqld\.exe|mariadbd\.exe)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

                $dlg = [System.Threading.Thread]{
                    try {
                        while (-not $stop) {
                            [Win32.User32]::EnumWindows({ param($h,$lp)
                                try {
                                    if (-not [Win32.User32]::IsWindowVisible($h)) { return $true }
                                    $sbC = New-Object System.Text.StringBuilder 256
                                    [void][Win32.User32]::GetClassName($h, $sbC, $sbC.Capacity)
                                    if ($sbC.ToString() -ne "#32770") { return $true } # dialog class

                                    $len = [Win32.User32]::GetWindowTextLength($h)
                                    if ($len -le 0) { return $true }
                                    $sbT = New-Object System.Text.StringBuilder ($len + 1)
                                    [void][Win32.User32]::GetWindowText($h, $sbT, $sbT.Capacity)
                                    $title = $sbT.ToString()

                                    if ($title -and $rx.IsMatch($title)) {
                                        # WM_CLOSE = 0x0010
                                        [void][Win32.User32]::PostMessage($h, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
                                    }
                                } catch { }
                                return $true
                            }, [IntPtr]::Zero) | Out-Null

                            Start-Sleep -Milliseconds 250
                        }
                    } catch { }
                }
                $dlg.IsBackground = $true
                $dlg.Start()
                Add-Step "Popup suppressor started (closing Windows 'cannot find' + mysql/mysqld/mariadbd dialogs)."
            }
        } catch {
            Add-Step ("WARN: Popup suppressor failed to start: " + $_.Exception.Message)
        }

        try {
            $p = Start-Process -FilePath "cmd.exe" `
                -ArgumentList @("/d","/c", "call", "`"$bat`"") `
                -WorkingDirectory $wd `
                -WindowStyle Hidden `
                -PassThru `
                -RedirectStandardOutput $outFile `
                -RedirectStandardError  $errFile `
                -RedirectStandardInput  $inFile

            $swBat = [diagnostics.stopwatch]::StartNew()
            $nextBeat = 0

            while (-not $p.HasExited) {
                Start-Sleep -Milliseconds 250

                $elapsed = [int]$swBat.Elapsed.TotalSeconds
                if ($elapsed -ge $timeoutSec) {
                    Add-Step ("ERROR: Website\Update.bat timed out after {0}s; killing process tree." -f $timeoutSec)

                    try { $p.Kill() } catch { }

                    # Kill child process tree (best-effort)
                    try {
                        $toKill = New-Object System.Collections.Generic.List[int]
                        $toKill.Add($p.Id) | Out-Null

                        $added = $true
                        while ($added) {
                            $added = $false
                            $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($toKill[-1])" -ErrorAction SilentlyContinue
                            foreach ($c in $children) {
                                if ($c -and $c.ProcessId -and -not $toKill.Contains([int]$c.ProcessId)) {
                                    $toKill.Add([int]$c.ProcessId) | Out-Null
                                    $added = $true
                                }
                            }
                        }

                        foreach ($pid in ($toKill | Sort-Object -Descending)) {
                            try { Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue } catch { }
                        }
                    } catch { }

                    throw ("Website\Update.bat timed out after " + $timeoutSec + " seconds.")
                }

                if ($elapsed -ge $nextBeat) {
                    $nextBeat = $elapsed + $heartbeatSec

                    $outBytes = 0
                    $errBytes = 0
                    try { $outBytes = (Get-Item -LiteralPath $outFile -ErrorAction Stop).Length } catch { }
                    try { $errBytes = (Get-Item -LiteralPath $errFile -ErrorAction Stop).Length } catch { }

                    Add-Step ("Update.bat still running (elapsed {0}s). stdout={1:N0} bytes; stderr={2:N0} bytes." -f $elapsed, $outBytes, $errBytes)
                }
            }

            Add-Step ("Update.bat finished after {0}s." -f ([int]$swBat.Elapsed.TotalSeconds))
            Add-Step ("Website\Update.bat exit code: " + $p.ExitCode)

            # If it failed, echo the tail of stdout/stderr into steps for quick triage
            if ($p.ExitCode -ne 0) {
                Add-Step "---- Update.bat STDOUT tail ----"
                try { Get-Content -LiteralPath $outFile -ErrorAction Stop -Tail 200 | ForEach-Object { Add-Step ("stdout: " + $_) } } catch { Add-Step "stdout: <unavailable>" }
                Add-Step "---- Update.bat STDERR tail ----"
                try { Get-Content -LiteralPath $errFile -ErrorAction Stop -Tail 200 | ForEach-Object { Add-Step ("stderr: " + $_) } } catch { Add-Step "stderr: <unavailable>" }

                throw ("Website\Update.bat failed (exit code " + $p.ExitCode + ").")
            }
        }
        finally {
            try { $stop = $true } catch { }
            try { if ($dlg -and $dlg.IsAlive) { $dlg.Join(1000) | Out-Null } } catch { }
            Add-Step "Popup suppressor stopped."
        }
    } else {
        Add-Step "WARN: Website\Update.bat not found, skipping."
    }


                    Start-Sleep -Seconds 1
                    Add-Step "Updater phase completed."
                } finally {
                    Pop-Location
                }

                # Restart in order: MySQL -> Auth -> World
                $restartIssues = New-Object System.Collections.Generic.List[string]
                if (-not (Restart-Role "MySQL"       "command.start.mysql" 90)) { $restartIssues.Add("MySQL failed to start") | Out-Null }
                if (-not (Restart-Role "Authserver"  "command.start.auth"  90)) { $restartIssues.Add("Authserver failed to start") | Out-Null }
                if (-not (Restart-Role "Worldserver" "command.start.world" 90)) { $restartIssues.Add("Worldserver failed to start") | Out-Null }

                if ($restartIssues.Count -gt 0) {
                    $restartErr = ($restartIssues.ToArray() -join "; ")
                    Add-Step "WARN: Restart sequence completed with issues: $restartErr"
                } else {
                    Add-Step "Restart sequence completed successfully."
                }

                return [pscustomobject]@{
                    Ok = $true
                    ZipPath = $zipPath
                    RestartOk = ([string]::IsNullOrWhiteSpace(($restartErr + "")))
                    RestartError = $restartErr
                    Steps = $log.ToArray()
                }
            }
            catch {
                $err = $_.Exception.Message

                # Best-effort: clear holds and attempt restart even on failure
                try { Set-Hold "Worldserver" $false } catch { }
                try { Set-Hold "Authserver"  $false } catch { }
                try { Set-Hold "MySQL"       $false } catch { }

                try {
                    $restartIssues = New-Object System.Collections.Generic.List[string]
                    if (-not (Restart-Role "MySQL"       "command.start.mysql" 90)) { $restartIssues.Add("MySQL failed to start") | Out-Null }
                    if (-not (Restart-Role "Authserver"  "command.start.auth"  90)) { $restartIssues.Add("Authserver failed to start") | Out-Null }
                    if (-not (Restart-Role "Worldserver" "command.start.world" 90)) { $restartIssues.Add("Worldserver failed to start") | Out-Null }
                    if ($restartIssues.Count -gt 0) { $restartErr = ($restartIssues.ToArray() -join "; ") }
                } catch { }

                Add-Step ("ERROR: Update failed: " + $err)
                if ($zipPath) { Add-Step ("Backup artifact exists: " + $zipPath) }

                return [pscustomobject]@{
                    Ok = $false
                    Error = $err
                    ZipPath = $zipPath
                    RestartOk = ([string]::IsNullOrWhiteSpace(($restartErr + "")))
                    RestartError = $restartErr
                    Steps = $log.ToArray()
                }
            }
        }).AddArgument($state) | Out-Null

        $async = $ps.BeginInvoke()
        $script:SppV2UpdateJob = [pscustomobject]@{ PowerShell=$ps; Async=$async; Runspace=$rs }

        try { if ($script:SppV2UpdateTimer) { $script:SppV2UpdateTimer.Stop() } } catch { }
        $script:SppV2UpdateTimer = New-Object System.Windows.Threading.DispatcherTimer
        $script:SppV2UpdateTimer.Interval = [TimeSpan]::FromMilliseconds(250)

        $script:SppV2UpdateTimer.add_Tick({
            try {
                if (-not $script:SppV2UpdateJob) { return }
                if (-not $script:SppV2UpdateJob.Async.IsCompleted) { return }

                $result = $script:SppV2UpdateJob.PowerShell.EndInvoke($script:SppV2UpdateJob.Async)

                try { $script:SppV2UpdateJob.PowerShell.Dispose() } catch { }
                try { $script:SppV2UpdateJob.Runspace.Close() } catch { }
                try { $script:SppV2UpdateJob.Runspace.Dispose() } catch { }
                $script:SppV2UpdateJob = $null

                try { $script:SppV2UpdateTimer.Stop() } catch { }

                if ($result -and $result.Steps) { foreach ($l in $result.Steps) { Add-GuiLog $l } }

                if ($result -and $result.Ok) {
                    $zip = $result.ZipPath
                    $restartOk = $true
                    $restartErr = $null
                    try {
                        if ($result.PSObject.Properties.Match("RestartOk").Count -gt 0) { $restartOk = [bool]$result.RestartOk }
                        if ($result.PSObject.Properties.Match("RestartError").Count -gt 0) { $restartErr = $result.RestartError }
                    } catch { }

                    if (-not $restartOk -and -not [string]::IsNullOrWhiteSpace(($restartErr + ""))) {
                        Add-GuiLog "SPP Update complete; backup: $zip"
                        Add-GuiLog "WARN: Restart phase reported issues: $restartErr"
                        Set-SppV2UpdateUiState -IsBusy $false -StatusText ("SPP update complete. Backup: " + $zip + "`r`nRestart warning: " + $restartErr)
                    } else {
                        Add-GuiLog "SPP Update complete; backup: $zip"
                        Set-SppV2UpdateUiState -IsBusy $false -StatusText ("SPP update complete. Backup: " + $zip)
                    }
                } else {
                    $msg = if ($result) { $result.Error } else { "Unknown error." }
                    $zip = $null
                    try { $zip = $result.ZipPath } catch { }
                    if (-not [string]::IsNullOrWhiteSpace(($zip + ""))) {
                        Add-GuiLog "ERROR: SPP update failed: $msg (backup created: $zip)"
                        Set-SppV2UpdateUiState -IsBusy $false -StatusText ("SPP update failed: " + $msg + "`r`nBackup created: " + $zip)
                    } else {
                        Add-GuiLog "ERROR: SPP update failed: $msg"
                        Set-SppV2UpdateUiState -IsBusy $false -StatusText ("SPP update failed: " + $msg)
                    }
                }
            } catch {
                Add-GuiLog "ERROR: SPP update completion handler failed: $_"
                Set-SppV2UpdateUiState -IsBusy $false -StatusText "SPP update failed (unexpected UI error)."
                try { $script:SppV2UpdateTimer.Stop() } catch { }
                $script:SppV2UpdateJob = $null
            }
        })

        $script:SppV2UpdateTimer.Start()
    }
    catch {
        Add-GuiLog "ERROR: SPP update failed to start: $($_.Exception.Message)"
        Set-SppV2UpdateUiState -IsBusy $false -StatusText ("SPP update failed to start: " + $_.Exception.Message)
    }
}

if ($BtnSppV2RepackUpdate) {
    $BtnSppV2RepackUpdate.Add_Click({
        Start-SppV2RepackUpdate
    })
}

# Tab 1: Server Info
$TxtOnlinePlayers = $Window.FindName("TxtOnlinePlayers")

$script:LastPlayerPollError = $null

$PlayerPollTimer = New-Object System.Windows.Threading.DispatcherTimer
$PlayerPollTimer.Interval = [TimeSpan]::FromSeconds(5)

$PlayerPollTimer.Add_Tick({
    try {
        $count = Get-OnlinePlayerCountCached_Legion

        $TxtOnlinePlayers.Text = [string]$count

        if ($count -gt 0) {
            $TxtOnlinePlayers.Foreground = [System.Windows.Media.Brushes]::LimeGreen
        } else {
            $TxtOnlinePlayers.Foreground = [System.Windows.Media.Brushes]::Gold
        }
    } catch {
        $TxtOnlinePlayers.Text = "—"
        $TxtOnlinePlayers.Foreground = [System.Windows.Media.Brushes]::Tomato
    }
})

# Start only if implemented
if (Get-Command Get-OnlinePlayerCount_Legion -ErrorAction SilentlyContinue) {
    $PlayerPollTimer.Start()
} else {
    $TxtOnlinePlayers.Text = "—"
}

# Initial values from config
$TxtMySQL.Text  = $Config.MySQL
$TxtAuth.Text   = $Config.Authserver
$TxtWorld.Text  = $Config.Worldserver
$TxtRepackRoot.Text  = $Config.RepackRoot


# Worldserver Telnet defaults
if ([string]::IsNullOrWhiteSpace([string]$Config.WorldTelnetHost)) { $Config.WorldTelnetHost = "127.0.0.1" }
if (-not $Config.WorldTelnetPort) { $Config.WorldTelnetPort = 3443 }
if ($null -eq $Config.WorldTelnetUser) { $Config.WorldTelnetUser = "" }

try { $TxtWorldTelnetHost.Text = [string]$Config.WorldTelnetHost } catch { }
try { $TxtWorldTelnetPort.Text = [string]$Config.WorldTelnetPort } catch { }
try { $TxtWorldTelnetUser.Text = [string]$Config.WorldTelnetUser } catch { }
try { $TxtWorldTelnetPassword.Password = "" } catch { }

# Target label for the Telnet console tab
try { $TxtTelnetTarget.Text = ("{0}:{1}" -f [string]$Config.WorldTelnetHost, [string]$Config.WorldTelnetPort) } catch { }

# Worldserver Log Tail defaults
if ($null -eq $Config.WorldserverLogPath) { $Config.WorldserverLogPath = "" }
try { $TxtWorldLogPath.Text = [string]$Config.WorldserverLogPath } catch { }
try {
    if (-not $TxtWorldLogOutput.Text) { $TxtWorldLogOutput.Text = "[Worldserver log tail ready]`r`n" }
} catch { }

function Update-WorldTelnetPasswordStatus {
    try {
        $h = ($TxtWorldTelnetHost.Text + "").Trim()
        if ([string]::IsNullOrWhiteSpace($h)) { $h = "127.0.0.1" }

        $p = 3443
        try { $p = [int]([string]$TxtWorldTelnetPort.Text) } catch { $p = 3443 }
        if (-not $p) { $p = 3443 }

        $u = ($TxtWorldTelnetUser.Text + "").Trim()

        if (Has-WorldTelnetPassword -TelnetHost $h -Port $p -Username $u) {
            $LblWorldTelnetPasswordStatus.Text = "Password is stored (encrypted)"
            $LblWorldTelnetPasswordStatus.Foreground = [System.Windows.Media.Brushes]::LimeGreen
        } else {
            $LblWorldTelnetPasswordStatus.Text = "Password not set"
            $LblWorldTelnetPasswordStatus.Foreground = [System.Windows.Media.Brushes]::Gold
        }
    } catch { }
}

Update-WorldTelnetPasswordStatus

if ([string]::IsNullOrWhiteSpace([string]$Config.DbHost))     { $Config.DbHost = "127.0.0.1" }
if (-not $Config.DbPort)                                      { $Config.DbPort = 3306 }
if ([string]::IsNullOrWhiteSpace([string]$Config.DbUser))     { $Config.DbUser = "root" }
if ([string]::IsNullOrWhiteSpace([string]$Config.DbNameChar)) { $Config.DbNameChar = "legion_characters" }

$TxtDbHost.Text     = [string]$Config.DbHost
$TxtDbPort.Text     = [string]$Config.DbPort
$TxtDbUser.Text     = [string]$Config.DbUser
$TxtDbNameChar.Text = [string]$Config.DbNameChar

# Never auto-fill password into UI; keep blank
try { $TxtDbPassword.Password = "" } catch { }


$TxtServiceStatus = $Window.FindName("TxtServiceStatus")

function Get-SelectedComboContent {
    param([System.Windows.Controls.ComboBox]$Combo)

    $item = $Combo.SelectedItem
    if (-not $item) { return "" }

    # ComboBoxItem
    if ($item -is [System.Windows.Controls.ComboBoxItem]) {
        return [string]$item.Content
    }

    # Fallback: plain strings or other objects
    return [string]$item
}

function Update-NtfyAuthUI {

    $mode = ""
    try {
        $mode = [string](Get-SelectedComboContent $CmbNtfyAuthMode)
    } catch { $mode = "" }

    $mode = $mode.Trim()

    switch -Wildcard ($mode) {

        "Basic*" {
            $TxtNtfyUsername.Visibility = "Visible"
            $TxtNtfyPassword.Visibility = "Visible"
            $TxtNtfyToken.Visibility    = "Collapsed"

            if ($LblNtfyUsername) { $LblNtfyUsername.Visibility = "Visible" }
            if ($LblNtfyPassword) { $LblNtfyPassword.Visibility = "Visible" }
            if ($LblNtfyToken)    { $LblNtfyToken.Visibility    = "Collapsed" }
        }

        "Token*" {
            $TxtNtfyUsername.Visibility = "Collapsed"
            $TxtNtfyPassword.Visibility = "Collapsed"
            $TxtNtfyToken.Visibility    = "Visible"

            if ($LblNtfyUsername) { $LblNtfyUsername.Visibility = "Collapsed" }
            if ($LblNtfyPassword) { $LblNtfyPassword.Visibility = "Collapsed" }
            if ($LblNtfyToken)    { $LblNtfyToken.Visibility    = "Visible" }
        }

        default { # None
            $TxtNtfyUsername.Visibility = "Collapsed"
            $TxtNtfyPassword.Visibility = "Collapsed"
            $TxtNtfyToken.Visibility    = "Collapsed"

            if ($LblNtfyUsername) { $LblNtfyUsername.Visibility = "Collapsed" }
            if ($LblNtfyPassword) { $LblNtfyPassword.Visibility = "Collapsed" }
            if ($LblNtfyToken)    { $LblNtfyToken.Visibility    = "Collapsed" }
        }
    }
}

Update-NtfyAuthUI

$CmbNtfyAuthMode.Add_SelectionChanged({ Update-NtfyAuthUI })

function Get-WowWatchdogService {
    try { return Get-Service -Name $ServiceName -ErrorAction Stop } catch { return $null }
}

function Update-ServiceStatusLabel {
    if (-not $TxtServiceStatus) { return }

    $svc = Get-WowWatchdogService
    if (-not $svc) {
        $TxtServiceStatus.Text = "Not installed"
        $TxtServiceStatus.Foreground = [System.Windows.Media.Brushes]::Orange
        return
    }

    $TxtServiceStatus.Text = $svc.Status.ToString()
    switch ($svc.Status) {
        "Running" { $TxtServiceStatus.Foreground = [System.Windows.Media.Brushes]::LimeGreen }
        "Stopped" { $TxtServiceStatus.Foreground = [System.Windows.Media.Brushes]::Red }
        default   { $TxtServiceStatus.Foreground = [System.Windows.Media.Brushes]::Yellow }
    }
}

function Select-ComboItemByContent {
    param(
        [Parameter(Mandatory)][System.Windows.Controls.ComboBox]$Combo,
        [Parameter(Mandatory)][string]$Content
    )
    foreach ($item in $Combo.Items) {
        if ($item -and $item.Content -eq $Content) {
            $Combo.SelectedItem = $item
            return $true
        }
    }
    return $false
}

function Set-ExpansionUiFromConfig {
    $exp = [string]$Config.Expansion
    if ([string]::IsNullOrWhiteSpace($exp)) { $exp = "Unknown" }

    # Try direct preset match
    $matched = Select-ComboItemByContent -Combo $CmbExpansion -Content $exp
    if (-not $matched) {
        # Use Custom for any non-preset value
        [void](Select-ComboItemByContent -Combo $CmbExpansion -Content "Custom")
        $TxtExpansionCustom.Text = $exp
        $TxtExpansionCustom.Visibility = "Visible"
    } else {
        if ($exp -eq "Custom") {
            $TxtExpansionCustom.Visibility = "Visible"
        } else {
            $TxtExpansionCustom.Visibility = "Collapsed"
        }
    }
}

function Set-PriorityOverrideCombo {
    param(
        [Parameter(Mandatory)][System.Windows.Controls.ComboBox]$Combo,
        [int]$Value
    )
    if ($Value -ge 1 -and $Value -le 5) {
        [void](Select-ComboItemByContent -Combo $Combo -Content ([string]$Value))
    } else {
        [void](Select-ComboItemByContent -Combo $Combo -Content "Auto")
    }
}

function Update-WatchdogStatusLabel {
    $svc = Get-WowWatchdogService
    if (-not $svc) {
        $TxtWatchdogStatus.Text = "Not installed"
        $TxtWatchdogStatus.Foreground = [System.Windows.Media.Brushes]::Orange
        return
    }

    if ($svc.Status -ne 'Running') {
        $TxtWatchdogStatus.Text = "Stopped"
        $TxtWatchdogStatus.Foreground = [System.Windows.Media.Brushes]::Orange
        return
    }

    # Service is running; validate heartbeat freshness
    $freshSeconds = 5
    if (Test-Path $HeartbeatFile) {
        try {
            $ts = Get-Content $HeartbeatFile -Raw -ErrorAction Stop
            $hb = [DateTime]::Parse($ts)

            $age = ((Get-Date) - $hb).TotalSeconds
            if ($age -le $freshSeconds) {
                $TxtWatchdogStatus.Text = "Running (Healthy)"
                $TxtWatchdogStatus.Foreground = [System.Windows.Media.Brushes]::LimeGreen
                return
            } else {
                $TxtWatchdogStatus.Text = "Running (Stalled - heartbeat $([int]$age)s old)"
                $TxtWatchdogStatus.Foreground = [System.Windows.Media.Brushes]::Yellow
                return
            }
        } catch {
            $TxtWatchdogStatus.Text = "Running (Heartbeat unreadable)"
            $TxtWatchdogStatus.Foreground = [System.Windows.Media.Brushes]::Yellow
            return
        }
    }

    $TxtWatchdogStatus.Text = "Running (No heartbeat file)"
    $TxtWatchdogStatus.Foreground = [System.Windows.Media.Brushes]::Yellow
}


function Start-WatchdogPreferred {
    $svc = Get-WowWatchdogService
    if (Test-Path $StopSignalFile) { Remove-Item $StopSignalFile -Force -ErrorAction SilentlyContinue }
    if (-not $svc) {
        Add-GuiLog "ERROR: WoWWatchdog service is not installed."
        return
    }

    try {
        if ($svc.Status -ne 'Running') {
            Start-Service -Name $ServiceName
        }
        Add-GuiLog "Service started."
    } catch {
        Add-GuiLog "ERROR: Failed to start service: $_"
    }
}

function Stop-WatchdogPreferred {
    $svc = Get-WowWatchdogService
    if (-not $svc) { return }

    try {
        # Ask watchdog loop to gracefully stop roles
        New-Item -Path $StopSignalFile -ItemType File -Force | Out-Null
        Add-GuiLog "Stop signal written. Requesting service stop."

        if ($svc.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -ErrorAction Stop
        }

        Add-GuiLog "Service stop requested."
    } catch {
        Add-GuiLog "ERROR: Failed to stop service gracefully: $_"
    }
}


# Expansion + NTFY values from config
Set-ExpansionUiFromConfig

$TxtNtfyServer.Text   = [string]$Config.NTFY.Server
$TxtNtfyTopic.Text    = [string]$Config.NTFY.Topic
$TxtNtfyTags.Text     = [string]$Config.NTFY.Tags
$TxtNtfyUsername.Text = [string]$Config.NTFY.Username

# AuthMode
$mode = "None"
try {
    if ($Config.NTFY -and $Config.NTFY.PSObject.Properties["AuthMode"]) {
        $mode = [string]$Config.NTFY.AuthMode
        if ([string]::IsNullOrWhiteSpace($mode)) { $mode = "None" }
    }
} catch { $mode = "None" }

[void](Select-ComboItemByContent -Combo $CmbNtfyAuthMode -Content $mode)

# DPAPI mode: do NOT load secrets into UI
# (Send logic will pull from secrets store if boxes are empty)
try { $TxtNtfyPassword.Password = "" } catch { }
try { $TxtNtfyToken.Password    = "" } catch { }

# Apply visibility after setting selection
Update-NtfyAuthUI

# Default priority
$prioDefault = 4
try { $prioDefault = [int]$Config.NTFY.PriorityDefault } catch { $prioDefault = 4 }
if ($prioDefault -lt 1 -or $prioDefault -gt 5) { $prioDefault = 4 }
[void](Select-ComboItemByContent -Combo $CmbNtfyPriorityDefault -Content ([string]$prioDefault))

# Per-service enable switches
$ChkNtfyMySQL.IsChecked       = [bool]$Config.NTFY.EnableMySQL
$ChkNtfyAuthserver.IsChecked  = [bool]$Config.NTFY.EnableAuthserver
$ChkNtfyWorldserver.IsChecked = [bool]$Config.NTFY.EnableWorldserver

# Per-service priority overrides
$svcPri = $Config.NTFY.ServicePriorities
if (-not $svcPri) { $svcPri = [pscustomobject]@{} }

Set-PriorityOverrideCombo -Combo $CmbPriMySQL       -Value ([int]($svcPri.MySQL))
Set-PriorityOverrideCombo -Combo $CmbPriAuthserver  -Value ([int]($svcPri.Authserver))
Set-PriorityOverrideCombo -Combo $CmbPriWorldserver -Value ([int]($svcPri.Worldserver))


# State-change triggers
$ChkNtfyOnDown.IsChecked       = [bool]$Config.NTFY.SendOnDown
$ChkNtfyOnUp.IsChecked         = [bool]$Config.NTFY.SendOnUp

# Expansion dropdown behavior
$CmbExpansion.Add_SelectionChanged({
    try {
        $sel = $CmbExpansion.SelectedItem
        if ($sel -and $sel.Content -eq "Custom") {
            $TxtExpansionCustom.Visibility = "Visible"
        } else {
            $TxtExpansionCustom.Visibility = "Collapsed"
        }
    } catch { }
})

# -------------------------------------------------
# Brushes for LED animation
# -------------------------------------------------
$BrushLedGreen1 = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(0x4C,0xE0,0x4C))
$BrushLedGreen2 = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(0x2D,0xA8,0x2D))
$BrushLedRed    = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(0xD9,0x44,0x44))
$BrushLedGray   = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(0x80,0x80,0x80))

$EllipseMySQL.Fill  = $BrushLedGray
$EllipseAuth.Fill   = $BrushLedGray
$EllipseWorld.Fill  = $BrushLedGray

# Cache for CPU sampling per role
if ($null -eq $global:ProcSampleCache) { $global:ProcSampleCache = @{} }

function Get-ProcUtilSnapshot {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("MySQL","Authserver","Worldserver")]
        [string]$Role
    )

    $p = Get-ProcessSafe $Role
    if ($null -eq $p) {
        return [pscustomobject]@{
            CpuPercent   = $null
            WorkingSetMB = $null
            PrivateMB    = $null
        }
    }

    $now = Get-Date
    $logical = [Environment]::ProcessorCount

    # Memory snapshot
    $wsMB = [math]::Round(($p.WorkingSet64 / 1MB), 1)
    $privMB = $null
    try { $privMB = [math]::Round(($p.PrivateMemorySize64 / 1MB), 1) } catch { }

    # CPU% via delta sampling
    $key = $Role
    $cpuPct = $null

    $curr = [pscustomobject]@{
        Pid       = $p.Id
        Timestamp = $now
        TotalCpu  = $p.TotalProcessorTime
    }

    if ($global:ProcSampleCache.ContainsKey($key)) {
        $prev = $global:ProcSampleCache[$key]

        # If PID changed, reset sampling
        if ($prev.Pid -eq $curr.Pid) {
            $dt = ($curr.Timestamp - $prev.Timestamp).TotalSeconds
            if ($dt -gt 0.2) {
                $dCpu = ($curr.TotalCpu - $prev.TotalCpu).TotalSeconds
                $cpuPct = [math]::Round((($dCpu / ($dt * $logical)) * 100), 1)
                if ($cpuPct -lt 0) { $cpuPct = 0 }
            }
        }
    }

    $global:ProcSampleCache[$key] = $curr

    [pscustomobject]@{
        CpuPercent   = $cpuPct
        WorkingSetMB = $wsMB
        PrivateMB    = $privMB
    }
}

function Format-CpuText([nullable[double]]$pct) {
    if ($null -eq $pct) { return "CPU: —" }
    return ("CPU: {0}%" -f $pct)
}

function Format-MemText([nullable[double]]$wsMB, [nullable[double]]$privMB) {
    if ($null -eq $wsMB) { return "RAM: —" }
    if ($null -ne $privMB) { return ("RAM: {0} MB (Priv {1} MB)" -f $wsMB, $privMB) }
    return ("RAM: {0} MB" -f $wsMB)
}

function Format-Uptime {
    param([TimeSpan]$Span)
    # d.hh:mm:ss (only show days if > 0)
    if ($Span.TotalDays -ge 1) {
        return ("{0}d {1:00}:{2:00}:{3:00}" -f [int]$Span.TotalDays, $Span.Hours, $Span.Minutes, $Span.Seconds)
    }
    return ("{0:00}:{1:00}:{2:00}" -f $Span.Hours, $Span.Minutes, $Span.Seconds)
}

function Update-WorldUptimeLabel {
    try {
        $p = Get-ProcessSafe "Worldserver"
        if ($null -eq $p) {
            $TxtWorldUptime.Text = "Stopped"
            return
        }

        $uptime = (Get-Date) - $p.StartTime
        $TxtWorldUptime.Text = (Format-Uptime -Span $uptime)
    } catch {
        $TxtWorldUptime.Text = "—"
    }
}


function Update-ResourceUtilizationUi {
    $uMy = Get-ProcUtilSnapshot -Role "MySQL"
    $uAu = Get-ProcUtilSnapshot -Role "Authserver"
    $uWo = Get-ProcUtilSnapshot -Role "Worldserver"

    if ($null -ne $TxtUtilMySQLCpu) { $TxtUtilMySQLCpu.Text = (Format-CpuText $uMy.CpuPercent) }
    if ($null -ne $TxtUtilMySQLMem) { $TxtUtilMySQLMem.Text = (Format-MemText $uMy.WorkingSetMB $uMy.PrivateMB) }

    if ($null -ne $TxtUtilAuthCpu)  { $TxtUtilAuthCpu.Text  = (Format-CpuText $uAu.CpuPercent) }
    if ($null -ne $TxtUtilAuthMem)  { $TxtUtilAuthMem.Text  = (Format-MemText $uAu.WorkingSetMB $uAu.PrivateMB) }

    if ($null -ne $TxtUtilWorldCpu) { $TxtUtilWorldCpu.Text = (Format-CpuText $uWo.CpuPercent) }
    if ($null -ne $TxtUtilWorldMem) { $TxtUtilWorldMem.Text = (Format-MemText $uWo.WorkingSetMB $uWo.PrivateMB) }
}


# -------------------------------------------------
# NTFY auth header helpers
# -------------------------------------------------
function ConvertFrom-SecureStringPlain {
    param([Parameter(Mandatory)][Security.SecureString]$Secure)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-NtfyAuthHeaders {
    param(
        [Parameter(Mandatory)][string]$Mode,
        [pscredential]$Credential,
        [Security.SecureString]$TokenSecure
    )

    $h = @{}

    switch ($Mode) {
        "Basic (User/Pass)" {
            if ($Credential) {
                $pair = "{0}:{1}" -f $Credential.UserName, $Credential.GetNetworkCredential().Password
                $b64  = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair))
                $h["Authorization"] = "Basic $b64"
            }
        }
        "Bearer Token" {
            if ($TokenSecure -and $TokenSecure.Length -gt 0) {
                $token = ConvertFrom-SecureStringPlain -Secure $TokenSecure
                $h["Authorization"] = "Bearer $token"
            }
        }
    }

    return $h
}

# -------------------------------------------------
# GUI log helper
# -------------------------------------------------
function Rotate-GuiLogIfNeeded {
    param(
        [Parameter(Mandatory)][string]$Path,
        [int64]$MaxBytes = 5242880,
        [int]$Keep = 5
    )

    try {
        if (-not (Test-Path -LiteralPath $Path)) { return }
        if ($MaxBytes -le 0 -or $Keep -le 0) { return }

        $len = (Get-Item -LiteralPath $Path).Length
        if ($len -lt $MaxBytes) { return }

        for ($i = $Keep - 1; $i -ge 1; $i--) {
            $src = "$Path.$i"
            $dst = "$Path." + ($i + 1)
            if (Test-Path -LiteralPath $src) {
                Move-Item -LiteralPath $src -Destination $dst -Force
            }
        }

        Move-Item -LiteralPath $Path -Destination "$Path.1" -Force
    } catch { }
}

function Add-GuiLog {
    param([string]$Message)

    try {
        $tsFile = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Rotate-GuiLogIfNeeded -Path $LogPath -MaxBytes $LogMaxBytes -Keep $LogRetainCount
        Add-Content -Path $LogPath -Value "[$tsFile] $Message" -Encoding UTF8
    } catch { }

    if (-not $Window) { return }

    $Window.Dispatcher.Invoke([action]{
        $ts = (Get-Date).ToString("HH:mm:ss")
        $TxtLiveLog.AppendText("[$ts] $Message`r`n")
        $TxtLiveLog.ScrollToEnd()
    })
}

# -------------------------------------------------
# Last-chance exception logging (helps diagnose CTD)
# -------------------------------------------------
try {
    [System.AppDomain]::CurrentDomain.add_UnhandledException({
        param($errorsender, $e)
        try {
            $ex = $e.ExceptionObject
            if ($ex) {
                Add-GuiLog ("FATAL: Unhandled exception: {0}`r`n{1}" -f $ex.Message, $ex.StackTrace)
            } else {
                Add-GuiLog "FATAL: Unhandled exception (no ExceptionObject)."
            }
        } catch { }
    })
} catch { }

try {
    [System.Windows.Application]::Current.DispatcherUnhandledException += {
        param($errorsender, $e)
        try {
            Add-GuiLog ("FATAL: DispatcherUnhandledException: {0}`r`n{1}" -f $e.Exception.Message, $e.Exception.StackTrace)
        } catch { }
        # Let it crash after logging (do not set $e.Handled = $true unless you want to suppress)
    }
} catch { }

# -------------------------------------------------
# Watchdog Command helper
# -------------------------------------------------
function Send-WatchdogCommand {
    param([string]$Name)

    $cmd = Join-Path $DataDir $Name
    New-Item -Path $cmd -ItemType File -Force | Out-Null
    Add-GuiLog "Command sent: $Name"
}

# -------------------------------------------------
# Hold helpers (prevents watchdog auto-restart)
# -------------------------------------------------
$HoldDir = Join-Path $DataDir "holds"
if (-not (Test-Path $HoldDir)) {
    New-Item -Path $HoldDir -ItemType Directory -Force | Out-Null
}

function Get-HoldFilePath {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("MySQL","Authserver","Worldserver")]
        [string]$Role
    )
    return (Join-Path $HoldDir "$Role.hold")
}

function Set-RoleHold {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("MySQL","Authserver","Worldserver")]
        [string]$Role,

        [Parameter(Mandatory)]
        [bool]$Held
    )

    $p = Get-HoldFilePath -Role $Role

    if ($Held) {
        New-Item -Path $p -ItemType File -Force | Out-Null
        Add-GuiLog "$Role placed on HOLD (watchdog will not auto-restart)."
    } else {
        if (Test-Path $p) { Remove-Item $p -Force -ErrorAction SilentlyContinue }
        Add-GuiLog "$Role HOLD cleared (watchdog may auto-restart if configured)."
    }
}

function Set-AllHolds {
    param([bool]$Held)
    Set-RoleHold -Role "Worldserver" -Held $Held
    Set-RoleHold -Role "Authserver"  -Held $Held
    Set-RoleHold -Role "MySQL"       -Held $Held
}


# -------------------------------------------------
# File picker helper
# -------------------------------------------------
function Pick-File {
    param([string]$Filter = "All files (*.*)|*.*")
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Filter = $Filter
    $ok = $dlg.ShowDialog($Window)
        if ($ok) { return $dlg.FileName }
    return $null
}

# -------------------------------------------------
# Process name aliases (WoW server variants)
# -------------------------------------------------
$ProcessAliases = @{
    MySQL = @(
        "mysqld",
        "mysqld-nt",
        "mysqld-opt",
        "mariadbd"
    )

    Authserver = @(
        "authserver",
        "bnetserver",
        "logonserver",
        "realmd",
        "auth"
    )

    Worldserver = @(
        "worldserver"
    )
}

# -------------------------------------------------
# Process helper
# -------------------------------------------------
function Get-ProcessSafe {
    param(
        [Parameter(Mandatory)]
        [string]$Role
    )

    if (-not $ProcessAliases.ContainsKey($Role)) {
        return $null
    }

    foreach ($name in $ProcessAliases[$Role]) {
        try {
        $proc = Get-Process -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($proc) { return $proc }
        } catch { }
    }

    return $null
}

# -------------------------------------------------
# Watchdog process state + NTFY
# -------------------------------------------------
function Send-NTFYAlert {
    param(
        [string]$ServiceName,
        [bool]$OldState,
        [bool]$NewState
    )

    # Baseline must be set
    if (-not $global:NtfyBaselineInitialized) { return }

    # Suppression window
    if ($global:NtfySuppressUntil -and (Get-Date) -lt $global:NtfySuppressUntil) { return }

    # Require server + topic
    if (-not (Get-NtfyEndpoint)) { return }

    $sendOnDown = [bool]$ChkNtfyOnDown.IsChecked
    $sendOnUp   = [bool]$ChkNtfyOnUp.IsChecked

    # DOWN event (UP -> DOWN)
    if ($OldState -eq $true -and $NewState -eq $false -and -not $sendOnDown) { return }

    # UP event (DOWN -> UP)
    if ($OldState -eq $false -and $NewState -eq $true -and -not $sendOnUp) { return }

    # Per-service enable switches
    switch ($ServiceName) {
        "MySQL"       { if (-not $ChkNtfyMySQL.IsChecked) { return } }
        "Authserver"  { if (-not $ChkNtfyAuthserver.IsChecked) { return } }
        "Worldserver" { if (-not $ChkNtfyWorldserver.IsChecked) { return } }
    }

    $exp      = Get-ExpansionLabel
    $id       = Get-WowIdentity
    $prev     = if ($OldState) { "UP" } else { "DOWN" }
    $curr     = if ($NewState) { "UP" } else { "DOWN" }
    $ts       = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    $titleState = if ($curr -eq "DOWN") { "DOWN" } else { "RECOVERED" }
    $title = "[WoW Watchdog] $ServiceName $titleState ($exp)"

    $body = @"
WoW Watchdog alert

Server: $($id.ServerName)
Host:   $($id.Hostname)
IP:     $($id.IPAddress)
Expansion: $exp

Service: $ServiceName
Previous state: $prev
New state: $curr
Timestamp: $ts
"@

    $prio = Get-NtfyPriorityForService -ServiceName $ServiceName
    $tags = Get-NtfyTags -ServiceName $ServiceName -StateTag ($curr.ToLowerInvariant())
    
    # Optional: suppress DOWN notifications if role is manually held
    if ($curr -eq "DOWN" -and (Role-IsHeld -Role $ServiceName)) {
        return
    }

    try {
        [void](Send-NtfyMessage -Title $title -Body $body -Priority $prio -TagsCsv $tags)
        Add-GuiLog "Sent NTFY notification for $ServiceName state change ($prev -> $curr)."
    } catch {
        Add-GuiLog ("ERROR: Failed to send NTFY notification for {0}: {1}" -f $ServiceName, $_)
    }
}

function Send-NTFYTest {
    if (-not (Get-NtfyEndpoint)) {
        Add-GuiLog "NTFY test failed: server or topic is empty."
        return
    }

    $exp = Get-ExpansionLabel
    $id  = Get-WowIdentity
    $ts  = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    $title = "[WoW Watchdog] Test Notification ($exp)"

    $body = @"
WoW Watchdog NTFY Test

Server: $($id.ServerName)
Host:   $($id.Hostname)
IP:     $($id.IPAddress)
Expansion: $exp
Timestamp: $ts
"@

    $prio = Get-NtfyPriorityForService -ServiceName "Test"
    # Preserve user tags but add test tag
    $tags = Get-NtfyTags -ServiceName "Test" -StateTag "test"

    try {
        [void](Send-NtfyMessage -Title $title -Body $body -Priority $prio -TagsCsv $tags)
        Add-GuiLog "Sent NTFY test notification."
    } catch {
        Add-GuiLog "ERROR: Failed to send NTFY test notification: $_"
    }
}

# -------------------------------------------------
# NTFY baseline initializer (hybrid behavior)
# -------------------------------------------------
function Initialize-NtfyBaseline {
    try {
        $global:MySqlUp  = [bool](Get-ProcessSafe "MySQL")
        $global:AuthUp   = [bool](Get-ProcessSafe "Authserver")
        $global:WorldUp  = [bool](Get-ProcessSafe "Worldserver")

        $global:NtfyBaselineInitialized = $true
        $global:NtfySuppressUntil = (Get-Date).AddSeconds(2)
    } catch {
        $global:NtfyBaselineInitialized = $false
    }
}

# -------------------------------------------------
# Polling: update LEDs + NTFY state changes
# -------------------------------------------------
function Update-ServiceStates {
    $newMySql  = [bool](Get-ProcessSafe "MySQL")
    $newAuth   = [bool](Get-ProcessSafe "Authserver")
    $newWorld  = [bool](Get-ProcessSafe "Worldserver")

    if ($newMySql -ne $global:MySqlUp) {
        Send-NTFYAlert -ServiceName "MySQL" -OldState $global:MySqlUp -NewState $newMySql
        $global:MySqlUp = $newMySql
    }
    if ($newAuth -ne $global:AuthUp) {
        Send-NTFYAlert -ServiceName "Authserver" -OldState $global:AuthUp -NewState $newAuth
        $global:AuthUp = $newAuth
    }
    if ($newWorld -ne $global:WorldUp) {
        Send-NTFYAlert -ServiceName "Worldserver" -OldState $global:WorldUp -NewState $newWorld
        $global:WorldUp = $newWorld
    }

    # Pulse (only for UP)
    $global:LedPulseFlip = -not $global:LedPulseFlip
    $g = if ($global:LedPulseFlip) { $BrushLedGreen1 } else { $BrushLedGreen2 }

    $EllipseMySQL.Fill  = if ($global:MySqlUp) { $g } else { $BrushLedRed }
    $EllipseAuth.Fill   = if ($global:AuthUp)  { $g } else { $BrushLedRed }
    $EllipseWorld.Fill  = if ($global:WorldUp) { $g } else { $BrushLedRed }
}

function Test-DbConnection {
    # Basic “can we query” test using the same mysql.exe pathway as the player count.
    $null = Get-OnlinePlayerCount_Legion
    return $true
}

# -------------------------------------------------
# Service control buttons (Hold-aware)
# -------------------------------------------------
$BtnStartMySQL.Add_Click({
    Set-RoleHold -Role "MySQL" -Held $false
    Send-WatchdogCommand "command.start.mysql"
})

$BtnStopMySQL.Add_Click({
    Set-RoleHold -Role "MySQL" -Held $true
    Send-WatchdogCommand "command.stop.mysql"
})

$BtnStartAuth.Add_Click({
    Set-RoleHold -Role "Authserver" -Held $false
    Send-WatchdogCommand "command.start.auth"
})

$BtnStopAuth.Add_Click({
    Set-RoleHold -Role "Authserver" -Held $true
    Send-WatchdogCommand "command.stop.auth"
})

$BtnStartWorld.Add_Click({
    Set-RoleHold -Role "Worldserver" -Held $false
    Send-WatchdogCommand "command.start.world"
})

$BtnStopWorld.Add_Click({
    Set-RoleHold -Role "Worldserver" -Held $true
    Send-WatchdogCommand "command.stop.world"
})

# Restart helpers (PowerShell 5.1 compatible)
function Invoke-RestartRole {
    param(
        [Parameter(Mandatory)][string]$Role,
        [Parameter(Mandatory)][string]$StopCommand,
        [Parameter(Mandatory)][string]$StartCommand
    )
    # Hold to prevent watchdog auto-restart during stop
    Set-RoleHold -Role $Role -Held $true
    Send-WatchdogCommand $StopCommand
    Start-Sleep -Seconds 2
    # Clear hold and request start
    Set-RoleHold -Role $Role -Held $false
    Send-WatchdogCommand $StartCommand
}

$BtnRestartMySQL.Add_Click({
    Invoke-RestartRole -Role "MySQL" -StopCommand "command.stop.mysql" -StartCommand "command.start.mysql"
})

$BtnRestartAuth.Add_Click({
    Invoke-RestartRole -Role "Authserver" -StopCommand "command.stop.auth" -StartCommand "command.start.auth"
})

$BtnRestartWorld.Add_Click({
    Invoke-RestartRole -Role "Worldserver" -StopCommand "command.stop.world" -StartCommand "command.start.world"
})

$BtnRestartStack.Add_Click({
    # Ordered restart: World/Auth/DB down via stop.all, then DB/Auth/World up in order
    Set-AllHolds -Held $true
    Send-WatchdogCommand "command.stop.all"
    Start-Sleep -Seconds 3
    Set-AllHolds -Held $false
    Send-WatchdogCommand "command.start.mysql"
    Send-WatchdogCommand "command.start.auth"
    Send-WatchdogCommand "command.start.world"
})


$BtnStartAll.Add_Click({
    # clear holds so ordered startup can proceed
    Set-AllHolds -Held $false

    # ordered start commands (watchdog enforces gating)
    Send-WatchdogCommand "command.start.mysql"
    Send-WatchdogCommand "command.start.auth"
    Send-WatchdogCommand "command.start.world"
})

$BtnStopAll.Add_Click({
    # apply holds before graceful shutdown
    Set-AllHolds -Held $true
    Send-WatchdogCommand "command.stop.all"
})

$BtnClearLog.Add_Click({
    try {
        # Clear UI
        $TxtLiveLog.Clear()

        # Clear file (preserve file existence)
        Set-Content -Path $LogPath -Value "" -Encoding UTF8 -Force

        Add-GuiLog "Log cleared."
    } catch {
        Add-GuiLog "ERROR: Failed to clear log: $_"
    }
})

$BtnTestDb.Add_Click({
    try {
        $ok = Test-DbConnection
        if ($ok) {
            Add-GuiLog "DB test succeeded (able to query characters.online)."
        }
    } catch {
        Add-GuiLog "ERROR: DB test failed: $_"
    }
})

$BtnSaveDbPassword.Add_Click({
    try {
        $pw = ""
        try { $pw = [string]$TxtDbPassword.Password } catch { $pw = "" }

        if ([string]::IsNullOrWhiteSpace($pw)) {
            Remove-DbSecretPassword
            Add-GuiLog "DB password removed from secrets store (blank)."
        } else {
            Set-DbSecretPassword -Plain $pw
            Add-GuiLog "DB password saved to secrets store (DPAPI)."
        }

        # Clear the box after save so it doesn't linger
        try { $TxtDbPassword.Password = "" } catch { }
    } catch {
        Add-GuiLog "ERROR: Failed saving DB password: $_"
    }
})

$BtnUpdateNow.Add_Click({

    $worker = New-Object System.ComponentModel.BackgroundWorker
    $worker.WorkerReportsProgress = $false

    $worker.add_DoWork({
        param($sender, $e)
        try {
            Set-UpdateButtonsEnabled -Enabled $false
            Set-UpdateFlowUi -Text "Preparing update." -Percent 0 -Show $true -Indeterminate $true

            # Reuse your repo settings
            $Owner = $RepoOwner
            $Repo  = $RepoName

            # Pull latest release
            Set-UpdateFlowUi -Text "Fetching latest release." -Percent 0 -Show $true -Indeterminate $true
            $rel = Get-LatestGitHubRelease -Owner $Owner -Repo $Repo
            
            # Find expected asset
            $asset = $rel.assets | Where-Object { $_.name -eq "WoWWatchdog-Setup.exe" } | Select-Object -First 1
            if (-not $asset) {
                $names = @()
                if ($rel.assets) { $names = $rel.assets | ForEach-Object { $_.name } }
                throw "Could not find WoWWatchdog-Setup.exe in latest release. Found: $($names -join ', ')"
            }

            # Step 1: Gracefully stop service
            Set-UpdateFlowUi -Text "Stopping WoWWatchdog service (graceful)." -Percent 0 -Show $true -Indeterminate $true
            try {
                [void](Stop-ServiceAndWait -Name $ServiceName -TimeoutSeconds 45)
            } catch {
                # If stop fails, abort update (safer than updating binaries mid-run)
                throw "Failed to stop service safely. $($_.Exception.Message)"
            }

            # Step 2: Download installer with progress
            $tempInstaller = Join-Path $env:TEMP "WoWWatchdog-Setup.exe"
            [void](Download-FileWithProgress -Url $asset.browser_download_url -OutFile $tempInstaller)

            # Optional sanity check on size (avoid HTML/403 pages)
            $fi = Get-Item $tempInstaller -ErrorAction Stop
            if ($fi.Length -lt 200000) { # 200KB floor, tune if needed
                throw "Downloaded installer is unexpectedly small ($($fi.Length) bytes). Aborting."
            }

            # Step 3: Run installer
            [void](Run-InstallerAndWait -InstallerPath $tempInstaller)

            # Step 4: Prompt restart actions on UI thread
            $Window.Dispatcher.Invoke([action]{
                Set-UpdateFlowUi -Text "Update installed." -Percent 100 -Show $true -Indeterminate $false

                $restartSvc = [System.Windows.MessageBox]::Show(
                    "Update installed successfully.`n`nRestart the WoWWatchdog service now?",
                    "Update Complete",
                    [System.Windows.MessageBoxButton]::YesNo,
                    [System.Windows.MessageBoxImage]::Question
                )

                if ($restartSvc -eq [System.Windows.MessageBoxResult]::Yes) {
                    try {
                        Set-UpdateFlowUi -Text "Starting WoWWatchdog service." -Percent 100 -Show $true -Indeterminate $true
                        Start-ServiceAndWait -Name $ServiceName -TimeoutSeconds 30 | Out-Null
                        Add-GuiLog "Service restarted after update."
                    } catch {
                        Add-GuiLog "ERROR: Service restart failed: $_"
                        [System.Windows.MessageBox]::Show(
                            "Update installed, but service restart failed:`n$($_.Exception.Message)",
                            "Service Restart Failed",
                            "OK",
                            "Error"
                        ) | Out-Null
                    }
                }

                $restartGui = [System.Windows.MessageBox]::Show(
                    "Restart the GUI now to ensure all updated files are loaded?",
                    "Restart Recommended",
                    [System.Windows.MessageBoxButton]::YesNo,
                    [System.Windows.MessageBoxImage]::Question
                )

                if ($restartGui -eq [System.Windows.MessageBoxResult]::Yes) {
                    try {
                        # Relaunch same executable (works if packaged as exe)
                        Start-Process -FilePath $ExePath -WorkingDirectory $ScriptDir | Out-Null
                        $Window.Close()
                    } catch {
                        Add-GuiLog "ERROR: Failed to relaunch GUI: $_"
                    }
                }

                Set-UpdateButtonsEnabled -Enabled $true
                Set-UpdateFlowUi -Text "Ready." -Percent 0 -Show $false
            })
        }
        catch {
            $errMsg = $_.Exception.Message
            $Window.Dispatcher.Invoke([action]{
                Set-UpdateButtonsEnabled -Enabled $true
                Set-UpdateFlowUi -Text ("Update failed: " + $errMsg) -Percent 0 -Show $true -Indeterminate $false

                [System.Windows.MessageBox]::Show(
                    $errMsg,
                    "Update Failed",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Error
                ) | Out-Null
            })
        }
    
    })

    $worker.RunWorkerAsync()
})

$BtnMinimize.Add_Click({ $Window.WindowState = 'Minimized' })
$BtnClose.Add_Click({ $Window.Close() })

$BtnBrowseMySQL.Add_Click({
    $f = Pick-File "Batch files (*.bat)|*.bat|All files (*.*)|*.*"
    if ($f) { $TxtMySQL.Text = $f }
})

$BtnBrowseAuth.Add_Click({
    $f = Pick-File "Executables (*.exe)|*.exe|All files (*.*)|*.*"
    if ($f) { $TxtAuth.Text = $f }
})

$BtnBrowseWorld.Add_Click({
    $f = Pick-File "Executables (*.exe)|*.exe|All files (*.*)|*.*"
    if ($f) { $TxtWorld.Text = $f }
})

$BtnSaveConfig.Add_Click({
    # Resolve expansion value
    $expSel = $CmbExpansion.SelectedItem
    $expVal = if ($expSel) { [string]$expSel.Content } else { "Unknown" }
    if ($expVal -eq "Custom") {
        $expVal = $TxtExpansionCustom.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($expVal)) { $expVal = "Custom" }
    }

    # Resolve Auth Mode selection
$authMode = "None"
try {
    $sel = $CmbNtfyAuthMode.SelectedItem
    if ($sel -and $sel.Content) { $authMode = [string]$sel.Content }
} catch { }

# Persist secrets (DPAPI) based on selected mode
# IMPORTANT: Password/Token boxes are intentionally blank on startup.
# If the user does not type a new value, we KEEP the previously stored secret.
try {
if ($authMode -eq "Basic (User/Pass)") {
    $plainPw = ""
    try { $plainPw = $TxtNtfyPassword.Password } catch { $plainPw = "" }

    # Only overwrite stored secret if user supplied a new value
    if (-not [string]::IsNullOrWhiteSpace($plainPw)) {
        Set-NtfySecret -Kind "BasicPassword" -Plain $plainPw
    }

    # Do not delete Token automatically; keep it in case the user switches modes later
}
elseif ($authMode -eq "Bearer Token") {
    $plainToken = ""
    try { $plainToken = $TxtNtfyToken.Password } catch { $plainToken = "" }

    # Only overwrite stored secret if user supplied a new value
    if (-not [string]::IsNullOrWhiteSpace($plainToken)) {
        Set-NtfySecret -Kind "Token" -Plain $plainToken
    }

    # Do not delete BasicPassword automatically; keep it in case the user switches modes later
}
else {
    # None: keep any stored secrets (do not delete automatically)
}
} catch { }

# Priority parsing helpers
    function Get-ComboContentIntOrZero {
        param([System.Windows.Controls.ComboBox]$Combo)
        $item = $Combo.SelectedItem
        if (-not $item) { return 0 }
        $c = [string]$item.Content
        if ($c -eq "Auto") { return 0 }
        $n = 0
        if ([int]::TryParse($c, [ref]$n)) { return $n }
        return 0
    }

    $prioDefault = Get-ComboContentIntOrZero $CmbNtfyPriorityDefault
    if ($prioDefault -lt 1 -or $prioDefault -gt 5) { $prioDefault = 4 }

    # DB fields from UI
$dbHostName = [string]$TxtDbHost.Text
if ([string]::IsNullOrWhiteSpace($dbHostName)) { $dbHostName = "127.0.0.1" }

$dbPortNum = 3306
try { $dbPortNum = [int]([string]$TxtDbPort.Text) } catch { $dbPortNum = 3306 }

$dbUserName = [string]$TxtDbUser.Text
if ([string]::IsNullOrWhiteSpace($dbUserName)) { $dbUserName = "root" }

$dbNameChars = [string]$TxtDbNameChar.Text
if ([string]::IsNullOrWhiteSpace($dbNameChars)) { $dbNameChars = "legion_characters" }

    
    # Worldserver Telnet fields from UI
    $telHost = ($TxtWorldTelnetHost.Text + "").Trim()
    if ([string]::IsNullOrWhiteSpace($telHost)) { $telHost = "127.0.0.1" }

    $telPort = 3443
    try { $telPort = [int]([string]$TxtWorldTelnetPort.Text) } catch { $telPort = 3443 }
    if (-not $telPort) { $telPort = 3443 }

    $telUser = ($TxtWorldTelnetUser.Text + "").Trim()

    # Telnet password (DPAPI secret): only overwrite if user typed a new value
    try {
        $plainTelPw = ""
        try { $plainTelPw = $TxtWorldTelnetPassword.Password } catch { $plainTelPw = "" }

        if (-not [string]::IsNullOrWhiteSpace($plainTelPw)) {
            Set-WorldTelnetPassword -TelnetHost $telHost -Port $telPort -Username $telUser -Plain $plainTelPw
            try { $TxtWorldTelnetPassword.Password = "" } catch { }
        }
    } catch { }

$cfg = [pscustomobject]@{
        ServerName  = $Config.ServerName
        Expansion   = $expVal

        MySQL       = $TxtMySQL.Text
        MySQLExe    = $TxtMySQLExe.Text
        Authserver  = $TxtAuth.Text
        Worldserver = $TxtWorld.Text
        WorldTelnetHost = $telHost
        WorldTelnetPort = $telPort
        WorldTelnetUser = $telUser
        WorldserverLogPath = ($TxtWorldLogPath.Text + "").Trim()
        RepackRoot = ($TxtRepackRoot.Text + "").Trim()

        DbBackupFolder = ($TxtDbBackupFolder.Text + "").Trim()
        RepackBackupFolder = ($TxtRepackBackupDest.Text + "").Trim()
        DbHost      = $dbHostName
        DbPort      = $dbPortNum
        DbUser      = $dbUserName
        DbNameChar  = $dbNameChars


        NTFY = [pscustomobject]@{
            Server            = $TxtNtfyServer.Text
            Topic             = $TxtNtfyTopic.Text
            Tags              = $TxtNtfyTags.Text

            AuthMode          = $authMode
            Username          = $TxtNtfyUsername.Text
            Password          = ""
            Token             = ""

            PriorityDefault   = $prioDefault

            EnableMySQL       = [bool]$ChkNtfyMySQL.IsChecked
            EnableAuthserver  = [bool]$ChkNtfyAuthserver.IsChecked
            EnableWorldserver = [bool]$ChkNtfyWorldserver.IsChecked

            ServicePriorities = [pscustomobject]@{
                MySQL       = (Get-ComboContentIntOrZero $CmbPriMySQL)
                Authserver  = (Get-ComboContentIntOrZero $CmbPriAuthserver)
                Worldserver = (Get-ComboContentIntOrZero $CmbPriWorldserver)
            }

            SendOnDown        = [bool]$ChkNtfyOnDown.IsChecked
            SendOnUp          = [bool]$ChkNtfyOnUp.IsChecked
        }
    }

    $cfg | ConvertTo-Json -Depth 6 | Set-Content -Path $ConfigPath -Encoding UTF8
    Add-GuiLog "Configuration saved."

    # Refresh runtime config (so alerts pick up changes without restart)
    $global:Config = $cfg
    $script:Config = $cfg
    $Config = $cfg

    # Refresh Telnet tab label + stored-password indicator without restart
    try { $TxtTelnetTarget.Text = ("{0}:{1}" -f [string]$cfg.WorldTelnetHost, [string]$cfg.WorldTelnetPort) } catch { }
    try { Update-WorldTelnetPasswordStatus } catch { }
})


# -------------------------------------------------
# Worldserver Telnet Console (embedded)
# -------------------------------------------------
$script:TelnetClient        = $null
$script:TelnetStream        = $null
$script:TelnetConnected     = $false
$script:TelnetStopRequested = $false

# Timer-based (UI-thread) connect/read loops for PS2EXE compatibility (no background thread scriptblocks)
$script:TelnetConnectTimer  = $null
$script:TelnetReadTimer     = $null
$script:TelnetLoginTimer    = $null
$script:TelnetConnectState  = $null


function Set-TelnetStatus {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][System.Windows.Media.Brush]$Brush
    )
    try {
        $LblTelnetStatus.Text = $Text
        $LblTelnetStatus.Foreground = $Brush
    } catch { }
}

function Update-TelnetUiState {
    param(
        [bool]$Connected,
        [bool]$Connecting
    )

    try {
        $BtnTelnetConnect.IsEnabled    = (-not $Connected) -and (-not $Connecting)
        $BtnTelnetDisconnect.IsEnabled = ($Connected -or $Connecting)
        $BtnTelnetSend.IsEnabled       = $Connected
        $TxtTelnetCommand.IsEnabled    = $Connected
    } catch { }
}

function Append-TelnetOutput {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return }

    try {
        # In this build, Telnet timers and handlers run on the UI thread.
        # Avoid Dispatcher.BeginInvoke scriptblock callbacks (can lack a runspace under PS2EXE).
        if ($TxtTelnetOutput -and $TxtTelnetOutput.Dispatcher -and (-not $TxtTelnetOutput.Dispatcher.CheckAccess())) {
            $TxtTelnetOutput.Dispatcher.Invoke([System.Action]{
                try {
                    $TxtTelnetOutput.AppendText($Text)
                    $TxtTelnetOutput.ScrollToEnd()
                } catch { }
            })
        } else {
            $TxtTelnetOutput.AppendText($Text)
            $TxtTelnetOutput.ScrollToEnd()
        }
    } catch {
        try {
            Add-GuiLog ("ERROR: Telnet output update failed: {0}" -f $_.Exception.Message)
        } catch { }
    }
}

# -------------------------------------------------
# Worldserver Log Tail (optional, shows live output by tailing a log file)
# Note: The Telnet RA console typically does NOT stream the worldserver stdout feed.
# This tail provides a live-ish view by reading the server's log file.
# -------------------------------------------------
$script:WorldLogTailTimer    = $null
$script:WorldLogTailTimer  = $null
$script:WorldLogTailStream = $null
$script:WorldLogTailReader = $null
$script:WorldLogTailPos    = 0L
$script:WorldLogTailPath   = ""

function Append-WorldLogOutput {
    param([string]$Text)

    if ([string]::IsNullOrEmpty($Text) -or -not $TxtWorldLogOutput) { return }

    try {
        # Ensure CRLF so output is readable even if source uses LF
        $t = $Text -replace "`r?`n", "`r`n"
        $TxtWorldLogOutput.AppendText($t)
        $TxtWorldLogOutput.ScrollToEnd()
    } catch {
        try { Add-GuiLog ("ERROR: World log append failed: {0}" -f $_.Exception.Message) } catch { }
    }
}

function Resolve-WorldserverLogPath {
    # Prefer explicit textbox path; fall back to config; finally fall back to common defaults
    $p = ""
    try { $p = ([string]$TxtWorldLogPath.Text).Trim() } catch { $p = "" }

    if ([string]::IsNullOrWhiteSpace($p)) {
        try { $p = ([string]$Config.WorldserverLogPath).Trim() } catch { $p = "" }
    }

    if (-not [string]::IsNullOrWhiteSpace($p)) {
        try {
            if (Test-Path -LiteralPath $p) { return $p }
        } catch { }
    }

    # Heuristics (only if repack root is set)
    $root = ""
    try { $root = ([string]$TxtRepackRoot.Text).Trim() } catch { $root = "" }
    if (-not [string]::IsNullOrWhiteSpace($root) -and (Test-Path -LiteralPath $root)) {
        $candidates = @(
            (Join-Path $root "worldserver.log"),
            (Join-Path $root "logs\worldserver.log"),
            (Join-Path $root "Logs\worldserver.log"),
            (Join-Path $root "worldserver\worldserver.log")
        )
        foreach ($c in $candidates) {
            try { if (Test-Path -LiteralPath $c) { return $c } } catch { }
        }
    }

    return ""
}

function Stop-WorldLogTail {
    try {
        if ($script:WorldLogTailTimer) { $script:WorldLogTailTimer.Stop() }
    } catch { }

    try { if ($script:WorldLogTailReader) { $script:WorldLogTailReader.Dispose() } } catch { }
    try { if ($script:WorldLogTailStream) { $script:WorldLogTailStream.Dispose() } } catch { }

    $script:WorldLogTailReader = $null
    $script:WorldLogTailStream = $null
    $script:WorldLogTailPos    = 0L
    $script:WorldLogTailPath   = ""
}

function WorldLogTail-Tick {
    if (-not $script:WorldLogTailStream -or -not $script:WorldLogTailReader) { return }

    try {
        $fs = $script:WorldLogTailStream
        $sr = $script:WorldLogTailReader

        $len = 0L
        try { $len = $fs.Length } catch { $len = 0L }

        # Handle truncation / rotation
        if ($len -lt $script:WorldLogTailPos) {
            $script:WorldLogTailPos = 0L
            Append-WorldLogOutput "`r`n[World log] Log was truncated/rotated; restarting from beginning.`r`n"
        }

        $backlog = $len - $script:WorldLogTailPos
        if ($backlog -le 0) { return }

        # Safety: if we fell behind badly, jump near the end to keep UI responsive
        if ($backlog -gt 2097152) {
            $jump = 131072
            $script:WorldLogTailPos = [math]::Max(0L, $len - $jump)
            Append-WorldLogOutput ("`r`n[World log] Large backlog detected ({0:N0} bytes). Jumping near end...`r`n" -f $backlog)
        }

        # Seek and read newly appended content (StreamReader handles encoding/BOM correctly)
        $sr.DiscardBufferedData()
        [void]$fs.Seek($script:WorldLogTailPos, [System.IO.SeekOrigin]::Begin)

        $newText = $sr.ReadToEnd()
        $script:WorldLogTailPos = $fs.Position

        if (-not [string]::IsNullOrEmpty($newText)) {
            Append-WorldLogOutput $newText
        }
    } catch {
        try {
            Add-GuiLog ("ERROR: World log tail read failed: {0}" -f $_.Exception.Message)
            Append-WorldLogOutput ("`r`n[World log] ERROR: Tail read failed: {0}`r`n" -f $_.Exception.Message)
        } catch { }
        try { Stop-WorldLogTail } catch { }
    }
}

function Start-WorldLogTail {
    param([switch]$StartAtEnd)

    # Restart from scratch
    Stop-WorldLogTail

    $p = Resolve-WorldserverLogPath
    if ([string]::IsNullOrWhiteSpace($p)) {
        Append-WorldLogOutput "`r`n[World log] No log file selected.`r`n"
        return
    }

    if (-not (Test-Path -LiteralPath $p)) {
        Append-WorldLogOutput ("`r`n[World log] Log file not found: {0}`r`n" -f $p)
        return
    }

    try {
        # Keep the file open with sharing so the worldserver can continue writing
        $fs = New-Object System.IO.FileStream($p, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8, $true)  # detect BOM

        $script:WorldLogTailStream = $fs
        $script:WorldLogTailReader = $sr
        $script:WorldLogTailPath   = $p

        $len = 0L
        try { $len = $fs.Length } catch { $len = 0L }

        if ($StartAtEnd) {
            $script:WorldLogTailPos = $len
            Append-WorldLogOutput ("`r`n[World log] Tailing: {0} (from end)`r`n" -f $p)
        } else {
            # Show last ~128KB so the user sees context immediately
            $window = 131072L
            $start = 0L
            if ($len -gt $window) { $start = $len - $window }
            $script:WorldLogTailPos = $start
            Append-WorldLogOutput ("`r`n[World log] Tailing: {0} (showing recent output)`r`n" -f $p)
            WorldLogTail-Tick
        }

        if (-not $script:WorldLogTailTimer) {
            $t = New-Object System.Windows.Threading.DispatcherTimer
            $t.Interval = [TimeSpan]::FromMilliseconds(500)
            $t.add_Tick({ WorldLogTail-Tick })
            $script:WorldLogTailTimer = $t
        }

        $script:WorldLogTailTimer.Start()
    } catch {
        try {
            Add-GuiLog ("ERROR: World log tail start failed: {0}" -f $_.Exception.Message)
            Append-WorldLogOutput ("`r`n[World log] ERROR: Tail start failed: {0}`r`n" -f $_.Exception.Message)
        } catch { }
        try { Stop-WorldLogTail } catch { }
    }
}

function Find-VisualParentButton {
    param($Obj)

    try {
        $cur = $Obj
        while ($null -ne $cur) {

            if ($cur -is [System.Windows.Controls.Button]) { return $cur }

            # Prefer framework parent pointers (works for many non-Visual elements too)
            if ($cur -is [System.Windows.FrameworkElement] -and $cur.Parent) {
                $cur = $cur.Parent
                continue
            }
            if ($cur -is [System.Windows.FrameworkContentElement] -and $cur.Parent) {
                $cur = $cur.Parent
                continue
            }

            # Visual tree parent (only valid for Visual / Visual3D)
            if (($cur -is [System.Windows.Media.Visual]) -or ($cur -is [System.Windows.Media.Media3D.Visual3D])) {
                $p = $null
                try { $p = [System.Windows.Media.VisualTreeHelper]::GetParent($cur) } catch { $p = $null }
                if ($p) { $cur = $p; continue }
            }

            # Logical tree parent fallback (handles Run/TextElement cases)
            $p2 = $null
            try { $p2 = [System.Windows.LogicalTreeHelper]::GetParent($cur) } catch { $p2 = $null }
            if ($p2) { $cur = $p2; continue }

            break
        }
    } catch { }

    return $null
}


function Browse-WorldLogPath {
    try {
        # Use WPF/Win32 dialog (same pattern as the other Browse buttons).
        try { Add-GuiLog "[World log] Browse clicked..." } catch { }
        try { Append-WorldLogOutput "[World log] Browse clicked...`r`n" } catch { }

        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Title  = "Select Worldserver Log File"
        $dlg.Filter = "Log files (*.log;*.txt)|*.log;*.txt|All files (*.*)|*.*"
        $dlg.CheckFileExists = $true
        $dlg.Multiselect = $false

        # Start near worldserver exe dir if available, else near last selected log path.
        $initDir = $null
        try {
            $ws = ([string]$Config.Worldserver + "").Trim()
            if (-not [string]::IsNullOrWhiteSpace($ws) -and (Test-Path -LiteralPath $ws)) {
                $initDir = (Split-Path -Parent $ws)
            }
        } catch { }

        if (-not $initDir) {
            try {
                $p = ([string]$Config.WorldserverLogPath + "").Trim()
                if (-not [string]::IsNullOrWhiteSpace($p) -and (Test-Path -LiteralPath $p)) {
                    $initDir = (Split-Path -Parent $p)
                }
            } catch { }
        }

        if ($initDir -and (Test-Path -LiteralPath $initDir)) {
            $dlg.InitialDirectory = $initDir
        }

        $ok = $false
        try { $ok = $dlg.ShowDialog($Window) } catch { $ok = $dlg.ShowDialog() }

        if ($ok -eq $true) {
            $file = ([string]$dlg.FileName + "").Trim()
            if (-not [string]::IsNullOrWhiteSpace($file)) {
                try { $TxtWorldLogPath.Text = $file } catch { }
                try { $Config.WorldserverLogPath = $file } catch { }
                try { Append-WorldLogOutput ("[World log] Selected: {0}`r`n" -f $file) } catch { }

                # Start tail immediately for the selected file
try {
    if ($ChkWorldLogTail) { $ChkWorldLogTail.IsChecked = $true }
    Start-WorldLogTail
} catch { }
            }
        }
    } catch {
        $em = $_.Exception.Message
        try { Append-WorldLogOutput ("[World log] ERROR: Browse failed: {0}`r`n" -f $em) } catch { }
        try { Add-GuiLog ("ERROR: World log browse failed: {0}" -f $em) } catch { }
    }
}

function Get-TelnetTargetFromUiOrConfig {
    # Prefer persisted config first (prevents default textbox values overriding saved settings on fresh launch)
    $h = ""
    $p = 3443

    try { $h = ([string]$Config.WorldTelnetHost).Trim() } catch { $h = "" }
    if ([string]::IsNullOrWhiteSpace($h)) {
        try { $h = ($TxtWorldTelnetHost.Text + "").Trim() } catch { $h = "" }
    }
    if ([string]::IsNullOrWhiteSpace($h)) { $h = "127.0.0.1" }

    try { $p = [int]$Config.WorldTelnetPort } catch { $p = 0 }
    if (-not $p) {
        try { $p = [int]([string]$TxtWorldTelnetPort.Text) } catch { $p = 0 }
    }
    if (-not $p) { $p = 3443 }

    return @{ Host = $h; Port = $p }
}

function Get-TelnetCredentialsFromUiOrSecrets {
    param(
        [Parameter(Mandatory)][string]$telnetHost,
        [Parameter(Mandatory)][int]$Port
    )

    $u = ""
    try { $u = ($TxtWorldTelnetUser.Text + "").Trim() } catch { $u = "" }
    if ([string]::IsNullOrWhiteSpace($u)) {
        try { $u = ([string]$Config.WorldTelnetUser).Trim() } catch { $u = "" }
    }

    # Prefer a password typed in the UI (even if not saved yet)
    $pw = ""
    try { $pw = [string]$TxtWorldTelnetPassword.Password } catch { $pw = "" }

    if ([string]::IsNullOrWhiteSpace($pw)) {
        try { $pw = Get-WorldTelnetPassword -TelnetHost $telnetHost -Port $Port -Username $u } catch { $pw = "" }
    }

    return @{ Username = $u; Password = $pw }
}

function Convert-TelnetBytesToText {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Count
    )

    # Handle a small subset of Telnet negotiation to prevent junk characters in the output.
    $out = New-Object System.Collections.Generic.List[byte]
    $i = 0

    while ($i -lt $Count) {
        $b = $Bytes[$i]

        if ($b -eq 255) { # IAC
            if (($i + 1) -ge $Count) { break }

            $cmd = $Bytes[$i + 1]

            # Escaped IAC (IAC IAC)
            if ($cmd -eq 255) {
                $out.Add(255) | Out-Null
                $i += 2
                continue
            }

            # WILL/WONT/DO/DONT
            if (($cmd -eq 251) -or ($cmd -eq 252) -or ($cmd -eq 253) -or ($cmd -eq 254)) {
                if (($i + 2) -ge $Count) { break }
                $opt = $Bytes[$i + 2]

                # Reply: refuse options (safe default)
                $respCmd = 0
                if (($cmd -eq 253) -or ($cmd -eq 254)) {
                    # DO/DONT -> WONT
                    $respCmd = 252
                } else {
                    # WILL/WONT -> DONT
                    $respCmd = 254
                }

                try {
                    if ($script:TelnetStream) {
                        $resp = [byte[]](255, $respCmd, $opt)
                        $script:TelnetStream.Write($resp, 0, $resp.Length)
                    }
                } catch { }

                $i += 3
                continue
            }

            # SB (subnegotiation): skip until IAC SE
            if ($cmd -eq 250) {
                $i += 2
                while ($i -lt ($Count - 1)) {
                    if (($Bytes[$i] -eq 255) -and ($Bytes[$i + 1] -eq 240)) {
                        $i += 2
                        break
                    }
                    $i++
                }
                continue
            }

            # Other: skip IAC + cmd
            $i += 2
            continue
        }

        $out.Add($b) | Out-Null
        $i++
    }

    try { return [System.Text.Encoding]::ASCII.GetString($out.ToArray()) }
    catch { return "" }
}

function Disconnect-WorldTelnet {
    param([switch]$Silent)

    $script:TelnetStopRequested = $true

    # Stop timer-based loops and clear any pending connect state
    try { Stop-TelnetTimers } catch { }
    $script:TelnetConnectState = $null
    $script:TelnetPendingPassword = $null

    try { if ($script:TelnetStream) { $script:TelnetStream.Close() } } catch { }
    try { if ($script:TelnetClient) { $script:TelnetClient.Close() } } catch { }

    $script:TelnetStream = $null
    $script:TelnetClient = $null
    $script:TelnetConnected = $false

    Update-TelnetUiState -Connected $false -Connecting $false
    Set-TelnetStatus -Text "Disconnected" -Brush ([System.Windows.Media.Brushes]::Gold)
Append-TelnetOutput "[Console ready] Click Connect to begin.\r\n"

    if (-not $Silent) {
        Append-TelnetOutput "`r`n[Disconnected]`r`n"
    }
}


function Stop-TelnetTimers {
    # Runs on UI thread; safe for PS2EXE. Stops any active Telnet timers.
    try { if ($script:TelnetConnectTimer) { $script:TelnetConnectTimer.Stop() } } catch { }
    try { if ($script:TelnetReadTimer)    { $script:TelnetReadTimer.Stop() } } catch { }
    try { if ($script:TelnetLoginTimer)   { $script:TelnetLoginTimer.Stop() } } catch { }
    $script:TelnetLoginTimer = $null
}

function Start-TelnetReadLoop {
    try {
        if (-not $script:TelnetConnected -or -not $script:TelnetStream) { return }

        if (-not $script:TelnetReadTimer) {
            $t = New-Object System.Windows.Threading.DispatcherTimer
            $t.Interval = [TimeSpan]::FromMilliseconds(150)
            $t.add_Tick({ Telnet-ReadTick })
            $script:TelnetReadTimer = $t
        }

        $script:TelnetReadTimer.Start()
    } catch {
        Add-GuiLog ("ERROR: Telnet read loop failed: {0}" -f $_.Exception.Message)
        Disconnect-WorldTelnet -Silent
    }
}

function Telnet-ReadTick {
    # UI-thread polling read loop (avoids BackgroundWorker/runspace issues in PS2EXE)
    if ($script:TelnetStopRequested) { return }
    if (-not $script:TelnetConnected -or -not $script:TelnetStream) {
        try { if ($script:TelnetReadTimer) { $script:TelnetReadTimer.Stop() } } catch { }
        return
    }

    $buf = New-Object byte[] 4096
    $loops = 0

    try {
        while ($loops -lt 20) {
            if (-not $script:TelnetStream) { break }
            if (-not $script:TelnetStream.DataAvailable) { break }

            $read = $script:TelnetStream.Read($buf, 0, $buf.Length)
            if ($read -le 0) {
                Append-TelnetOutput "`r`n[Connection closed]`r`n"
                Disconnect-WorldTelnet -Silent
                return
            }

            $chunk = Convert-TelnetBytesToText -Bytes $buf -Count $read
            if (-not [string]::IsNullOrEmpty($chunk)) {
                Append-TelnetOutput $chunk
            }

            $loops++
        }
    } catch {
        Add-GuiLog ("ERROR: Telnet read error: {0}" -f $_.Exception.Message)
        Disconnect-WorldTelnet -Silent
    }
}

function Telnet-ConnectFail {
    param([Parameter(Mandatory)][string]$Message)

    # Auto-retry: if user entered 127.0.0.1, try localhost once (common IPv6-only bind)
    try {
        $st = $script:TelnetConnectState
        if ($st -and ($st.Host -eq '127.0.0.1') -and (-not $st.TriedLocalhostRetry)) {
            Add-GuiLog "INFO: IPv4 loopback connect failed; retrying localhost (IPv6 loopback)..."

            try { $TxtTelnetTarget.Text = ("localhost:{0}" -f $st.Port) } catch { }
            try { Append-TelnetOutput ("[Retrying localhost:{0}]`r`n" -f $st.Port) } catch { }

            try { if ($script:TelnetConnectTimer) { $script:TelnetConnectTimer.Stop() } } catch { }

            try { if ($st.Client) { $st.Client.Close() } } catch { }

            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $client.BeginConnect('localhost', [int]$st.Port, $null, $null)

            $st.Client = $client
            $st.Iar = $iar
            $st.Started = Get-Date
            $st.Host = 'localhost'
            $st.TriedLocalhostRetry = $true

            $script:TelnetConnectState = $st

            if (-not $script:TelnetConnectTimer) {
                $t = New-Object System.Windows.Threading.DispatcherTimer
                $t.Interval = [TimeSpan]::FromMilliseconds(150)
                $t.add_Tick({ Telnet-ConnectTick })
                $script:TelnetConnectTimer = $t
            }

            try { $script:TelnetConnectTimer.Start() } catch { }

            Update-TelnetUiState -Connected $false -Connecting $true
            Set-TelnetStatus -Text "Connecting..." -Brush ([System.Windows.Media.Brushes]::Gold)
            return
        }
    } catch { }

    try { if ($script:TelnetConnectTimer) { $script:TelnetConnectTimer.Stop() } } catch { }

    # Clean up any pending client
    try {
        if ($script:TelnetConnectState -and $script:TelnetConnectState.Client) {
            $script:TelnetConnectState.Client.Close()
        }
    } catch { }

    $script:TelnetConnectState = $null

    Add-GuiLog ("ERROR: Telnet connect failed: {0}" -f $Message)
    Update-TelnetUiState -Connected $false -Connecting $false
    Set-TelnetStatus -Text "Connect failed" -Brush ([System.Windows.Media.Brushes]::Tomato)
}


function Telnet-ConnectTick {
    # UI-thread connect completion poller
    if ($script:TelnetStopRequested) {
        try { if ($script:TelnetConnectTimer) { $script:TelnetConnectTimer.Stop() } } catch { }
        try {
            if ($script:TelnetConnectState -and $script:TelnetConnectState.Client) {
                $script:TelnetConnectState.Client.Close()
            }
        } catch { }
        $script:TelnetConnectState = $null
        return
    }

    $st = $script:TelnetConnectState
    if (-not $st) {
        try { if ($script:TelnetConnectTimer) { $script:TelnetConnectTimer.Stop() } } catch { }
        return
    }

    try {
        $elapsedMs = (New-TimeSpan -Start $st.Started -End (Get-Date)).TotalMilliseconds
        if ($elapsedMs -gt 5000) {
            Telnet-ConnectFail -Message ("Connection timed out to {0}:{1}" -f $st.Host, $st.Port)
            return
        }

        if ($st.Iar -and $st.Iar.AsyncWaitHandle -and $st.Iar.AsyncWaitHandle.WaitOne(0, $false)) {
            try { if ($script:TelnetConnectTimer) { $script:TelnetConnectTimer.Stop() } } catch { }
try { $st.Client.EndConnect($st.Iar) } catch {
                $msg = $_.Exception.Message
                try {
                    if ($_.Exception.InnerException -and $_.Exception.InnerException.Message) {
                        $msg = $_.Exception.InnerException.Message
                    }
                } catch { }
                Telnet-ConnectFail -Message $msg
                return
            }

            if (-not $st.Client.Connected) {
                Telnet-ConnectFail -Message ("Unable to connect to {0}:{1}" -f $st.Host, $st.Port)
                return
            }

            $stream = $st.Client.GetStream()
            $stream.ReadTimeout  = 1000
            $stream.WriteTimeout = 1000

            $script:TelnetClient    = $st.Client
            $script:TelnetStream    = $stream
            $script:TelnetConnected = $true

            $script:TelnetConnectState = $null

            Update-TelnetUiState -Connected $true -Connecting $false
            Set-TelnetStatus -Text "Connected" -Brush ([System.Windows.Media.Brushes]::LimeGreen)

            Append-TelnetOutput "[Connected] Auto-login...`r`n"

            # Auto-login: send username now; password shortly after (if present)
            try {
                if (-not [string]::IsNullOrWhiteSpace($st.Username)) {
                    Send-WorldTelnetLine -Line $st.Username -NoEcho
                }
            } catch { }

            try {
                if (-not [string]::IsNullOrWhiteSpace($st.Password)) {
                    # one-shot timer (300ms) to send password, without echoing
                    $pw = [string]$st.Password

                    if (-not $script:TelnetLoginTimer) {
                        $lt = New-Object System.Windows.Threading.DispatcherTimer
                        $lt.Interval = [TimeSpan]::FromMilliseconds(300)
                        $lt.add_Tick({
                            try { $script:TelnetLoginTimer.Stop() } catch { }
                            try { Send-WorldTelnetLine -Line $script:TelnetPendingPassword -NoEcho } catch { }
                            $script:TelnetPendingPassword = $null
                        })
                        $script:TelnetLoginTimer = $lt
                    }

                    $script:TelnetPendingPassword = $pw
                    $script:TelnetLoginTimer.Start()
                }
            } catch { }

            # Start read loop (UI-thread polling)
            Start-TelnetReadLoop
        }
    } catch {
        $msg = $_.Exception.Message
        try {
            if ($_.Exception.InnerException -and $_.Exception.InnerException.Message) {
                $msg = $_.Exception.InnerException.Message
            }
        } catch { }
        Telnet-ConnectFail -Message $msg
    }
}

function Connect-WorldTelnet {
    try {
        if ($script:TelnetConnected -or $script:TelnetConnectState) { return }

        $target = Get-TelnetTargetFromUiOrConfig
        $telnetHost = ([string]$target.Host).Trim()
        $port = [int]$target.Port

        try { $TxtTelnetTarget.Text = ("{0}:{1}" -f $telnetHost, $port) } catch { }

        $creds = Get-TelnetCredentialsFromUiOrSecrets -TelnetHost $telnetHost -Port $port
        $user  = [string]$creds.Username
        $pw    = [string]$creds.Password

        if ([string]::IsNullOrWhiteSpace($user)) {
            Add-GuiLog "ERROR: Telnet username is not set (Configuration tab > Worldserver Telnet)."
            Set-TelnetStatus -Text "Missing username" -Brush ([System.Windows.Media.Brushes]::Tomato)
            return
        }

        $script:TelnetStopRequested = $false

        Stop-TelnetTimers

        Update-TelnetUiState -Connected $false -Connecting $true
        Set-TelnetStatus -Text "Connecting..." -Brush ([System.Windows.Media.Brushes]::Gold)

        Append-TelnetOutput (("`r`n[Connecting to {0}:{1}]`r`n") -f $telnetHost, $port)
$client = $null
        $iar    = $null
        $ipObj  = $null

        # Prefer the IPAddress overload when the host is an IP (avoids dual-stack/DNS ambiguity)
        if ([System.Net.IPAddress]::TryParse($telnetHost, [ref]$ipObj)) {
            $client = New-Object System.Net.Sockets.TcpClient($ipObj.AddressFamily)
            $iar = $client.BeginConnect($ipObj, $port, $null, $null)
        } else {
            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $client.BeginConnect($telnetHost, $port, $null, $null)
        }
$script:TelnetConnectState = [pscustomobject]@{
            Client   = $client
            Iar      = $iar
            Started  = (Get-Date)
            Host     = $telnetHost
            Port     = $port
            Username = $user
            Password = $pw
            TriedLocalhostRetry = $false
        }

        if (-not $script:TelnetConnectTimer) {
            $t = New-Object System.Windows.Threading.DispatcherTimer
            $t.Interval = [TimeSpan]::FromMilliseconds(150)
            $t.add_Tick({ Telnet-ConnectTick })
            $script:TelnetConnectTimer = $t
        }

        $script:TelnetConnectTimer.Start()
    } catch {
        Add-GuiLog ("ERROR: Telnet connect error: {0}" -f $_.Exception.Message)
        Update-TelnetUiState -Connected $false -Connecting $false
        Set-TelnetStatus -Text "Connect failed" -Brush ([System.Windows.Media.Brushes]::Tomato)
    }
}



# (Telnet read loop replaced by UI-thread DispatcherTimer for PS2EXE compatibility)

function Send-WorldTelnetLine {
    param(
        [Parameter(Mandatory)][string]$Line,
        [switch]$NoEcho
    )

    if (-not $script:TelnetConnected -or -not $script:TelnetStream) {
        Add-GuiLog "WARN: Telnet is not connected."
        return
    }

    try {
        $enc = [System.Text.Encoding]::ASCII
        $bytes = $enc.GetBytes(($Line + "`r`n"))
        $script:TelnetStream.Write($bytes, 0, $bytes.Length)
        $script:TelnetStream.Flush()

        # Echo locally for clarity (unless suppressed for sensitive values like passwords)
        if (-not $NoEcho) {
            Append-TelnetOutput ("`r`n> {0}`r`n" -f $Line)
        }
    } catch {
        Add-GuiLog ("ERROR: Telnet send failed: {0}" -f $_.Exception.Message)
        Disconnect-WorldTelnet -Silent
    }
}


# Telnet tab event handlers (connect only on click; output always auto-scroll)
Update-TelnetUiState -Connected $false -Connecting $false
Set-TelnetStatus -Text "Disconnected" -Brush ([System.Windows.Media.Brushes]::Gold)
Append-TelnetOutput "[Console ready] Click Connect to begin.\r\n"

$BtnTelnetConnect.Add_Click({ Connect-WorldTelnet })
$BtnTelnetDisconnect.Add_Click({ Disconnect-WorldTelnet })

$BtnTelnetSend.Add_Click({
    $cmd = ($TxtTelnetCommand.Text + "").Trim()
    if ([string]::IsNullOrWhiteSpace($cmd)) { return }
    $TxtTelnetCommand.Clear()
    Send-WorldTelnetLine -Line $cmd
})

$TxtTelnetCommand.Add_KeyDown({
    param($sender, $e)
    try {
        if ($e.Key -eq [System.Windows.Input.Key]::Enter) {
            $cmd = ($TxtTelnetCommand.Text + "").Trim()
            if (-not [string]::IsNullOrWhiteSpace($cmd)) {
                $TxtTelnetCommand.Clear()
                Send-WorldTelnetLine -Line $cmd
            }
            $e.Handled = $true
        }
    } catch { }
})

# Worldserver Log Tail (Console Tab)
$ChkWorldLogTail.Add_Checked({
    try { Start-WorldLogTail } catch { }
})
$ChkWorldLogTail.Add_Unchecked({
    try { Stop-WorldLogTail } catch { }
})

$BtnClearWorldLog.Add_Click({
    try { $TxtWorldLogOutput.Clear() } catch { }
    try {
        if ($ChkWorldLogTail -and $ChkWorldLogTail.IsChecked) {
            Start-WorldLogTail -StartAtEnd
        }
    } catch { }
})

$BtnStartWatchdog.Add_Click({ Start-WatchdogPreferred })
$BtnStopWatchdog.Add_Click({ Stop-WatchdogPreferred })
$BtnTestNtfy.Add_Click({ Send-NTFYTest })
$BtnBrowseMySQLExe.Add_Click({
    $f = Pick-File "mysql.exe (mysql.exe)|mysql.exe|Executables (*.exe)|*.exe|All files (*.*)|*.*"
    if ($f) { $TxtMySQLExe.Text = $f }
})
if ($TxtMySQLExe) { $TxtMySQLExe.Text = [string]$Config.MySQLExe }

$BtnLaunchSppManager.Add_Click({
    try {
        $owner = "skeezerbean"
        $repo  = "SPP-LegionV2-Management"

        $installDir = $script:ToolsDir  # Matches: SPP.LegionV2.Management.0.0.2.24.zip
        $assetRegex = '^SPP\.LegionV2\.Management\.\d+\.\d+\.\d+\.\d+\.zip$'

        # Confirmed extracted EXE location:
        $exeRel = 'SPP LegionV2 Management\SPP-LegionV2-Management.exe'

        $exePath = Ensure-GitHubZipToolInstalled `
            -Owner $owner `
            -Repo $repo `
            -InstallDir $installDir `
            -ExeRelativePath $exeRel `
            -AssetNameRegex $assetRegex

        Start-Process -FilePath $exePath -WorkingDirectory (Split-Path $exePath) | Out-Null
    } catch {
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Launch Failed", "OK", "Error") | Out-Null
    }
})

# -------------------------------------------------
# Timer – update status + log view
# -------------------------------------------------
Initialize-NtfyBaseline

if ($null -eq $global:UtilTick) { $global:UtilTick = 0 }

$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(1)

$timer.Add_Tick({
    try {
        Update-ServiceStates
        Update-WatchdogStatusLabel
        Update-ServiceStatusLabel
        Update-WorldUptimeLabel

        # Every 5 seconds: Resource utilization snapshot
        $global:UtilTick++
        if ($global:UtilTick -ge 5) {
            $global:UtilTick = 0
            Update-ResourceUtilizationUi
        }

        # Log view
        if (Test-Path $LogPath) {
            $text = Get-Content $LogPath -Raw -ErrorAction SilentlyContinue
            if ($text -ne $TxtLiveLog.Text) {
                $TxtLiveLog.Text = $text
                $TxtLiveLog.ScrollToEnd()
            }
        }
     } catch {
        Add-GuiLog "TIMER ERROR: $($_.Exception.Message)"
    }
})

$timer.Start()



# Ensure telnet socket is closed when the window exits
$Window.add_Closing({
    try { Disconnect-WorldTelnet -Silent } catch { }
    try { Stop-WorldLogTail } catch { }
})

# -------------------------------------------------
# Show
# -------------------------------------------------
try {
    $null = $Window.ShowDialog()
}
catch {
    [System.Windows.MessageBox]::Show(
        "Fatal GUI error:`n`n$($_)",
        "WoW Watchdog",
        'OK',
        'Error'
    )
}
