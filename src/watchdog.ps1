<# WoW Watchdog – Service Safe (with GUI Heartbeat) #>

param(
    [int]$RestartCooldown  = 5,
    [int]$WorldserverBurst = 300,  # seconds
    [int]$MaxRestarts      = 100,  # max restarts within burst window
    [int]$ConfigRetrySec   = 10,   # if config invalid/missing, re-check every N seconds
    [int]$HeartbeatEverySec = 1    # heartbeat update cadence
)

$ErrorActionPreference = 'Stop'

# -------------------------------
# Paths (service / EXE safe)
# -------------------------------
$BaseDir = if ($PSScriptRoot) {
    $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Path) {
    Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    Split-Path -Parent ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
}

$AppName = "WoWWatchdog"
$DataDir = Join-Path $env:ProgramData $AppName
if (-not (Test-Path $DataDir)) {
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
}

$LogFile         = Join-Path $DataDir "watchdog.log"
$StopSignalFile  = Join-Path $DataDir "stop_watchdog.txt"
$ConfigPath      = Join-Path $DataDir "config.json"
$HeartbeatFile   = Join-Path $DataDir "watchdog.heartbeat"      # GUI checks timestamp freshness
$StatusFile      = Join-Path $DataDir "watchdog.status.json"    # GUI reads richer status (optional)

# Log only on config-state changes (prevents spam)
$global:LastConfigValidity = $null   # $true=valid, $false=invalid, $null=unknown
$global:LastConfigIssueSig = ""      # signature of last issues logged
$global:LastConfigLoadState = ""   # "MissingConfig", "InvalidConfig", or ""

# -------------------------------
# Logging (never throw)
# -------------------------------
function Log {
    param([string]$Message)
    try {
        $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Add-Content -Path $LogFile -Value "[$ts] $Message" -Encoding UTF8
    } catch { }
}

# -------------------------------
# Status helpers (never throw)
# -------------------------------
function Write-Heartbeat {
    param(
        [string]$State = "Running",
        [hashtable]$Extra = $null
    )

    try {
        $now = Get-Date
        # Heartbeat file: ISO timestamp only (simple + robust)
        Set-Content -Path $HeartbeatFile -Value ($now.ToString("o")) -Encoding UTF8 -Force

        # Optional richer status JSON
        $obj = [ordered]@{
            timestamp   = $now.ToString("o")
            pid         = $PID
            state       = $State
            baseDir     = $BaseDir
            dataDir     = $DataDir
        }

        if ($Extra) {
            foreach ($k in $Extra.Keys) { $obj[$k] = $Extra[$k] }
        }

        ($obj | ConvertTo-Json -Depth 6) | Set-Content -Path $StatusFile -Encoding UTF8 -Force
    } catch { }
}

# -------------------------------
# Process aliases
# -------------------------------
$ProcessAliases = @{
    MySQL      = @("mysqld","mysqld-nt","mysqld-opt","mariadbd")
    Authserver = @("authserver","bnetserver","logonserver","realmd","auth")
    Worldserver= @("worldserver")
}

function Test-ProcessRoleRunning {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("MySQL","Authserver","Worldserver")]
        [string]$Role
    )

    foreach ($p in $ProcessAliases[$Role]) {
        try {
            if (Get-Process -Name $p -ErrorAction SilentlyContinue) { return $true }
        } catch { }
    }
    return $false
}

# -------------------------------
# Restart tracking
# -------------------------------
$LastRestart = @{
    MySQL      = Get-Date "2000-01-01"
    Authserver = Get-Date "2000-01-01"
    Worldserver= Get-Date "2000-01-01"
}

$WorldRestartCount = 0
$WorldBurstStart   = $null

# -------------------------------
# Config loading + validation
# -------------------------------
function Load-ConfigSafe {
if (-not (Test-Path $ConfigPath)) {
    if ($global:LastConfigLoadState -ne "MissingConfig") {
        Log "config.json missing at $ConfigPath. Watchdog idle (will retry)."
        $global:LastConfigLoadState = "MissingConfig"
    }

    Write-Heartbeat -State "Idle" -Extra @{ reason = "MissingConfig"; configPath = $ConfigPath }
    return $null
}

    try {
        $cfg = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
        $global:LastConfigLoadState = ""
        return $cfg

} catch {
    if ($global:LastConfigLoadState -ne "InvalidConfig") {
        Log "config.json invalid/unparseable. Watchdog idle (will retry). Error: $($_)"
        $global:LastConfigLoadState = "InvalidConfig"
    }

    Write-Heartbeat -State "Idle" -Extra @{ reason = "InvalidConfig"; configPath = $ConfigPath }
    return $null
}
}

function Test-ConfigPaths {
    param($Cfg)

    $issues = New-Object System.Collections.Generic.List[string]

    $pairs = @(
        @{ Role="MySQL";      Path=[string]$Cfg.MySQL },
        @{ Role="Authserver"; Path=[string]$Cfg.Authserver },
        @{ Role="Worldserver";Path=[string]$Cfg.Worldserver }
    )

    foreach ($p in $pairs) {
        if ([string]::IsNullOrWhiteSpace($p.Path)) {
            $issues.Add("EMPTY path for $($p.Role)")
            continue
        }
        if (-not (Test-Path $p.Path)) {
            $issues.Add("MISSING path for $($p.Role): $($p.Path)")
        }
    }

    return $issues
}

# -------------------------------
# Start helper (bat/exe safe)
# -------------------------------
function Start-Target {
    param(
        [Parameter(Mandatory)][string]$Role,
        [Parameter(Mandatory)][string]$Path
    )

    # Batch files need cmd.exe
    if ($Path -match '\.bat$') {
        Start-Process -FilePath "cmd.exe" `
            -ArgumentList "/c `"$Path`"" `
            -WorkingDirectory (Split-Path $Path) `
            -WindowStyle Hidden
        return
    }

    # EXE path
    Start-Process -FilePath $Path `
        -WorkingDirectory (Split-Path $Path) `
        -WindowStyle Hidden
}

# -------------------------------
# Ensure functions
# -------------------------------
function Ensure-Role {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("MySQL","Authserver","Worldserver")]
        [string]$Role,

        [Parameter(Mandatory)]
        [string]$Path
    )

    if (Test-ProcessRoleRunning -Role $Role) { return }

    # Restart cooldown
    $delta = ((Get-Date) - $LastRestart[$Role]).TotalSeconds
    if ($delta -lt $RestartCooldown) { return }

    # Worldserver crash-loop protection
    if ($Role -eq "Worldserver") {
        $now = Get-Date
        if (-not $WorldBurstStart) {
            $WorldBurstStart   = $now
            $WorldRestartCount = 0
        } else {
            $burstAge = ($now - $WorldBurstStart).TotalSeconds
            if ($burstAge -gt $WorldserverBurst) {
                $WorldBurstStart   = $now
                $WorldRestartCount = 0
            }
        }

        $WorldRestartCount++
        if ($WorldRestartCount -gt $MaxRestarts) {
            Log "ERROR: Worldserver restart limit exceeded ($WorldRestartCount > $MaxRestarts in $WorldserverBurst sec). Suppressing restarts."
            return
        }
    }

    $LastRestart[$Role] = Get-Date
    Log "$Role not running — starting: $Path"

    try {
        Start-Target -Role $Role -Path $Path
    } catch {
        Log "ERROR starting $Role ($Path): $($_)"
    }
}

# -------------------------------
# Startup
# -------------------------------
Log "Watchdog service starting (PID $PID)"
Write-Heartbeat -State "Starting" -Extra @{ version = "service-safe-heartbeat"; configPath = $ConfigPath }

$lastConfigCheck = Get-Date "2000-01-01"
$cfg = $null
$pathsOk = $false
$issuesLast = @()


# -------------------------------
# Main loop
# -------------------------------
while ($true) {
    try {
        # Stop signal (GUI writes this)
        if (Test-Path $StopSignalFile) {
            Log "Stop signal detected ($StopSignalFile). Shutting down watchdog."
            Remove-Item $StopSignalFile -Force -ErrorAction SilentlyContinue
            Write-Heartbeat -State "Stopping" -Extra @{ reason = "StopSignal" }
            break
        }

        # Reload config periodically or if not loaded
        $sinceCfg = ((Get-Date) - $lastConfigCheck).TotalSeconds
        if (-not $cfg -or $sinceCfg -ge $ConfigRetrySec -or -not $pathsOk) {
            $lastConfigCheck = Get-Date
            $cfg = Load-ConfigSafe
            $pathsOk = $false

            if ($cfg) {
                $issues = Test-ConfigPaths -Cfg $cfg
                $issuesLast = $issues

if ($issues.Count -gt 0) {

    # Build a stable signature so we only log when the issue set changes
    $sig = ($issues | Sort-Object) -join " | "

    if ($global:LastConfigValidity -ne $false -or $global:LastConfigIssueSig -ne $sig) {
        Log ("Config path issues: " + $sig)
        $global:LastConfigValidity = $false
        $global:LastConfigIssueSig = $sig
    }

    Write-Heartbeat -State "Idle" -Extra @{ reason = "BadPaths"; issues = $issues }
    Start-Sleep -Seconds $ConfigRetrySec
    continue

} else {

    $pathsOk = $true

    # Only log the success transition once (invalid -> valid, or unknown -> valid)
    if ($global:LastConfigValidity -ne $true) {
        Log "Config loaded and paths validated."
        $global:LastConfigValidity = $true
        $global:LastConfigIssueSig = ""
    }
}

            } else {
                Start-Sleep -Seconds $ConfigRetrySec
                continue
            }
        }

        # Ensure roles
        Ensure-Role -Role "MySQL"      -Path ([string]$cfg.MySQL)
        Ensure-Role -Role "Authserver" -Path ([string]$cfg.Authserver)
        Ensure-Role -Role "Worldserver"-Path ([string]$cfg.Worldserver)

        # Heartbeat + lightweight telemetry for GUI
        $extra = @{
            mysqlRunning      = (Test-ProcessRoleRunning -Role "MySQL")
            authRunning       = (Test-ProcessRoleRunning -Role "Authserver")
            worldRunning      = (Test-ProcessRoleRunning -Role "Worldserver")
            worldBurstStart   = if ($WorldBurstStart) { $WorldBurstStart.ToString("o") } else { $null }
            worldRestartCount = $WorldRestartCount
            lastIssues        = $issuesLast
        }
        Write-Heartbeat -State "Running" -Extra $extra

        Start-Sleep -Seconds $HeartbeatEverySec
    }
    catch {
        Log "Unhandled watchdog error: $($_)"
        Write-Heartbeat -State "Error" -Extra @{ error = "$($_)" }
        Start-Sleep -Seconds 5
    }
}

Log "Watchdog service stopped."
Write-Heartbeat -State "Stopped" -Extra @{ reason = "Exited" }
