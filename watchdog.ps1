<#
    WoW Unified Watchdog (GUI-compatible + service-friendly)

    - Reads config.json in the same folder

    - Startup order:
        1. MySQL (batch)
        2. Authserver.exe
        3. Worldserver.exe

    - Keeps them running
    - Now includes restart cooldowns (prevents spam restarts)
    - Crash-loop protection for worldserver
    - Graceful stop via stop_watchdog.txt
#>

param(
    [int]$RestartCooldown = 5,
    [int]$WorldserverBurst = 300,
    [int]$MaxRestarts     = 100
)

$ScriptDir       = Split-Path -Parent $MyInvocation.MyCommand.Path
$ConfigPath      = Join-Path $ScriptDir "config.json"
$LogFile         = Join-Path $ScriptDir "watchdog.log"
$StopSignalFile  = Join-Path $ScriptDir "stop_watchdog.txt"

$global:LastRestartMySQL  = Get-Date "2000-01-01"
$global:LastRestartAuth   = Get-Date "2000-01-01"
$global:LastRestartWorld  = Get-Date "2000-01-01"

$global:WorldRestartCount = 0
$global:WorldBurstStart   = $null

function Log {
    param([string]$Message)
    $ts   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts] $Message"
    Add-Content -Path $LogFile -Value $line
    Write-Host $line
}

# ------------------------------------------------
# Read config.json
# ------------------------------------------------
if (-not (Test-Path $ConfigPath)) {
    Log "config.json not found. Creating default config.json."

    $default = [pscustomobject]@{
        # Optional identity metadata used for alert context (GUI/NTFY)
        ServerName  = ""
        Expansion   = "Unknown"

        MySQL       = "C:\Path\To\MySQL.bat"
        Authserver  = Join-Path $ScriptDir "authserver.exe"
        Worldserver = Join-Path $ScriptDir "worldserver.exe"

        # Optional NTFY config (GUI uses this; watchdog itself may ignore it)
        NTFY        = [pscustomobject]@{
            Server            = ""
            Topic             = ""
            Tags              = "wow,watchdog"
            PriorityDefault   = 4

            EnableMySQL       = $true
            EnableAuthserver  = $true
            EnableWorldserver = $true

            ServicePriorities = [pscustomobject]@{
                MySQL       = 0
                Authserver  = 0
                Worldserver = 0
            }

            SendOnDown        = $true
            SendOnUp          = $false
        }
    }

    $default | ConvertTo-Json -Depth 6 | Set-Content -Path $ConfigPath -Encoding UTF8
    Log "Default config.json created. Adjust paths and restart watchdog."
    exit
}

try {
    $Config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
} catch {
    Log ("ERROR: Failed to parse config.json: {0}" -f $_)
    exit 1
}

$MySQLPath      = $Config.MySQL
$AuthPath       = $Config.Authserver
$WorldPath      = $Config.Worldserver

function Ensure-MySQL {
    $mysqlProc = Get-Process -Name "mysqld" -ErrorAction SilentlyContinue
    if ($mysqlProc) { return }

    $now   = Get-Date
    $delta = ($now - $global:LastRestartMySQL).TotalSeconds

    if ($delta -lt $RestartCooldown) {
        return
    }

    $global:LastRestartMySQL = $now
    Log ("MySQL not running — launching batch file: {0}" -f $MySQLPath)

    try {
        Start-Process -FilePath $MySQLPath -WindowStyle Hidden
    } catch {
        Log ("ERROR: Failed to start MySQL batch: {0}" -f $_)
    }
}

function Ensure-Authserver {
    $authProc = Get-Process -Name "authserver" -ErrorAction SilentlyContinue
    if ($authProc) { return }

    $now   = Get-Date
    $delta = ($now - $global:LastRestartAuth).TotalSeconds

    if ($delta -lt $RestartCooldown) {
        return
    }

    $global:LastRestartAuth = $now
    Log ("Authserver not running — starting: {0}" -f $AuthPath)

    try {
        Start-Process -FilePath $AuthPath -WorkingDirectory (Split-Path $AuthPath)
    } catch {
        Log ("ERROR: Failed to start authserver: {0}" -f $_)
    }
}

function Ensure-Worldserver {
    $worldProc = Get-Process -Name "worldserver" -ErrorAction SilentlyContinue
    if ($worldProc) { return }

    # Crash-loop protection
    $now = Get-Date
    if (-not $global:WorldBurstStart) {
        $global:WorldBurstStart = $now
        $global:WorldRestartCount = 0
    } else {
        $burstAge = ($now - $global:WorldBurstStart).TotalSeconds
        if ($burstAge -gt $WorldserverBurst) {
            $global:WorldBurstStart = $now
            $global:WorldRestartCount = 0
        }
    }

    $global:WorldRestartCount++
    if ($global:WorldRestartCount -gt $MaxRestarts) {
        Log "ERROR: Worldserver restart limit exceeded; stopping watchdog."
        exit 2
    }

    $delta = ($now - $global:LastRestartWorld).TotalSeconds
    if ($delta -lt $RestartCooldown) {
        return
    }

    $global:LastRestartWorld = $now
    Log ("Worldserver not running — starting: {0}" -f $WorldPath)

    try {
        Start-Process -FilePath $WorldPath -WorkingDirectory (Split-Path $WorldPath)
    } catch {
        Log ("ERROR: Failed to start worldserver: {0}" -f $_)
    }
}

Log "WoW Watchdog starting..."

while ($true) {
    if (Test-Path $StopSignalFile) {
        Log "Stop signal detected ($StopSignalFile). Exiting watchdog."
        Remove-Item $StopSignalFile -Force -ErrorAction SilentlyContinue
        break
    }

    Ensure-MySQL
    Ensure-Authserver
    Ensure-Worldserver

    Start-Sleep -Seconds 1
}

Log "WoW Watchdog stopped."
