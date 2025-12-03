<#
    MoP Unified Watchdog (GUI-compatible + service-friendly)

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
    [int]$RestartDelay    = 3,
    [int]$PauseAfterBurst = 300,
    [int]$MaxRestarts     = 100
)

# ------------------------------------------------
# Script base path
# ------------------------------------------------
$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
Set-Location $ScriptDir

$ConfigPath     = Join-Path $ScriptDir "config.json"
$LogFile        = Join-Path $ScriptDir "watchdog.log"
$StopSignalFile = Join-Path $ScriptDir "stop_watchdog.txt"

# ------------------------------------------------
# Logging
# ------------------------------------------------
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
        MySQL       = "C:\Path\To\MySQL.bat"
        Authserver  = Join-Path $ScriptDir "authserver.exe"
        Worldserver = Join-Path $ScriptDir "worldserver.exe"
    }

    $default | ConvertTo-Json -Depth 3 | Set-Content -Path $ConfigPath -Encoding UTF8
    Log "Default config.json created. Adjust paths and restart watchdog."
    exit
}

try {
    $Config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
} catch {
    Log ("ERROR: Failed to parse config.json: {0}" -f $_)
    exit 1
}

$MySQLPath = $Config.MySQL
$AuthPath  = $Config.Authserver
$WorldPath = $Config.Worldserver

foreach ($p in @($MySQLPath, $AuthPath, $WorldPath)) {
    if (-not ($p) -or -not (Test-Path $p)) {
        Log ("ERROR: Required file missing or path empty: '{0}'" -f $p)
        exit 1
    }
}

Log "Watchdog starting with:"
Log ("  MySQL:      {0}" -f $MySQLPath)
Log ("  Authserver: {0}" -f $AuthPath)
Log ("  Worldserver:{0}" -f $WorldPath)

# ------------------------------------------------
# RESTART COOLDOWN PATCH
# ------------------------------------------------
$RestartCooldown = 5   # Seconds between restart attempts

$global:LastRestartMySQL  = Get-Date "1900-01-01"
$global:LastRestartAuth   = Get-Date "1900-01-01"
$global:LastRestartWorld  = Get-Date "1900-01-01"

# ------------------------------------------------
# MySQL with cooldown fix
# ------------------------------------------------
function Ensure-MySQL {
    $mysqlProc = Get-Process -Name "mysqld" -ErrorAction SilentlyContinue
    if ($mysqlProc) { return }

    $now   = Get-Date
    $delta = ($now - $global:LastRestartMySQL).TotalSeconds

    if ($delta -lt $RestartCooldown) {
        return  # Skip rapid-fire restarts
    }

    $global:LastRestartMySQL = $now

    Log ("MySQL not running — launching batch file: {0}" -f $MySQLPath)

    try {
        Start-Process -FilePath $MySQLPath -WorkingDirectory (Split-Path $MySQLPath) | Out-Null
    } catch {
        Log ("ERROR: Failed to start MySQL: {0}" -f $_)
        return
    }

    # Wait up to 20 seconds for mysqld.exe to appear
    for ($i = 1; $i -le 20; $i++) {
        Start-Sleep -Seconds 1
        $mysqlProc = Get-Process -Name "mysqld" -ErrorAction SilentlyContinue
        if ($mysqlProc) {
            Log "MySQL started successfully."
            return
        }
    }

    Log "WARNING: MySQL batch executed, but mysqld.exe did not appear within 20 seconds."
}

# ------------------------------------------------
# Authserver with cooldown fix
# ------------------------------------------------
function Ensure-Authserver {
    $exeName = [System.IO.Path]::GetFileNameWithoutExtension($AuthPath)
    if (-not $exeName) { return }

    $proc = Get-Process -Name $exeName -ErrorAction SilentlyContinue
    if ($proc) { return }

    $now   = Get-Date
    $delta = ($now - $global:LastRestartAuth).TotalSeconds

    if ($delta -lt $RestartCooldown) {
        return
    }

    $global:LastRestartAuth = $now

    Log ("Authserver not running — starting: {0}" -f $AuthPath)

    try {
        Start-Process -FilePath $AuthPath -WorkingDirectory (Split-Path $AuthPath) | Out-Null
    } catch {
        Log ("ERROR: Failed to start Authserver: {0}" -f $_)
    }

    Start-Sleep -Seconds 2
}

# ------------------------------------------------
# Worldserver with cooldown + existing crash-loop logic
# ------------------------------------------------
function Ensure-Worldserver {
    param([ref]$RestartCount)

    $exeName = [System.IO.Path]::GetFileNameWithoutExtension($WorldPath)
    if (-not $exeName) { return }

    $proc = Get-Process -Name $exeName -ErrorAction SilentlyContinue
    if ($proc) {
        $RestartCount.Value = 0
        return
    }

    $now   = Get-Date
    $delta = ($now - $global:LastRestartWorld).TotalSeconds

    if ($delta -lt $RestartCooldown) {
        return
    }

    $global:LastRestartWorld = $now

    Log "Worldserver not running — starting."

    try {
        Start-Process -FilePath $WorldPath -WorkingDirectory (Split-Path $WorldPath) | Out-Null
    } catch {
        Log ("ERROR: Failed to start Worldserver: {0}" -f $_)
    }

    $RestartCount.Value++

    if ($RestartCount.Value -ge $MaxRestarts) {
        Log ("CRASH-LOOP: Worldserver restarted {0} times. Pausing for {1} seconds." -f $RestartCount.Value, $PauseAfterBurst)
        Start-Sleep -Seconds $PauseAfterBurst
        $RestartCount.Value = 0
    }

    Start-Sleep -Seconds 5
}

# ------------------------------------------------
# MAIN LOOP
# ------------------------------------------------
$RestartCount = 0
Log "Watchdog main loop entering."

while ($true) {

    if (Test-Path $StopSignalFile) {
        Log ("Stop signal file detected. Exiting watchdog.")
        Remove-Item $StopSignalFile -Force
        break
    }

    Ensure-MySQL
    Ensure-Authserver
    Ensure-Worldserver -RestartCount ([ref]$RestartCount)

    Start-Sleep -Seconds $RestartDelay
}

Log "Watchdog stopped."
