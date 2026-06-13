<# WoW Watchdog – Service Safe (with GUI Heartbeat) #>

param(
    [int]$RestartCooldown  = 5,
    [int]$WorldserverBurst = 300,  # seconds
    [int]$MaxRestarts      = 20,   # max restarts within burst window (must be reachable given RestartCooldown)
    [int]$ConfigRetrySec   = 10,   # if config invalid/missing, re-check every N seconds
    [int]$HeartbeatEverySec = 1,    # heartbeat update cadence
    [int]$ShutdownDelaySec = 8,  # delay between service stops
    [int64]$LogMaxBytes    = 5242880, # 5 MB
    [int]$LogRetainCount   = 5,
    # REST API parameters (Android companion app)
    [switch]$ApiEnabled,
    [int]$ApiPort          = 8099,
    [string]$ApiBind       = "+"   # "+" = all interfaces, "localhost" = local only
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
$StopSignalFile  = Join-Path $DataDir "watchdog.stop"
$ConfigPath      = Join-Path $DataDir "config.json"
$HeartbeatFile   = Join-Path $DataDir "watchdog.heartbeat"      # GUI checks timestamp freshness
$StatusFile      = Join-Path $DataDir "watchdog.status.json"    # GUI reads richer status

$CommandDir = $DataDir

# Command files are dropped by the GUI to request immediate service actions.
$CommandFiles = @{
    StartMySQL      = Join-Path $CommandDir "command.start.mysql"
    StopMySQL       = Join-Path $CommandDir "command.stop.mysql"
    StartAuthserver = Join-Path $CommandDir "command.start.auth"
    StopAuthserver  = Join-Path $CommandDir "command.stop.auth"
    StartWorld      = Join-Path $CommandDir "command.start.world"
    StopWorld       = Join-Path $CommandDir "command.stop.world"
}

$HoldDir = Join-Path $DataDir "holds"
if (-not (Test-Path $HoldDir)) { New-Item -ItemType Directory -Path $HoldDir -Force | Out-Null }

function Get-HoldFile {
    param([Parameter(Mandatory)][ValidateSet("MySQL","Authserver","Worldserver")][string]$Role)
    Join-Path $HoldDir "$Role.hold"
}

function Is-RoleHeld {
    param([Parameter(Mandatory)][ValidateSet("MySQL","Authserver","Worldserver")][string]$Role)
    # Hold files are created by the GUI to pause restarts for a role.
    return (Test-Path (Get-HoldFile -Role $Role))
}


# Log only on config-state changes (prevents spam during retries)
$global:LastConfigValidity = $null   # $true=valid, $false=invalid, $null=unknown
$global:LastConfigIssueSig = ""      # signature of last issues logged
$global:LastConfigLoadState = ""   # "MissingConfig", "InvalidConfig", or ""

# -------------------------------
# Logging (never throw)
# -------------------------------
function Rotate-LogIfNeeded {
    param(
        [Parameter(Mandatory)][string]$Path,
        [int64]$MaxBytes = 5242880,
        [int]$Keep = 5
    )

    try {
        if (-not (Test-Path $Path)) { return }
        if ($MaxBytes -le 0 -or $Keep -le 0) { return }

        $len = (Get-Item -LiteralPath $Path).Length
        if ($len -lt $MaxBytes) { return }

        for ($i = $Keep - 1; $i -ge 1; $i--) {
            $src = "$Path.$i"
            $dst = "$Path." + ($i + 1)
            if (Test-Path $src) {
                Move-Item -LiteralPath $src -Destination $dst -Force
            }
        }

        Move-Item -LiteralPath $Path -Destination "$Path.1" -Force
    } catch { }
}

function Invoke-WithLogLock {
    param([Parameter(Mandatory)][scriptblock]$Action)

    $mutex = $null
    $hasLock = $false
    try {
        $mutex = New-Object System.Threading.Mutex($false, "Global\WoWWatchdog_Log")
        $hasLock = $mutex.WaitOne(2000)
    } catch {
        $hasLock = $false
    }

    try {
        & $Action
    } finally {
        if ($hasLock -and $mutex) {
            try { $mutex.ReleaseMutex() } catch { }
        }
        if ($mutex) { $mutex.Dispose() }
    }
}

function Write-AtomicFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content,
        [System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8
    )

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    $tmpName = (".{0}.tmp.{1}" -f ([System.IO.Path]::GetFileName($Path)), ([guid]::NewGuid().ToString("N")))
    $tmpPath = Join-Path $dir $tmpName

    try {
        [System.IO.File]::WriteAllText($tmpPath, $Content, $Encoding)
        Move-Item -LiteralPath $tmpPath -Destination $Path -Force
    } finally {
        if (Test-Path -LiteralPath $tmpPath) {
            Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Log {
    param([string]$Message)
    try {
        Invoke-WithLogLock -Action {
            Rotate-LogIfNeeded -Path $LogFile -MaxBytes $LogMaxBytes -Keep $LogRetainCount
            $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Add-Content -Path $LogFile -Value "[$ts] $Message" -Encoding UTF8
        }
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
        # Heartbeat file: ISO timestamp only (simple + robust for GUI freshness checks)
        Write-AtomicFile -Path $HeartbeatFile -Content ($now.ToString("o"))

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

         $json = $obj | ConvertTo-Json -Depth 6
         Write-AtomicFile -Path $StatusFile -Content $json
    } catch { }
}

function Try-ConsumeCommandFile {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $false }

    # Atomically rename the file to claim it; this prevents double-processing.
    $dir = Split-Path -Parent $Path
    $claimed = Join-Path $dir ("{0}.processing.{1}" -f ([System.IO.Path]::GetFileName($Path)), ([guid]::NewGuid().ToString("N")))

    try {
        Move-Item -LiteralPath $Path -Destination $claimed -Force -ErrorAction Stop
    } catch {
        return $false
    }

    try {
        Remove-Item -LiteralPath $claimed -Force -ErrorAction SilentlyContinue
    } catch { }

    return $true
}

# -------------------------------
# Process aliases
# -------------------------------
$ProcessAliases = @{
    MySQL      = @("mysqld","mysqld-nt","mysqld-opt","mariadbd")
    Authserver = @("authserver","bnetserver","logonserver","realmd","auth")
    Worldserver= @("worldserver")
}

function Test-PortOpen {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutMs = 1000
    )

    if ($Port -le 0) { return $false }

    $client = $null
    $async = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        $wait = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $wait) {
            return $false
        }
        $client.EndConnect($async) | Out-Null
        return $true
    } catch {
        return $false
    } finally {
        if ($client) {
            try { $client.Close() } catch { }
            try { $client.Dispose() } catch { }
        }
    }
}

function Get-RolePort {
    param(
        [Parameter(Mandatory)]$Cfg,
        [Parameter(Mandatory)][ValidateSet("MySQL","Authserver","Worldserver")][string]$Role
    )

    switch ($Role) {
        "MySQL" { return [int]$Cfg.MySQLPort }
        "Authserver" { return [int]$Cfg.AuthserverPort }
        "Worldserver" { return [int]$Cfg.WorldserverPort }
    }
}

function Test-ProcessRoleRunning {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("MySQL","Authserver","Worldserver")]
        [string]$Role,

        [string]$ExpectedPath
    )

    $expectedExe = $null
    if (-not [string]::IsNullOrWhiteSpace($ExpectedPath) -and $ExpectedPath -match '\.exe$') {
        $expectedExe = $ExpectedPath
    }

    # If we have an explicit expected path, confirm the exact executable.
    if ($expectedExe) {
        $expectedExeFull = $expectedExe
        try { $expectedExeFull = [System.IO.Path]::GetFullPath($expectedExe) } catch { }

        $expectedName = [System.IO.Path]::GetFileNameWithoutExtension($expectedExe)
        $procs = @()
        try { $procs = Get-Process -Name $expectedName -ErrorAction SilentlyContinue } catch { }

        # No process with that image name exists — the role is genuinely down.
        if (-not $procs -or @($procs).Count -eq 0) { return $false }

        # A process with the right image name is present, but we may not be able to
        # read its full path (e.g. a 64-bit core queried from a 32-bit host, or
        # modules still loading right after launch). Distinguish a confirmed path
        # *mismatch* from an *unverifiable* path so we never report a running
        # service as down and trigger a relaunch.
        $sawUnverifiablePath = $false
        $sawReadableMismatch = $false
        foreach ($proc in $procs) {
            $procPath = $null
            try {
                $procPath = $proc.Path
                if (-not $procPath) { $procPath = $proc.MainModule.FileName }
            } catch {
                $procPath = $null
            }

            if (-not $procPath) { $sawUnverifiablePath = $true; continue }

            try { $procPath = [System.IO.Path]::GetFullPath($procPath) } catch { }
            if ($procPath -ieq $expectedExeFull) { return $true }

            # Readable path pointing elsewhere — this instance is a different install.
            $sawReadableMismatch = $true
        }

        # Name matched but no instance's path could be confirmed against the expected
        # executable. Trust the bare name match only when we never saw a readable path
        # pointing at a *different* install: a false "not running" makes the watchdog
        # spawn duplicates until memory is exhausted, but if same-named processes are
        # demonstrably from other installs then this role is genuinely stopped.
        if ($sawUnverifiablePath -and -not $sawReadableMismatch) { return $true }

        return $false
    }

    # Fallback: look for known process name aliases.
    foreach ($p in $ProcessAliases[$Role]) {
        try {
            if (Get-Process -Name $p -ErrorAction SilentlyContinue) { return $true }
        } catch { }
    }
    return $false
}

function Test-RoleHealthy {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("MySQL","Authserver","Worldserver")]
        [string]$Role,

        [string]$ExpectedPath,

        [int]$Port = 0,

        [int]$CacheTtlSec = 5,

        [int]$NegativeCacheTtlSec = 15,

        [switch]$SkipCache
    )

    if (-not (Test-ProcessRoleRunning -Role $Role -ExpectedPath $ExpectedPath)) {
        return $false
    }

    if ($Port -le 0) {
        return $true
    }

    if (-not $script:PortCheckCache) {
        $script:PortCheckCache = @{}
    }

    if (-not $SkipCache) {
        if ($script:PortCheckCache.ContainsKey($Role)) {
            $cached = $script:PortCheckCache[$Role]
            if ($cached) {
                $age = ((Get-Date) - $cached.Timestamp).TotalSeconds
                if ($cached.Result -and ($CacheTtlSec -gt 0) -and ($age -lt $CacheTtlSec)) {
                    return $true
                }
                if (-not $cached.Result -and ($NegativeCacheTtlSec -gt 0) -and ($age -lt $NegativeCacheTtlSec)) {
                    return $false
                }
            }
        }
    }

    $result = (Test-PortOpen -HostName "127.0.0.1" -Port $Port)
    $script:PortCheckCache[$Role] = [pscustomobject]@{
        Timestamp = Get-Date
        Result    = $result
    }
    return $result
}

# -------------------------------
# Restart tracking
# -------------------------------
$LastRestart = @{
    MySQL      = Get-Date "2000-01-01"
    Authserver = Get-Date "2000-01-01"
    Worldserver= Get-Date "2000-01-01"
}

# Per-role crash-loop tracking. Hashtable contents are mutated in place so the
# counts persist across Ensure-Role calls regardless of variable scope.
$RestartBurstStart = @{
    MySQL      = $null
    Authserver = $null
    Worldserver= $null
}
$RestartBurstCount = @{
    MySQL      = 0
    Authserver = 0
    Worldserver= 0
}
# Once a role hits its limit we stop relaunching until the window resets; this
# flag throttles the suppression so we log it once instead of on every tick.
$RestartSuppressed = @{
    MySQL      = $false
    Authserver = $false
    Worldserver= $false
}

# Legacy script-scope aliases kept for GUI/API telemetry (mirror Worldserver).
$WorldRestartCount = 0
$WorldBurstStart   = $null

# -------------------------------
# Config loading + validation
# -------------------------------
$DefaultConfig = [ordered]@{
    ServerName  = ""
    Expansion   = "Unknown"
    MySQL       = ""
    Authserver  = ""
    Worldserver = ""
    MySQLPort       = 3310
    AuthserverPort  = 1119
    WorldserverPort = 8086
    PortCheckTtlSec     = 5
    PortCheckFailTtlSec = 15
    PortWarmupSec       = 180
    # MySQL graceful-shutdown settings: ask the database to flush and exit cleanly
    # instead of force-killing it. Password is stored in plaintext like the other
    # secrets in this file; leave blank for a passwordless local root account.
    MySQLUser               = "root"
    MySQLPassword           = ""
    MySQLAdmin              = ""    # optional explicit mysqladmin.exe / mariadb-admin.exe path
    MySQLShutdownTimeoutSec = 60
    API = [ordered]@{
        Enabled = $false
        Port    = 8099
        Bind    = "+"
    }
    NTFY = [ordered]@{
        Server           = ""
        Topic            = ""
        Tags             = "wow,watchdog"
        PriorityDefault  = 4
        EnableMySQL      = $true
        EnableAuthserver = $true
        EnableWorldserver= $true
        SendOnDown       = $true
        SendOnUp         = $false
    }
}

function Write-ConfigFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Object
    )

    try {
        $dir = Split-Path -Parent $Path
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
        $Object | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -Encoding UTF8
    } catch {
        Log "ERROR: Failed to write config to $Path. Error: $($_)"
    }
}

function Ensure-ConfigSchema {
    param(
        [Parameter(Mandatory)]$Cfg,
        [Parameter(Mandatory)]$Defaults
    )

    $changed = $false
    # Ensure any new default properties are backfilled into existing configs.
    foreach ($p in $Defaults.PSObject.Properties) {
        if (-not $Cfg.PSObject.Properties[$p.Name]) {
            $Cfg | Add-Member -MemberType NoteProperty -Name $p.Name -Value $p.Value
            $changed = $true
            continue
        }

        if ($p.Value -is [psobject] -and $Cfg.$($p.Name) -is [psobject]) {
            $nestedChanged = Ensure-ConfigSchema -Cfg $Cfg.$($p.Name) -Defaults $p.Value
            if ($nestedChanged) { $changed = $true }
        }
    }

    return $changed
}

function Load-ConfigSafe {
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        if ($global:LastConfigLoadState -ne "MissingConfig") {
            Log "config.json missing at $ConfigPath. Watchdog idle (will retry)."
            $global:LastConfigLoadState = "MissingConfig"
        }
        Write-ConfigFile -Path $ConfigPath -Object $DefaultConfig
        Write-Heartbeat -State "Idle" -Extra @{ reason = "MissingConfig"; configPath = $ConfigPath }
        return $null
    }

    try {
        $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        if ($cfg) {
            if (Ensure-ConfigSchema -Cfg $cfg -Defaults $DefaultConfig) {
                Write-ConfigFile -Path $ConfigPath -Object $cfg
            }
        }
        $global:LastConfigLoadState = ""
        return $cfg
    }
    catch {
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

    # Validate that configured paths exist before starting processes.
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
        if (-not (Test-Path -LiteralPath $p.Path)) {
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

    # Batch files need cmd.exe for proper execution.
    if ($Path -match '\.bat$') {
        Start-Process -FilePath "cmd.exe" `
            -ArgumentList "/c `"$Path`"" `
            -WorkingDirectory (Split-Path $Path) `
            -WindowStyle Hidden
        return
    }

    # Direct EXE path.
    Start-Process -FilePath $Path `
        -WorkingDirectory (Split-Path $Path) `
        -WindowStyle Hidden
}

# -------------------------------
# Graceful MySQL shutdown
# -------------------------------
function Resolve-MySQLAdmin {
    param($Cfg)

    # Prefer an explicitly configured admin client.
    $explicit = if ($Cfg) { [string]$Cfg.MySQLAdmin } else { "" }
    if (-not [string]::IsNullOrWhiteSpace($explicit) -and (Test-Path -LiteralPath $explicit)) {
        return $explicit
    }

    # Otherwise derive it from the folder of the configured MySQL binary (and its
    # neighbouring bin\ folder, the common repack layout: ...\database\bin\).
    $mysqlPath = if ($Cfg) { [string]$Cfg.MySQL } else { "" }
    if ([string]::IsNullOrWhiteSpace($mysqlPath)) { return $null }

    $dir = $null
    try { $dir = Split-Path -Parent $mysqlPath } catch { }
    if ([string]::IsNullOrWhiteSpace($dir)) { return $null }

    foreach ($d in @($dir, (Join-Path $dir "bin"))) {
        foreach ($name in @("mysqladmin.exe","mariadb-admin.exe")) {
            $cand = Join-Path $d $name
            if (Test-Path -LiteralPath $cand) { return $cand }
        }
    }
    return $null
}

function Stop-MySQLGracefully {
    param(
        [Parameter(Mandatory)]$Cfg,
        [int]$TimeoutSec = 60
    )

    # MySQL/MariaDB must flush its buffers and checkpoint on the way down. A forced
    # kill leaves InnoDB to run crash recovery on the next start (slow) and risks
    # corruption, so ask the server to shut itself down and wait for it to exit.
    $admin = Resolve-MySQLAdmin -Cfg $Cfg
    if (-not $admin) {
        Log "MySQL graceful shutdown: mysqladmin/mariadb-admin not found (set MySQLAdmin in config); using process stop."
        return $false
    }

    $port = [int]$Cfg.MySQLPort
    $user = if (-not [string]::IsNullOrWhiteSpace([string]$Cfg.MySQLUser)) { [string]$Cfg.MySQLUser } else { "root" }
    $pass = [string]$Cfg.MySQLPassword

    $adminArgs = @("--host=127.0.0.1", "--port=$port", "--user=$user", "--connect-timeout=5")
    if (-not [string]::IsNullOrEmpty($pass)) { $adminArgs += "--password=$pass" }
    $adminArgs += "shutdown"

    try {
        Log "MySQL graceful shutdown via $admin (user '$user')."
        $proc = Start-Process -FilePath $admin -ArgumentList $adminArgs -WindowStyle Hidden -PassThru -ErrorAction Stop
        if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
            Log "MySQL graceful shutdown: admin client timed out after $TimeoutSec sec; using process stop."
            try { $proc.Kill() } catch { }
            return $false
        }
        if ($proc.ExitCode -ne 0) {
            Log "MySQL graceful shutdown: admin client exited with code $($proc.ExitCode); using process stop."
            return $false
        }
    } catch {
        Log "MySQL graceful shutdown command failed: $($_). Using process stop."
        return $false
    }

    # Confirm the server process is actually gone before reporting success.
    if (Wait-ForRoleDown -Role "MySQL" -ExpectedPath ([string]$Cfg.MySQL) -TimeoutSec $TimeoutSec) {
        Log "MySQL shut down cleanly."
        return $true
    }

    Log "MySQL still running after graceful shutdown wait ($TimeoutSec sec); using process stop."
    return $false
}

# -------------------------------
# Stop a service/role.
# -------------------------------
function Stop-Role {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("MySQL","Authserver","Worldserver")]
        [string]$Role,

        $Cfg = $null
    )

    # MySQL: attempt a clean database shutdown before falling back to a hard stop so
    # the server flushes/checkpoints instead of being terminated mid-write.
    if ($Role -eq "MySQL" -and $Cfg) {
        $timeout = 60
        try { if ($Cfg.MySQLShutdownTimeoutSec) { $timeout = [int]$Cfg.MySQLShutdownTimeoutSec } } catch { }
        if (Stop-MySQLGracefully -Cfg $Cfg -TimeoutSec $timeout) {
            return
        }
    }

    # Stop by process name aliases to handle renamed binaries.
    foreach ($p in $ProcessAliases[$Role]) {
        try {
            Get-Process -Name $p -ErrorAction SilentlyContinue |
                Stop-Process -Force -ErrorAction SilentlyContinue
        } catch { }
    }

    Log "$Role stop requested."
}

# -------------------------------
# Stop all roles gracefully
# -------------------------------
function Stop-All-Gracefully {
    param(
        [int]$DelaySec = 5,
        [int]$WaitTimeoutSec = 60,
        $Cfg
    )

    Log "Graceful shutdown initiated."

    # Stop in reverse dependency order: World -> Auth -> DB.
    Stop-Role -Role "Worldserver"
    if (-not (Wait-ForRoleDown -Role "Worldserver" -ExpectedPath ([string]$Cfg.Worldserver) -TimeoutSec $WaitTimeoutSec)) {
        Log "Graceful shutdown wait timed out for Worldserver."
    }
    Start-Sleep -Seconds $DelaySec

    Stop-Role -Role "Authserver"
    if (-not (Wait-ForRoleDown -Role "Authserver" -ExpectedPath ([string]$Cfg.Authserver) -TimeoutSec $WaitTimeoutSec)) {
        Log "Graceful shutdown wait timed out for Authserver."
    }
    Start-Sleep -Seconds $DelaySec

    Stop-Role -Role "MySQL" -Cfg $Cfg
    if (-not (Wait-ForRoleDown -Role "MySQL" -ExpectedPath ([string]$Cfg.MySQL) -TimeoutSec $WaitTimeoutSec)) {
        Log "Graceful shutdown wait timed out for MySQL."
    }

    Log "Graceful shutdown completed."
}


# -------------------------------
# Ensure proper startup. DB->Auth->World
# -------------------------------
function Wait-ForRole {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("MySQL","Authserver","Worldserver")]
        [string]$Role,

        [string]$ExpectedPath,

        [int]$Port = 0,

        [int]$TimeoutSec = 120
    )

    $start = Get-Date
    while (((Get-Date) - $start).TotalSeconds -lt $TimeoutSec) {
        if (Test-RoleHealthy -Role $Role -ExpectedPath $ExpectedPath -Port $Port -SkipCache) {
            return $true
        }
        Start-Sleep -Seconds 2
    }

    Log "Timeout waiting for $Role to become ready."
    return $false
}

function Wait-ForRoleDown {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("MySQL","Authserver","Worldserver")]
        [string]$Role,

        [string]$ExpectedPath,

        [int]$TimeoutSec = 60
    )

    $start = Get-Date
    while (((Get-Date) - $start).TotalSeconds -lt $TimeoutSec) {
        if (-not (Test-ProcessRoleRunning -Role $Role -ExpectedPath $ExpectedPath)) {
            return $true
        }
        Start-Sleep -Seconds 2
    }

    Log "Timeout waiting for $Role to stop."
    return $false
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
        [string]$Path,

        [int]$Port = 0,

        [int]$CacheTtlSec = 5,

        [int]$NegativeCacheTtlSec = 15,

        [int]$PortWarmupSec = 180,

        $Cfg = $null
    )

    # Manual hold (GUI-requested stop) — do not restart.
    if (Is-RoleHeld -Role $Role) {
        return
    }

    $processRunning = Test-ProcessRoleRunning -Role $Role -ExpectedPath $Path
    if ($processRunning) {
        if ($Port -le 0) { return }

        $portReady = Test-RoleHealthy -Role $Role -ExpectedPath $Path -Port $Port -CacheTtlSec $CacheTtlSec -NegativeCacheTtlSec $NegativeCacheTtlSec
        if ($portReady) {
            if ($script:PortWarmupStart) { $script:PortWarmupStart.Remove($Role) | Out-Null }
            return
        }

        if ($PortWarmupSec -gt 0) {
            if (-not $script:PortWarmupStart) { $script:PortWarmupStart = @{} }
            if (-not $script:PortWarmupStart.ContainsKey($Role)) {
                $script:PortWarmupStart[$Role] = Get-Date
            }
            $age = ((Get-Date) - $script:PortWarmupStart[$Role]).TotalSeconds
            if ($age -lt $PortWarmupSec) {
                return
            }
        }
    } else {
        if ($script:PortWarmupStart) { $script:PortWarmupStart.Remove($Role) | Out-Null }
    }

    # Restart cooldown.
    $delta = ((Get-Date) - $LastRestart[$Role]).TotalSeconds
    if ($delta -lt $RestartCooldown) { return }

    # Crash-loop protection for every role: bound how many times we relaunch a role
    # within the burst window so a stuck/failed detection cannot spawn unbounded
    # instances and exhaust system memory. (Hashtable mutation persists across calls.)
    $now = Get-Date
    if (-not $RestartBurstStart[$Role]) {
        $RestartBurstStart[$Role] = $now
        $RestartBurstCount[$Role] = 0
        $RestartSuppressed[$Role] = $false
    } else {
        $burstAge = ($now - $RestartBurstStart[$Role]).TotalSeconds
        if ($burstAge -gt $WorldserverBurst) {
            $RestartBurstStart[$Role] = $now
            $RestartBurstCount[$Role] = 0
            $RestartSuppressed[$Role] = $false
        }
    }

    # Already at the limit for this window: suppress without counting further or
    # spamming the log (log once, on the transition into suppression).
    if ($RestartBurstCount[$Role] -ge $MaxRestarts) {
        if (-not $RestartSuppressed[$Role]) {
            $RestartSuppressed[$Role] = $true
            Log "ERROR: $Role restart limit reached ($MaxRestarts in $WorldserverBurst sec). Suppressing restarts until the burst window resets."
        }
        return
    }

    $RestartBurstCount[$Role]++

    # Mirror Worldserver counters into the legacy script-scope vars for telemetry.
    if ($Role -eq "Worldserver") {
        $script:WorldBurstStart   = $RestartBurstStart[$Role]
        $script:WorldRestartCount = $RestartBurstCount[$Role]
    }

    # If the process is still running at this point it is wedged: up, but its port
    # never became ready within the warmup window. Relaunching without stopping it
    # would spawn a *duplicate* instance every cycle (bounded only by the burst cap),
    # which is exactly the memory-exhaustion failure the burst protection guards
    # against. Stop the stale instance first so this is a genuine restart, not a
    # second copy. Skip the relaunch this cycle if it refuses to die, so we never
    # accumulate duplicates.
    if ($processRunning) {
        Log "$Role is running but unhealthy (port $Port not ready after $PortWarmupSec sec warmup) — stopping stale instance before restart."
        # Pass the config so MySQL recycles via the same graceful shutdown used by
        # normal stop commands (flush/checkpoint before exit), only force-killing if
        # the database is unreachable. Without it InnoDB could be terminated mid-write.
        try { Stop-Role -Role $Role -Cfg $Cfg } catch { Log "ERROR stopping stale $Role: $($_)" }
        if ($script:PortWarmupStart) { $script:PortWarmupStart.Remove($Role) | Out-Null }
        if (-not (Wait-ForRoleDown -Role $Role -ExpectedPath $Path -TimeoutSec 15)) {
            Log "WARNING: stale $Role still running after stop request; deferring relaunch to avoid duplicate instances."
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
$script:ApiInitialized = $false

# -------------------------------
# Process start commands
# -------------------------------
function Process-Commands {
    param($Cfg)

    # --- START commands (ordered) ---
      if (Try-ConsumeCommandFile -Path $CommandFiles.StartMySQL) {
        Log "Command processed: command.start.mysql"
        Start-Target -Role "MySQL" -Path $Cfg.MySQL
    }

    if (Try-ConsumeCommandFile -Path $CommandFiles.StartAuthserver) {
        Log "Command processed: command.start.auth"

        if (Wait-ForRole -Role "MySQL" -ExpectedPath ([string]$Cfg.MySQL) -Port (Get-RolePort -Cfg $Cfg -Role "MySQL")) {
            Start-Target -Role "Authserver" -Path $Cfg.Authserver
        } else {
            Log "Authserver start blocked: MySQL not ready."
        }
    }

     if (Try-ConsumeCommandFile -Path $CommandFiles.StartWorld) {
        Log "Command processed: command.start.world"

        if (Wait-ForRole -Role "Authserver" -ExpectedPath ([string]$Cfg.Authserver) -Port (Get-RolePort -Cfg $Cfg -Role "Authserver")) {
            Start-Target -Role "Worldserver" -Path $Cfg.Worldserver
        } else {
            Log "Worldserver start blocked: Authserver not ready."
        }
    }

    # --- STOP commands ---
    $StopAllCmd = Join-Path $CommandDir "command.stop.all"

     if (Try-ConsumeCommandFile -Path $StopAllCmd) {
        Log "Command processed: command.stop.all"
        Stop-All-Gracefully -DelaySec $ShutdownDelaySec -Cfg $Cfg
    }


      if (Try-ConsumeCommandFile -Path $CommandFiles.StopWorld) {
        Log "Command processed: command.stop.world"
        Stop-Role -Role "Worldserver"
    }

     if (Try-ConsumeCommandFile -Path $CommandFiles.StopAuthserver) {
        Log "Command processed: command.stop.auth"
        Stop-Role -Role "Authserver"
    }

    if (Try-ConsumeCommandFile -Path $CommandFiles.StopMySQL) {
        Log "Command processed: command.stop.mysql"
        Stop-Role -Role "MySQL" -Cfg $Cfg
    }
}


# ===============================
# REST API (Android companion app)
# ===============================
$script:ApiListener   = $null
$script:ApiAsyncResult = $null
$script:ApiSecretsFile = Join-Path $DataDir "api.secrets.json"
$script:ApiRateLimit   = @{}  # IP -> { Failures, LockedUntil }

function Initialize-ApiListener {
    if (-not $ApiEnabled) {
        # Check config-driven API enable
        if ($cfg -and $cfg.API -and $cfg.API.Enabled -eq $true) {
            # Config says enable
        } else {
            return
        }
    }

    $port = $ApiPort
    $bind = $ApiBind
    if ($cfg -and $cfg.API) {
        if ($cfg.API.Port)  { $port = [int]$cfg.API.Port }
        if ($cfg.API.Bind)  { $bind = $cfg.API.Bind }
    }

    try {
        $script:ApiListener = New-Object System.Net.HttpListener
        $prefix = "http://${bind}:${port}/"
        $script:ApiListener.Prefixes.Add($prefix)
        $script:ApiListener.Start()
        $script:ApiAsyncResult = $script:ApiListener.BeginGetContext($null, $null)
        Log "REST API listening on $prefix"
    } catch {
        Log "ERROR: Failed to start REST API listener: $($_)"
        $script:ApiListener = $null
    }
}

function Get-OrCreateApiKey {
    # Load or generate API key, stored as plaintext in api.secrets.json
    # (DPAPI is Windows-only; for cross-platform compat we use a simple JSON file)
    if (Test-Path -LiteralPath $script:ApiSecretsFile) {
        try {
            $secrets = Get-Content -LiteralPath $script:ApiSecretsFile -Raw | ConvertFrom-Json
            if ($secrets.ApiKey) { return $secrets.ApiKey }
        } catch { }
    }

    # Generate a 48-character random API key
    $bytes = New-Object byte[] 36
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $key = [Convert]::ToBase64String($bytes) -replace '[+/=]',''
    $key = $key.Substring(0, [Math]::Min(48, $key.Length))

    $obj = [ordered]@{ ApiKey = $key; CreatedAt = (Get-Date).ToString("o") }
    try {
        $json = $obj | ConvertTo-Json -Depth 4
        Write-AtomicFile -Path $script:ApiSecretsFile -Content $json
    } catch {
        Log "ERROR: Failed to save API key: $($_)"
    }

    Log "REST API key generated. Key: $key"
    return $key
}

function Test-ApiKeyValid {
    param([string]$ProvidedKey)
    $expectedKey = Get-OrCreateApiKey
    return ($ProvidedKey -ceq $expectedKey)
}

function Test-ApiRateLimited {
    param([string]$IP)
    if (-not $script:ApiRateLimit.ContainsKey($IP)) { return $false }
    $entry = $script:ApiRateLimit[$IP]
    if ($entry.LockedUntil -and (Get-Date) -lt $entry.LockedUntil) { return $true }
    if ($entry.LockedUntil -and (Get-Date) -ge $entry.LockedUntil) {
        $script:ApiRateLimit.Remove($IP)
        return $false
    }
    return $false
}

function Add-ApiAuthFailure {
    param([string]$IP)
    if (-not $script:ApiRateLimit.ContainsKey($IP)) {
        $script:ApiRateLimit[$IP] = @{ Failures = 0; LockedUntil = $null }
    }
    $script:ApiRateLimit[$IP].Failures++
    if ($script:ApiRateLimit[$IP].Failures -ge 10) {
        $script:ApiRateLimit[$IP].LockedUntil = (Get-Date).AddMinutes(5)
        Log "REST API: IP $IP locked out for 5 minutes (too many failed auth attempts)"
    }
}

function Send-ApiResponse {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [int]$StatusCode = 200,
        $Body = $null
    )
    try {
        $Response.StatusCode = $StatusCode
        $Response.ContentType = "application/json; charset=utf-8"
        $Response.Headers.Add("Access-Control-Allow-Origin", "*")
        $Response.Headers.Add("Access-Control-Allow-Headers", "X-API-Key, Content-Type")
        $Response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

        if ($null -ne $Body) {
            $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 10 }
            $buf = [System.Text.Encoding]::UTF8.GetBytes($json)
            $Response.ContentLength64 = $buf.Length
            $Response.OutputStream.Write($buf, 0, $buf.Length)
        } else {
            $Response.ContentLength64 = 0
        }
    } catch { } finally {
        try { $Response.Close() } catch { }
    }
}

function Get-ApiStatusPayload {
    param($Cfg)

    $portCheckTtl     = if ($Cfg) { [int]$Cfg.PortCheckTtlSec } else { 5 }
    $portCheckFailTtl = if ($Cfg) { [int]$Cfg.PortCheckFailTtlSec } else { 15 }

    $services = [ordered]@{}
    foreach ($role in @("MySQL","Authserver","Worldserver")) {
        $expPath = if ($Cfg) { [string]$Cfg.$role } else { "" }
        $port    = if ($Cfg) { Get-RolePort -Cfg $Cfg -Role $role } else { 0 }
        $running = Test-RoleHealthy -Role $role -ExpectedPath $expPath -Port $port -CacheTtlSec $portCheckTtl -NegativeCacheTtlSec $portCheckFailTtl
        $held    = Is-RoleHeld -Role $role

        $services[$role.ToLower()] = [ordered]@{
            running = [bool]$running
            healthy = [bool]$running
            held    = [bool]$held
        }
    }

    return [ordered]@{
        timestamp         = (Get-Date).ToString("o")
        watchdog          = [ordered]@{ state = "Running"; pid = $PID }
        services          = $services
        worldRestartCount = $WorldRestartCount
        serverName        = if ($Cfg) { [string]$Cfg.ServerName } else { "" }
        expansion         = if ($Cfg) { [string]$Cfg.Expansion } else { "Unknown" }
    }
}

function Get-ApiConfigPayload {
    param($Cfg)
    if (-not $Cfg) { return @{ error = "No config loaded" } }
    return [ordered]@{
        serverName      = [string]$Cfg.ServerName
        expansion       = [string]$Cfg.Expansion
        mysqlPort       = [int]$Cfg.MySQLPort
        authserverPort  = [int]$Cfg.AuthserverPort
        worldserverPort = [int]$Cfg.WorldserverPort
        ntfy            = [ordered]@{
            server = [string]$Cfg.NTFY.Server
            topic  = [string]$Cfg.NTFY.Topic
        }
    }
}

function Get-ApiLogsPayload {
    param([int]$Lines = 50)
    if (-not (Test-Path -LiteralPath $LogFile)) { return @{ lines = @() } }
    try {
        $all = Get-Content -LiteralPath $LogFile -Tail $Lines -Encoding UTF8 -ErrorAction Stop
        return @{ lines = @($all) }
    } catch {
        return @{ lines = @(); error = "$($_)" }
    }
}

function Invoke-ApiCommand {
    param([string]$CommandName)
    $cmdPath = Join-Path $CommandDir $CommandName
    Write-AtomicFile -Path $cmdPath -Content ""
    Log "REST API command sent: $CommandName"
}

# --- RA Console Proxy State ---
$script:RaClient  = $null
$script:RaStream  = $null
$script:RaReader  = $null
$script:RaWriter  = $null
$script:RaBuffer  = New-Object System.Collections.Generic.List[string]

function Connect-RaConsole {
    param([string]$Host_, [int]$Port, [string]$Username, [string]$Password)
    try {
        Disconnect-RaConsole
        $script:RaClient = New-Object System.Net.Sockets.TcpClient
        $script:RaClient.Connect($Host_, $Port)
        $script:RaStream = $script:RaClient.GetStream()
        $script:RaStream.ReadTimeout = 500
        $script:RaReader = New-Object System.IO.StreamReader($script:RaStream, [System.Text.Encoding]::UTF8)
        $script:RaWriter = New-Object System.IO.StreamWriter($script:RaStream, [System.Text.Encoding]::UTF8)
        $script:RaWriter.AutoFlush = $true
        $script:RaBuffer.Clear()

        # Read login prompt, send credentials
        Start-Sleep -Milliseconds 300
        Read-RaAvailable | Out-Null
        $script:RaWriter.WriteLine($Username)
        Start-Sleep -Milliseconds 300
        Read-RaAvailable | Out-Null
        $script:RaWriter.WriteLine($Password)
        Start-Sleep -Milliseconds 500
        Read-RaAvailable | Out-Null

        return $true
    } catch {
        Log "REST API: RA console connect failed: $($_)"
        Disconnect-RaConsole
        return $false
    }
}

function Disconnect-RaConsole {
    try { if ($script:RaReader) { $script:RaReader.Dispose() } } catch { }
    try { if ($script:RaWriter) { $script:RaWriter.Dispose() } } catch { }
    try { if ($script:RaStream) { $script:RaStream.Dispose() } } catch { }
    try { if ($script:RaClient) { $script:RaClient.Close(); $script:RaClient.Dispose() } } catch { }
    $script:RaClient = $null
    $script:RaStream = $null
    $script:RaReader = $null
    $script:RaWriter = $null
}

function Read-RaAvailable {
    $lines = @()
    if (-not $script:RaStream -or -not $script:RaClient -or -not $script:RaClient.Connected) { return $lines }
    try {
        while ($script:RaStream.DataAvailable) {
            $line = $script:RaReader.ReadLine()
            if ($null -ne $line) {
                $lines += $line
                $script:RaBuffer.Add($line)
                # Keep buffer capped at 500 lines
                while ($script:RaBuffer.Count -gt 500) { $script:RaBuffer.RemoveAt(0) }
            }
        }
    } catch { }
    return $lines
}

function Send-RaCommand {
    param([string]$Command)
    if (-not $script:RaWriter -or -not $script:RaClient -or -not $script:RaClient.Connected) {
        return $false
    }
    try {
        $script:RaWriter.WriteLine($Command)
        return $true
    } catch { return $false }
}

function Handle-ApiRequest {
    param(
        [System.Net.HttpListenerContext]$Context,
        $Cfg
    )

    $req  = $Context.Request
    $resp = $Context.Response
    $path = $req.Url.AbsolutePath.TrimEnd('/')
    $method = $req.HttpMethod.ToUpper()
    $ip = $req.RemoteEndPoint.Address.ToString()

    # CORS preflight
    if ($method -eq "OPTIONS") {
        Send-ApiResponse -Response $resp -StatusCode 204
        return
    }

    # Health check (no auth required)
    if ($path -eq "/api/v1/health" -and $method -eq "GET") {
        Send-ApiResponse -Response $resp -StatusCode 200 -Body @{ status = "ok"; timestamp = (Get-Date).ToString("o") }
        return
    }

    # Rate limit check
    if (Test-ApiRateLimited -IP $ip) {
        Send-ApiResponse -Response $resp -StatusCode 429 -Body @{ error = "Too many failed attempts. Try again later." }
        return
    }

    # Auth check
    $apiKey = $req.Headers["X-API-Key"]
    if (-not $apiKey -or -not (Test-ApiKeyValid -ProvidedKey $apiKey)) {
        Add-ApiAuthFailure -IP $ip
        Send-ApiResponse -Response $resp -StatusCode 401 -Body @{ error = "Invalid or missing API key" }
        return
    }

    # Route dispatch
    try {
        switch -Regex ($path) {
            '^/api/v1/status$' {
                if ($method -ne "GET") { Send-ApiResponse -Response $resp -StatusCode 405 -Body @{ error = "Method not allowed" }; return }
                $payload = Get-ApiStatusPayload -Cfg $Cfg
                Send-ApiResponse -Response $resp -StatusCode 200 -Body $payload
            }
            '^/api/v1/config$' {
                if ($method -ne "GET") { Send-ApiResponse -Response $resp -StatusCode 405 -Body @{ error = "Method not allowed" }; return }
                $payload = Get-ApiConfigPayload -Cfg $Cfg
                Send-ApiResponse -Response $resp -StatusCode 200 -Body $payload
            }
            '^/api/v1/logs$' {
                if ($method -ne "GET") { Send-ApiResponse -Response $resp -StatusCode 405 -Body @{ error = "Method not allowed" }; return }
                $lines = 50
                $qs = $req.QueryString["lines"]
                if ($qs) { try { $lines = [Math]::Min([int]$qs, 500) } catch { } }
                $payload = Get-ApiLogsPayload -Lines $lines
                Send-ApiResponse -Response $resp -StatusCode 200 -Body $payload
            }
            '^/api/v1/services/(mysql|auth|world)/(start|stop|restart)$' {
                if ($method -ne "POST") { Send-ApiResponse -Response $resp -StatusCode 405 -Body @{ error = "Method not allowed" }; return }
                $roleKey = $Matches[1]
                $action  = $Matches[2]
                $cmdMap = @{
                    "mysql-start"   = "command.start.mysql"
                    "mysql-stop"    = "command.stop.mysql"
                    "auth-start"    = "command.start.auth"
                    "auth-stop"     = "command.stop.auth"
                    "world-start"   = "command.start.world"
                    "world-stop"    = "command.stop.world"
                }
                if ($action -eq "restart") {
                    Invoke-ApiCommand -CommandName $cmdMap["$roleKey-stop"]
                    Start-Sleep -Milliseconds 500
                    Invoke-ApiCommand -CommandName $cmdMap["$roleKey-start"]
                } else {
                    Invoke-ApiCommand -CommandName $cmdMap["$roleKey-$action"]
                }
                Send-ApiResponse -Response $resp -StatusCode 200 -Body @{ ok = $true; action = $action; role = $roleKey }
            }
            '^/api/v1/services/start-all$' {
                if ($method -ne "POST") { Send-ApiResponse -Response $resp -StatusCode 405 -Body @{ error = "Method not allowed" }; return }
                Invoke-ApiCommand -CommandName "command.start.mysql"
                Invoke-ApiCommand -CommandName "command.start.auth"
                Invoke-ApiCommand -CommandName "command.start.world"
                Send-ApiResponse -Response $resp -StatusCode 200 -Body @{ ok = $true; action = "start-all" }
            }
            '^/api/v1/services/stop-all$' {
                if ($method -ne "POST") { Send-ApiResponse -Response $resp -StatusCode 405 -Body @{ error = "Method not allowed" }; return }
                Invoke-ApiCommand -CommandName "command.stop.all"
                Send-ApiResponse -Response $resp -StatusCode 200 -Body @{ ok = $true; action = "stop-all" }
            }
            '^/api/v1/services/(mysql|auth|world)/hold$' {
                if ($method -ne "POST") { Send-ApiResponse -Response $resp -StatusCode 405 -Body @{ error = "Method not allowed" }; return }
                $roleMap = @{ "mysql" = "MySQL"; "auth" = "Authserver"; "world" = "Worldserver" }
                $role = $roleMap[$Matches[1]]
                $holdFile = Get-HoldFile -Role $role
                if (Test-Path $holdFile) {
                    Remove-Item -LiteralPath $holdFile -Force -ErrorAction SilentlyContinue
                    $held = $false
                    Log "REST API: Hold removed for $role"
                } else {
                    Write-AtomicFile -Path $holdFile -Content ""
                    $held = $true
                    Log "REST API: Hold set for $role"
                }
                Send-ApiResponse -Response $resp -StatusCode 200 -Body @{ ok = $true; role = $role; held = $held }
            }
            '^/api/v1/console/connect$' {
                if ($method -ne "POST") { Send-ApiResponse -Response $resp -StatusCode 405 -Body @{ error = "Method not allowed" }; return }
                $body = ""
                if ($req.HasEntityBody) {
                    $reader = New-Object System.IO.StreamReader($req.InputStream, $req.ContentEncoding)
                    $body = $reader.ReadToEnd()
                    $reader.Dispose()
                }
                $params = @{}
                if ($body) { try { $params = $body | ConvertFrom-Json } catch { } }
                $raHost = if ($params.host) { $params.host } else { "127.0.0.1" }
                $raPort = if ($params.port) { [int]$params.port } else { 3443 }
                $raUser = if ($params.username) { $params.username } else { "" }
                $raPass = if ($params.password) { $params.password } else { "" }
                $ok = Connect-RaConsole -Host_ $raHost -Port $raPort -Username $raUser -Password $raPass
                if ($ok) {
                    Send-ApiResponse -Response $resp -StatusCode 200 -Body @{ ok = $true; connected = $true }
                } else {
                    Send-ApiResponse -Response $resp -StatusCode 500 -Body @{ ok = $false; error = "Failed to connect to RA console" }
                }
            }
            '^/api/v1/console/send$' {
                if ($method -ne "POST") { Send-ApiResponse -Response $resp -StatusCode 405 -Body @{ error = "Method not allowed" }; return }
                $body = ""
                if ($req.HasEntityBody) {
                    $reader = New-Object System.IO.StreamReader($req.InputStream, $req.ContentEncoding)
                    $body = $reader.ReadToEnd()
                    $reader.Dispose()
                }
                $params = @{}
                if ($body) { try { $params = $body | ConvertFrom-Json } catch { } }
                $command = if ($params.command) { $params.command } else { "" }
                if (-not $command) {
                    Send-ApiResponse -Response $resp -StatusCode 400 -Body @{ error = "Missing 'command' field" }
                    return
                }
                $ok = Send-RaCommand -Command $command
                Start-Sleep -Milliseconds 300
                $output = Read-RaAvailable
                Send-ApiResponse -Response $resp -StatusCode 200 -Body @{ ok = $ok; output = @($output) }
            }
            '^/api/v1/console/output$' {
                if ($method -ne "GET") { Send-ApiResponse -Response $resp -StatusCode 405 -Body @{ error = "Method not allowed" }; return }
                $newLines = Read-RaAvailable
                $sinceIdx = 0
                $qs = $req.QueryString["since"]
                if ($qs) { try { $sinceIdx = [int]$qs } catch { } }
                $total = $script:RaBuffer.Count
                $lines = @()
                if ($sinceIdx -lt $total) {
                    $lines = @($script:RaBuffer.GetRange($sinceIdx, $total - $sinceIdx))
                }
                $connected = ($null -ne $script:RaClient -and $script:RaClient.Connected)
                Send-ApiResponse -Response $resp -StatusCode 200 -Body @{ lines = $lines; total = $total; connected = $connected }
            }
            '^/api/v1/console/disconnect$' {
                if ($method -ne "POST") { Send-ApiResponse -Response $resp -StatusCode 405 -Body @{ error = "Method not allowed" }; return }
                Disconnect-RaConsole
                Send-ApiResponse -Response $resp -StatusCode 200 -Body @{ ok = $true; connected = $false }
            }
            default {
                Send-ApiResponse -Response $resp -StatusCode 404 -Body @{ error = "Not found"; path = $path }
            }
        }
    } catch {
        Log "REST API error handling $method $path : $($_)"
        Send-ApiResponse -Response $resp -StatusCode 500 -Body @{ error = "Internal server error" }
    }
}

function Process-ApiRequests {
    param($Cfg)
    if (-not $script:ApiListener) { return }
    # Process up to 5 pending requests per tick
    for ($i = 0; $i -lt 5; $i++) {
        if (-not $script:ApiAsyncResult) {
            try { $script:ApiAsyncResult = $script:ApiListener.BeginGetContext($null, $null) } catch { return }
        }
        if ($script:ApiAsyncResult.IsCompleted) {
            try {
                $ctx = $script:ApiListener.EndGetContext($script:ApiAsyncResult)
                $script:ApiAsyncResult = $null
                Handle-ApiRequest -Context $ctx -Cfg $Cfg
            } catch {
                $script:ApiAsyncResult = $null
                Log "REST API listener error: $($_)"
            }
        } else {
            break
        }
    }
}

function Stop-ApiListener {
    if ($script:ApiListener) {
        try { $script:ApiListener.Stop() } catch { }
        try { $script:ApiListener.Close() } catch { }
        $script:ApiListener = $null
        Log "REST API listener stopped."
    }
    Disconnect-RaConsole
}

# -------------------------------
# Main loop
# -------------------------------
while ($true) {
    try {
        # Stop signal (GUI writes this) triggers graceful shutdown.
        if (Try-ConsumeCommandFile -Path $StopSignalFile) {
            Log "Stop signal detected ($StopSignalFile). Initiating graceful shutdown."

            Stop-All-Gracefully -DelaySec $ShutdownDelaySec -Cfg $cfg
            Stop-ApiListener

            Write-Heartbeat -State "Stopping" -Extra @{ reason = "StopSignal" }
            break

        }

        # Reload config periodically or if not loaded.
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

        # Initialize REST API once config is loaded
        if (-not $script:ApiInitialized) {
            Initialize-ApiListener
            $script:ApiInitialized = $true
        }

        Process-Commands -Cfg $cfg
        Process-ApiRequests -Cfg $cfg

        # Ensure roles (dependency order is enforced below).
        $portCheckTtlSec = [int]$cfg.PortCheckTtlSec
        $portCheckFailTtlSec = [int]$cfg.PortCheckFailTtlSec
        $portWarmupSec = [int]$cfg.PortWarmupSec

        Ensure-Role -Role "MySQL" -Path ([string]$cfg.MySQL) -Port (Get-RolePort -Cfg $cfg -Role "MySQL") -CacheTtlSec $portCheckTtlSec -NegativeCacheTtlSec $portCheckFailTtlSec -PortWarmupSec $portWarmupSec -Cfg $cfg

if (Test-RoleHealthy -Role "MySQL" -ExpectedPath ([string]$cfg.MySQL) -Port (Get-RolePort -Cfg $cfg -Role "MySQL") -CacheTtlSec $portCheckTtlSec -NegativeCacheTtlSec $portCheckFailTtlSec) {
    Ensure-Role -Role "Authserver" -Path ([string]$cfg.Authserver) -Port (Get-RolePort -Cfg $cfg -Role "Authserver") -CacheTtlSec $portCheckTtlSec -NegativeCacheTtlSec $portCheckFailTtlSec -PortWarmupSec $portWarmupSec -Cfg $cfg
}

if (Test-RoleHealthy -Role "Authserver" -ExpectedPath ([string]$cfg.Authserver) -Port (Get-RolePort -Cfg $cfg -Role "Authserver") -CacheTtlSec $portCheckTtlSec -NegativeCacheTtlSec $portCheckFailTtlSec) {
    Ensure-Role -Role "Worldserver" -Path ([string]$cfg.Worldserver) -Port (Get-RolePort -Cfg $cfg -Role "Worldserver") -CacheTtlSec $portCheckTtlSec -NegativeCacheTtlSec $portCheckFailTtlSec -PortWarmupSec $portWarmupSec -Cfg $cfg
}


        # Heartbeat + lightweight telemetry for GUI.
            $extra = @{
                mysqlRunning = (Test-RoleHealthy -Role "MySQL" -ExpectedPath ([string]$cfg.MySQL) -Port (Get-RolePort -Cfg $cfg -Role "MySQL") -CacheTtlSec $portCheckTtlSec -NegativeCacheTtlSec $portCheckFailTtlSec)
                authRunning  = (Test-RoleHealthy -Role "Authserver" -ExpectedPath ([string]$cfg.Authserver) -Port (Get-RolePort -Cfg $cfg -Role "Authserver") -CacheTtlSec $portCheckTtlSec -NegativeCacheTtlSec $portCheckFailTtlSec)
                worldRunning = (Test-RoleHealthy -Role "Worldserver" -ExpectedPath ([string]$cfg.Worldserver) -Port (Get-RolePort -Cfg $cfg -Role "Worldserver") -CacheTtlSec $portCheckTtlSec -NegativeCacheTtlSec $portCheckFailTtlSec)
                mysqlHeld    = (Is-RoleHeld -Role "MySQL")
                authHeld     = (Is-RoleHeld -Role "Authserver")
                worldHeld    = (Is-RoleHeld -Role "Worldserver")
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

Stop-ApiListener
Log "Watchdog service stopped."
Write-Heartbeat -State "Stopped" -Extra @{ reason = "Exited" }
