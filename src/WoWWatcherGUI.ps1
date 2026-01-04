<# 
    WoW Watchdog GUI Script
#>

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

if (-not (Test-IsAdmin)) {

    # Relaunch *this process*, not powershell.exe
    $exePath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

    try {
        Start-Process -FilePath $exePath -Verb RunAs
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
        Add-Content -Path (Join-Path $env:ProgramData "WoWWatchdog\crash.log") -Value $msg
    } catch { }
    break
}


Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

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

$AppVersion = [version]"1.1.9"
$RepoOwner  = "FAUSTUS1005"
$RepoName   = "WoW-Watchdog"

# -------------------------------------------------
# Paths / constants
# -------------------------------------------------
# Canonical paths and globals
# -------------------------------------------------
$AppName     = "WoWWatchdog"
$ExePath     = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$InstallDir  = Split-Path -Parent $ExePath
$ScriptDir   = $InstallDir

$DataDir     = Join-Path $env:ProgramData $AppName
if (-not (Test-Path $DataDir)) {
    New-Item -Path $DataDir -ItemType Directory -Force | Out-Null
}

$ConfigPath     = Join-Path $DataDir "config.json"
$SecretsPath    = Join-Path $DataDir "secrets.json"
$LogPath        = Join-Path $DataDir "watchdog.log"
$HeartbeatFile  = Join-Path $DataDir "watchdog.heartbeat"
$StopSignalFile = Join-Path $DataDir "watchdog.stop"

$ServiceName    = "WoWWatchdog"

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
    param([Parameter(Mandatory)][ValidateSet("BasicPassword","Token")][string]$Kind)

    $server = ""
    $topic  = ""
    try { $server = [string]$TxtNtfyServer.Text } catch { }
    try { $topic  = [string]$TxtNtfyTopic.Text } catch { }

    $server = ($server.Trim()).TrimEnd('/')
    $topic  = ($topic.Trim()).Trim('/')

    if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($topic)) {
        return "NTFY::$Kind"
    }

    return "NTFY::$Kind::$server/$topic"
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

function Get-LatestGitHubRelease {
    param(
        [Parameter(Mandatory)][string]$Owner,
        [Parameter(Mandatory)][string]$Repo
    )

    $uri = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
    $headers = @{
        "User-Agent" = "WoWWatchdog"
        "Accept"     = "application/vnd.github+json"
    }

    # If rate limited enable
    # $headers["Authorization"] = "Bearer $($env:GITHUB_TOKEN)"

    return Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
}

function Parse-ReleaseVersion {
    param([string]$TagName)

    $t = ""
    if ($TagName) { $t = $TagName.Trim() }
    if ($t.StartsWith("v")) { $t = $t.Substring(1) }
    [version]$t
}

function Get-WoWWatchdogDataFolder {
    if ($global:WoWWatchdogDataDir -and (Test-Path $global:WoWWatchdogDataDir)) {
        return $global:WoWWatchdogDataDir
    }

    $base = Join-Path $env:APPDATA "WoWWatchdog"
    $data = Join-Path $base "data"
    if (-not (Test-Path $data)) { New-Item -ItemType Directory -Path $data -Force | Out-Null }
    $data
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

function Expand-ZipSafe {
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][string]$Destination
    )

    if (-not (Test-Path $Destination)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }

    Expand-Archive -Path $ZipPath -DestinationPath $Destination -Force
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

    # Otherwise, if anything is already installed, use it
    $existingExe = Get-FirstExeInFolder -Folder $InstallDir
    if ($existingExe) { return $existingExe }

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

# -------------------------------------------------
# XAML – Dark/Blue Theme
# -------------------------------------------------
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="WoW Watchdog"
        Width="920" Height="1000"
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
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

<TabControl Grid.Row="0"
            Margin="0,0,0,6"
            Background="#FF0D111A"
            BorderBrush="#FF2B3E5E"
            Foreground="White"
            Padding="4">

  <!-- ================================================= -->
  <!-- TAB 1: Main                                       -->
  <!-- ================================================= -->
  <TabItem Header="Main">
    <ScrollViewer VerticalScrollBarVisibility="Auto"
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
              <RowDefinition Height="Auto"/> <!-- Watchdog buttons -->
              <RowDefinition Height="Auto"/> <!-- Per-service buttons -->
              <RowDefinition Height="Auto"/> <!-- Start/Stop All -->
            </Grid.RowDefinitions>

            <!-- Watchdog -->
            <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,8">
              <Button x:Name="BtnStartWatchdog" Content="Start Watchdog" MinWidth="160"
                      Background="#FF2D7A3A" Foreground="White" Margin="0,0,10,0"/>
              <Button x:Name="BtnStopWatchdog" Content="Stop Watchdog" MinWidth="160"
                      Background="#FF7A3A3A" Foreground="White"/>
            </StackPanel>

            <!-- Per-service -->
            <StackPanel Grid.Row="1"
                        Orientation="Horizontal"
                        Margin="0,0,0,8">
              <Button x:Name="BtnStartMySQL"
                      Content="Start DB"
                      Width="90"
                      Margin="0,0,6,0"
                      Style="{StaticResource BtnStart}"/>

              <Button x:Name="BtnStopMySQL"
                      Content="Stop DB"
                      Width="90"
                      Margin="0,0,12,0"
                      Style="{StaticResource BtnStop}"/>

              <Button x:Name="BtnStartAuth"
                      Content="Start Auth"
                      Width="90"
                      Margin="0,0,6,0"
                      Style="{StaticResource BtnStart}"/>

              <Button x:Name="BtnStopAuth"
                      Content="Stop Auth"
                      Width="90"
                      Margin="0,0,12,0"
                      Style="{StaticResource BtnStop}"/>

              <Button x:Name="BtnStartWorld"
                      Content="Start World"
                      Width="100"
                      Margin="0,0,6,0"
                      Style="{StaticResource BtnStart}"/>

              <Button x:Name="BtnStopWorld"
                      Content="Stop World"
                      Width="100"
                      Style="{StaticResource BtnStop}"/>
            </StackPanel>

            <!-- Start/Stop All -->
            <StackPanel Grid.Row="2"
                        Orientation="Horizontal">
              <Button x:Name="BtnStartAll"
                      Content="Start All (Ordered)"
                      Width="180"
                      Margin="0,0,10,0"
                      Style="{StaticResource BtnStart}"/>

              <Button x:Name="BtnStopAll"
                      Content="Stop All (Graceful)"
                      Width="180"
                      Style="{StaticResource BtnStop}"/>
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
        <GroupBox Grid.Row="3" Foreground="White" HorizontalAlignment="Stretch" Margin="0,0,0,10">
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
      <RowDefinition Height="Auto"/>  <!-- Header -->
      <RowDefinition Height="Auto"/>  <!-- Buttons / tools -->
      <RowDefinition Height="*"/>     <!-- Future content -->
    </Grid.RowDefinitions>

        <!-- Tools tab content -->
        <Grid Margin="12">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <GroupBox Grid.Row="1" Margin="0,0,0,10" Foreground="White" HorizontalAlignment="Stretch">
            <GroupBox.Header>
            <TextBlock Text="Launchers"
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
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>

            <Button x:Name="BtnLaunchSppManager"
                    Grid.Column="0"
                    Content="SPP Legion V2 Manager"
                    MinWidth="220"
                    Height="40"
                    Background="#FF3478BF"
                    Foreground="White"
                    BorderBrush="#FF2B5E9A"
                    BorderThickness="1"
                    Margin="0,0,12,0"/>

        <TextBlock Grid.Column="1"
           TextWrapping="Wrap"
           Foreground="#FF86B5E5"
           VerticalAlignment="Center">
            <Hyperlink NavigateUri="https://github.com/skeezerbean">
            The latest release will be downloaded and launched. Credit to Skeezerbean.
            </Hyperlink>
        </TextBlock>

            </Grid>
        </GroupBox>

        <!-- Optional: status text -->
        <TextBlock Grid.Row="2"
                    x:Name="TxtToolsStatus"
                    Foreground="#FF86B5E5"
                    TextWrapping="Wrap"/>
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

          </Grid>
        </GroupBox>

        <!-- Notes -->
        <TextBlock Grid.Row="2"
                   TextWrapping="Wrap"
                   Foreground="#FF86B5E5">
This application checks GitHub releases to determine if a newer version is available.
Updates are applied in-place and may restart services if required.
        </TextBlock>

      </Grid>
    </ScrollViewer>
  </TabItem>

</TabControl>

        <!-- Live Log (independent scroll) -->
<GroupBox Grid.Row="1" Foreground="White" HorizontalAlignment="Stretch" Margin="0,8,0,0">
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
        param($sender, $e)

        try {
            Start-Process $e.Uri.AbsoluteUri
            $e.Handled = $true
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
$BtnStartAll    = $Window.FindName("BtnStartAll")
$BtnStopAll     = $Window.FindName("BtnStopAll")
$BtnClearLog    = $Window.FindName("BtnClearLog")

# Server Info: DB controls
$TxtDbHost        = $Window.FindName("TxtDbHost")
$TxtDbPort        = $Window.FindName("TxtDbPort")
$TxtDbUser        = $Window.FindName("TxtDbUser")
$TxtDbNameChar    = $Window.FindName("TxtDbNameChar")
$TxtDbPassword    = $Window.FindName("TxtDbPassword")
$BtnSaveDbPassword= $Window.FindName("BtnSaveDbPassword")
$BtnTestDb        = $Window.FindName("BtnTestDb")

$TxtUtilMySQLCpu  = $Window.FindName("TxtUtilMySQLCpu")
$TxtUtilMySQLMem  = $Window.FindName("TxtUtilMySQLMem")
$TxtUtilAuthCpu   = $Window.FindName("TxtUtilAuthCpu")
$TxtUtilAuthMem   = $Window.FindName("TxtUtilAuthMem")
$TxtUtilWorldCpu  = $Window.FindName("TxtUtilWorldCpu")
$TxtUtilWorldMem  = $Window.FindName("TxtUtilWorldMem")

# Tab: Update
$TxtCurrentVersion = $Window.FindName("TxtCurrentVersion")
$TxtLatestVersion  = $Window.FindName("TxtLatestVersion")
$BtnCheckUpdates   = $Window.FindName("BtnCheckUpdates")
$BtnUpdateNow      = $Window.FindName("BtnUpdateNow")

$BtnLaunchSppManager = $Window.FindName("BtnLaunchSppManager")

$TxtCurrentVersion.Text = $AppVersion.ToString()

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
        Add-GuiLog "Stop signal written. Requesting service stop..."

        if ($svc.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -ErrorAction Stop
        }

        Add-GuiLog "Service stop requested."
    } catch {
        Add-GuiLog "ERROR: Failed to stop service gracefully: $_"
    }
}

function Start-InnoUpdateFromUrl {
    param(
        [Parameter(Mandatory=$true)][string]$InstallerUrl,
        [Parameter(Mandatory=$true)][version]$LatestVersion,

        # Asset hygiene
        [string]$ExpectedAssetName = "WoWWatchdog-Setup.exe",
        [string]$ActualAssetName   = $null,   # pass release asset name

        # Basic integrity checks
        [int64]$MinBytes = 2034408,            # KB floor; adjust to installer size
        [string]$ExpectedSha256 = $null,

        # If your install location requires elevation, set to $true
        [switch]$RunAsAdmin
    )

    # ensure TLS 1.2 for GitHub
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

        if ($ExpectedAssetName) {
        $nameToCheck = if ($ActualAssetName) {
            $ActualAssetName
        } else {
            [IO.Path]::GetFileName((($InstallerUrl -split '\?')[0]))
        }

        if ($nameToCheck -and ($nameToCheck -ne $ExpectedAssetName)) {
            throw "Update asset mismatch. Expected '$ExpectedAssetName' but got '$nameToCheck'. Aborting update."
        }
    }

    # Stable filename in temp
    $assetName = if ($ActualAssetName) {
        $ActualAssetName
    } elseif ($ExpectedAssetName) {
        $ExpectedAssetName
    } else {
        "Update-$($LatestVersion).exe"
    }

    $tempPath = Join-Path $env:TEMP $assetName

    # Download
    try {
        if (Test-Path $tempPath) { Remove-Item $tempPath -Force -ErrorAction SilentlyContinue }
        Invoke-WebRequest -Uri $InstallerUrl -OutFile $tempPath -UseBasicParsing -ErrorAction Stop
    } catch {
        throw "Failed to download update installer. $($_.Exception.Message)"
    }

    if (-not (Test-Path $tempPath)) {
        throw "Update download did not produce a file at $tempPath"
    }

    # Basic sanity: size threshold
    $fi = Get-Item $tempPath -ErrorAction Stop
    if ($fi.Length -lt $MinBytes) {
        throw "Downloaded installer is unexpectedly small ($($fi.Length) bytes). Aborting update."
    }

    # Optional integrity: SHA256 match (only if you provide it somewhere)
    if ($ExpectedSha256) {
        try {
            $hash = (Get-FileHash -Path $tempPath -Algorithm SHA256 -ErrorAction Stop).Hash
        } catch {
            throw "Failed to compute SHA256 for installer. $($_.Exception.Message)"
        }
        if ($hash -ne $ExpectedSha256.ToUpperInvariant()) {
            throw "Installer SHA256 mismatch. Expected $ExpectedSha256 but got $hash. Aborting update."
        }
    }

    # Launch Inno installer silently
    $args = @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/SP-"
    ) -join " "

    try {
        $sp = @{
            FilePath         = $tempPath
            ArgumentList     = $args
            WorkingDirectory = (Split-Path $tempPath)
        }

        if ($RunAsAdmin) {
            Start-Process @sp -Verb RunAs | Out-Null
        } else {
            Start-Process @sp | Out-Null
        }
    } catch {
        throw "Failed to start installer. $($_.Exception.Message)"
    }

    return $true
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
        # If your exe name differs, adjust this (no .exe needed)
        $p = Get-Process -Name "worldserver" -ErrorAction SilentlyContinue | Select-Object -First 1

        if ($null -eq $p) {
            $TxtWorldUptime.Text = "Stopped"
            return
        }

        $uptime = (Get-Date) - $p.StartTime
        $TxtWorldUptime.Text = (Format-Uptime -Span $uptime)
    } catch {
        # StartTime can throw if access is denied or process exits mid-read
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
# NTFY auth header helper
# -------------------------------------------------
function Get-NtfyAuthHeaders {
    param(
        [string]$Mode,
        [string]$Username,
        [string]$Password,
        [string]$Token
    )

    $headers = @{}
    $m = ""
    if ($Mode) { $m = $Mode.Trim() }

    switch ($m) {
        "None" { return $headers }

        "Basic (User/Pass)" {
            $u = ""
            if ($Username) { $u = $Username.Trim() }

            $pw = ""
            if (-not [string]::IsNullOrWhiteSpace($Password)) {
                $pw = $Password
            } else {
                $pw = Get-NtfySecret -Kind "BasicPassword"
            }

            if (-not [string]::IsNullOrWhiteSpace($u) -and -not [string]::IsNullOrWhiteSpace($pw)) {
                $pair = "{0}:{1}" -f $u, $pw
                $b64  = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair))
                $headers["Authorization"] = "Basic $b64"
            }
            return $headers
        }

        "Token (Bearer)" {
            $tk = ""
            if (-not [string]::IsNullOrWhiteSpace($Token)) {
                $tk = $Token
            } else {
                $tk = Get-NtfySecret -Kind "Token"
            }

            if (-not [string]::IsNullOrWhiteSpace($tk)) {
                $headers["Authorization"] = "Bearer $tk"
            }
            return $headers
        }

        default {
            # Unknown -> treat as None
            return $headers
        }
    }
}

# -------------------------------------------------
# GUI log helper
# -------------------------------------------------
function Add-GuiLog {
    param([string]$Message)

    try {
        $tsFile = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
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
    $ok = $dlg.ShowDialog()
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
            $proc = Get-Process -Name $name -ErrorAction SilentlyContinue
            if ($proc) {
                return $proc
            }
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
    if (-not $global:NtfyBaselineInitialized) {
        return
    }

    # Suppression window (hybrid behavior)
    if ($global:NtfySuppressUntil -and (Get-Date) -lt $global:NtfySuppressUntil) {
        return
    }

    # Require server + topic
    if ([string]::IsNullOrWhiteSpace($TxtNtfyServer.Text) -or
        [string]::IsNullOrWhiteSpace($TxtNtfyTopic.Text)) {
        return
    }

    $sendOnDown = [bool]$ChkNtfyOnDown.IsChecked
    $sendOnUp   = [bool]$ChkNtfyOnUp.IsChecked

    # DOWN event (UP -> DOWN)
    if ($OldState -eq $true -and $NewState -eq $false -and -not $sendOnDown) { return }

    # UP event (DOWN -> UP)
    if ($OldState -eq $false -and $NewState -eq $true -and -not $sendOnUp) { return }

    # Per-service enable switches
    switch ($ServiceName) {
        "MySQL"      { if (-not $ChkNtfyMySQL.IsChecked) { return } }
        "Authserver" { if (-not $ChkNtfyAuthserver.IsChecked) { return } }
        "Worldserver"{ if (-not $ChkNtfyWorldserver.IsChecked) { return } }
    }

    function Get-ComboContent {
        param([System.Windows.Controls.ComboBox]$Combo)
        $item = $Combo.SelectedItem
        if (-not $item) { return "" }
        return [string]$item.Content
    }

    function Get-ExpansionCurrent {
        $sel = $CmbExpansion.SelectedItem
        $exp = if ($sel) { [string]$sel.Content } else { "" }
        if ($exp -eq "Custom") {
            $exp = $TxtExpansionCustom.Text.Trim()
        }
        if ([string]::IsNullOrWhiteSpace($exp)) { $exp = "Unknown" }
        return $exp
    }

    function Get-PrimaryIPv4 {
        try {
            $ip = Get-NetIPAddress -AddressFamily IPv4 -InterfaceOperationalStatus Up -ErrorAction Stop |
                Where-Object { $_.IPAddress -and $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254*" } |
                Select-Object -First 1 -ExpandProperty IPAddress
            if ($ip) { return $ip }
        } catch { }
        return "Unknown"
    }

    # Cached identity (resolve once)
    if (-not $global:WowWatchdogIdentity) {
        $global:WowWatchdogIdentity = [pscustomobject]@{
            Hostname   = $env:COMPUTERNAME
            IPAddress  = (Get-PrimaryIPv4)
        }
    }

    $expansion = Get-ExpansionCurrent
    $hostname  = $global:WowWatchdogIdentity.Hostname
    $ipaddr    = $global:WowWatchdogIdentity.IPAddress
    $serverName = [string]$Config.ServerName
    if ([string]::IsNullOrWhiteSpace($serverName)) { $serverName = $hostname }

    $prev = if ($OldState) { "UP" } else { "DOWN" }
    $curr = if ($NewState) { "UP" } else { "DOWN" }
    $ts   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    $server = $TxtNtfyServer.Text.TrimEnd('/')
    $topic  = $TxtNtfyTopic.Text.Trim('/')
    $url    = "$server/$topic"

    # Priority (global default + per-service override)
    $prio = 4
    $globalPrioStr = Get-ComboContent $CmbNtfyPriorityDefault
    [void][int]::TryParse($globalPrioStr, [ref]$prio)
    if ($prio -lt 1 -or $prio -gt 5) { $prio = 4 }

    $override = "Auto"
    switch ($ServiceName) {
        "MySQL"      { $override = Get-ComboContent $CmbPriMySQL }
        "Authserver" { $override = Get-ComboContent $CmbPriAuthserver }
        "Worldserver"{ $override = Get-ComboContent $CmbPriWorldserver }
    }
    if ($override -and $override -ne "Auto") {
        $o = 0
        if ([int]::TryParse($override, [ref]$o) -and $o -ge 1 -and $o -le 5) {
            $prio = $o
        }
    }

    # Tags (merge GUI tags + dynamic tags)
    $tagList = New-Object System.Collections.Generic.List[string]
    $rawTags = [string]$TxtNtfyTags.Text
    if (-not [string]::IsNullOrWhiteSpace($rawTags)) {
        foreach ($t in ($rawTags -split ",")) {
            $tt = $t.Trim()
            if ($tt) { $tagList.Add($tt) }
        }
    }
    $tagList.Add("wow")
    $tagList.Add(($expansion.ToLower()))
    $tagList.Add(($ServiceName.ToLower()))
    $tagList.Add(($curr.ToLower()))

    # Unique tags
    $tagsUnique = ($tagList | Where-Object { $_ } | Select-Object -Unique)
    $tagsHeader = ($tagsUnique -join ",")

    $titleState = if ($curr -eq "DOWN") { "DOWN" } else { "RECOVERED" }
    $title = "[WoW Watchdog] $ServiceName $titleState ($expansion)"

    $message = @"
WoW Watchdog alert

Server: $serverName
Host:   $hostname
IP:     $ipaddr
Expansion: $expansion

Service: $ServiceName
Previous state: $prev
New state: $curr
Timestamp: $ts
"@

    try {
$headers = @{
    "Title"    = $title
    "Priority" = "$prio"
    "Tags"     = $tagsHeader
}

# Auth: None / Basic / Token
$mode = (Get-SelectedComboContent $CmbNtfyAuthMode).Trim()

$username = ""
if ($TxtNtfyUsername -and $TxtNtfyUsername.Text) { $username = [string]$TxtNtfyUsername.Text }

$password = ""
if ($TxtNtfyPassword) { $password = [string]$TxtNtfyPassword.Password }

$token = ""
if ($TxtNtfyToken) { $token = [string]$TxtNtfyToken.Password }   # PasswordBox

$authHeaders = Get-NtfyAuthHeaders -Mode $mode -Username $username -Password $password -Token $token
foreach ($k in $authHeaders.Keys) { $headers[$k] = $authHeaders[$k] }

Invoke-RestMethod -Uri $url -Method Post -Body $message -Headers $headers -ErrorAction Stop | Out-Null

        Add-GuiLog "Sent NTFY notification for $ServiceName state change ($prev -> $curr)."
    } catch {
        Add-GuiLog ("ERROR: Failed to send NTFY notification for {0}: {1}" -f $ServiceName, $_)
    }
}

function Send-NTFYTest {
    if ([string]::IsNullOrWhiteSpace($TxtNtfyServer.Text) -or
        [string]::IsNullOrWhiteSpace($TxtNtfyTopic.Text)) {
        Add-GuiLog "NTFY test failed: server or topic is empty."
        return
    }

    $server = $TxtNtfyServer.Text.TrimEnd('/')
    $topic  = $TxtNtfyTopic.Text.Trim('/')
    $url    = "$server/$topic"

    $expansion = "Unknown"
    try {
        $sel = $CmbExpansion.SelectedItem
        $expansion = if ($sel) { [string]$sel.Content } else { "Unknown" }
        if ($expansion -eq "Custom") {
            $expansion = $TxtExpansionCustom.Text.Trim()
            if ([string]::IsNullOrWhiteSpace($expansion)) { $expansion = "Custom" }
        }
    } catch { }

    $hostname = $env:COMPUTERNAME
    $ipaddr   = "Unknown"
    try {
        $ipaddr = Get-NetIPAddress -AddressFamily IPv4 -InterfaceOperationalStatus Up -ErrorAction Stop |
            Where-Object { $_.IPAddress -and $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254*" } |
            Select-Object -First 1 -ExpandProperty IPAddress
        if (-not $ipaddr) { $ipaddr = "Unknown" }
    } catch { }

    $prio = 4
    try {
        $pItem = $CmbNtfyPriorityDefault.SelectedItem
        if ($pItem) { [void][int]::TryParse([string]$pItem.Content, [ref]$prio) }
        if ($prio -lt 1 -or $prio -gt 5) { $prio = 4 }
    } catch { $prio = 4 }

    $tags = "wow,watchdog,test"
    $rawTags = [string]$TxtNtfyTags.Text
    if (-not [string]::IsNullOrWhiteSpace($rawTags)) {
        $tags = ($rawTags.Trim())
    }

    $title   = "[WoW Watchdog] Test Notification ($expansion)"
    $ts      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    $message = @"
WoW Watchdog NTFY Test

Host: $hostname
IP:   $ipaddr
Expansion: $expansion
Timestamp: $ts
"@

    try {
$headers = @{
    "Title"    = $title
    "Priority" = "$prio"
    "Tags"     = $tags
}

# Auth: None / Basic / Token
$mode = (Get-SelectedComboContent $CmbNtfyAuthMode).Trim()

$username = ""
if ($TxtNtfyUsername -and $TxtNtfyUsername.Text) { $username = [string]$TxtNtfyUsername.Text }

$password = ""
if ($TxtNtfyPassword) { $password = [string]$TxtNtfyPassword.Password }

$token = ""
if ($TxtNtfyToken) { $token = [string]$TxtNtfyToken.Password }


$authHeaders = Get-NtfyAuthHeaders -Mode $mode -Username $username -Password $password -Token $token
foreach ($k in $authHeaders.Keys) { $headers[$k] = $authHeaders[$k] }

Invoke-RestMethod -Uri $url -Method Post -Body $message -Headers $headers -ErrorAction Stop | Out-Null


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
    try {
        $Owner = "faustus1005"
        $Repo  = "WoW-Watchdog"

        $rel = Get-LatestGitHubRelease -Owner $Owner -Repo $Repo
        $latestVer = Parse-ReleaseVersion -TagName $rel.tag_name

        $asset = $rel.assets | Where-Object { $_.name -eq "WoWWatchdog-Setup.exe" } | Select-Object -First 1
        if ($null -eq $asset) {
            $names = @()
            if ($rel.assets) { $names = $rel.assets | ForEach-Object { $_.name } }
            throw ("Could not find 'WoWWatchdog-Setup.exe' in latest release assets. Found: " + ($names -join ", "))
        }

        # IMPORTANT: use browser_download_url, not asset.url/assets_url
        $ok = Start-InnoUpdateFromUrl `
            -InstallerUrl $asset.browser_download_url `
            -LatestVersion $latestVer `
            -ExpectedAssetName "WoWWatchdog-Setup.exe"

        if ($ok) {
            # Close the GUI so the installer can replace files
            $app = [System.Windows.Application]::Current
            if ($app -and $app.MainWindow) {
                $app.MainWindow.Close()
            } elseif ($app) {
                $app.Shutdown()
            }
        }
    }
    catch {
        [System.Windows.MessageBox]::Show(
            $_.Exception.Message,
            "Update Failed",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        ) | Out-Null
    }
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
try {
if ($authMode -eq "Basic (User/Pass)") {
    $plainPw = ""
    try { $plainPw = $TxtNtfyPassword.Password } catch { $plainPw = "" }

    if ([string]::IsNullOrWhiteSpace($plainPw)) {
        Remove-NtfySecret -Kind "BasicPassword"
    } else {
        Set-NtfySecret -Kind "BasicPassword" -Plain $plainPw
    }

    Remove-NtfySecret -Kind "Token"
}
elseif ($authMode -eq "Token (Bearer)") {
    $plainToken = ""
    try { $plainToken = $TxtNtfyToken.Password } catch { $plainToken = "" }

    if ([string]::IsNullOrWhiteSpace($plainToken)) {
        Remove-NtfySecret -Kind "Token"
    } else {
        Set-NtfySecret -Kind "Token" -Plain $plainToken
    }

    Remove-NtfySecret -Kind "BasicPassword"
}
else {
    # None: optional cleanup of both secrets
    # Remove-NtfySecret -Kind "BasicPassword"
    # Remove-NtfySecret -Kind "Token"
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

    $cfg = [pscustomobject]@{
        ServerName  = $Config.ServerName
        Expansion   = $expVal

        MySQL       = $TxtMySQL.Text
        MySQLExe    = $TxtMySQLExe.Text
        Authserver  = $TxtAuth.Text
        Worldserver = $TxtWorld.Text

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

        $dataRoot   = Get-WoWWatchdogDataFolder
        $installDir = Join-Path $dataRoot "SPP-LegionV2-Management"

        # Matches: SPP.LegionV2.Management.0.0.2.24.zip
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
    } catch { }
})

$timer.Start()


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
