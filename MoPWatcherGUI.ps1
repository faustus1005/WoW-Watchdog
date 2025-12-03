<#
    MoP Watcher GUI (PowerShell 5.1)
    --------------------------------

    Pairs with watchdog.ps1 in the same folder.

    Uses config.json:
        {
          "MySQL"      : "C:\\path\\to\\MySQL.bat",
          "Authserver" : "C:\\path\\to\\authserver.exe",
          "Worldserver": "C:\\path\\to\\worldserver.exe",
          "NTFY"       : {
              "Server"           : "https://ntfy.sh",
              "Topic"            : "mytopic",
              "EnableMySQL"      : true,
              "EnableAuthserver" : true,
              "EnableWorldserver": true,
              "SendOnDown"       : true,
              "SendOnUp"         : false
          }
        }

    GUI Features:
      * Dark / blue themed UI, rounded outer window, drop shadow
      * Custom title bar (no system chrome)
      * Minimize + Close buttons in title bar
      * Browse + save paths to config.json
      * Start / Stop watchdog.ps1
      * Watchdog status label (Running / Stopped)
      * Process status LEDs (mysqld, authserver, worldserver) with soft pulse animation
      * NTFY notifications:
          - Server + Topic
          - Per-service toggles
          - Send On Down / Send On Up
          - Test Notification button
          - Baseline + 2s suppression on startup to avoid false alerts
      * Live tail of watchdog.log
          - Own scroll bar
          - Bottom panel resizes with window
      * Optional service panel:
          - Install / Uninstall Windows service "MoPWatchdog"
          - Start / Stop service
      * Clean exit:
          - Writes stop_watchdog.txt to end watchdog loop
          - Leaves MySQL/Auth/World processes running
#>

Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase,System.Drawing,System.Windows.Forms

# -------------------------------------------------
# Paths & globals
# -------------------------------------------------
if ($PSScriptRoot) {
    $ScriptDir = $PSScriptRoot
} elseif ($PSCommandPath) {
    $ScriptDir = Split-Path -Parent $PSCommandPath
} else {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

Set-Location $ScriptDir

$ConfigPath       = Join-Path $ScriptDir "config.json"
$WatchdogPath     = Join-Path $ScriptDir "watchdog.ps1"
$LogPath          = Join-Path $ScriptDir "watchdog.log"
$StopSignalFile   = Join-Path $ScriptDir "stop_watchdog.txt"
$ServiceName      = "MoPWatchdog"

$global:WatchdogPID   = $null
$global:ExitRequested = $false

# Status flags for LED animation + previous state (for NTFY)
$global:MySqlUp     = $false
$global:AuthUp      = $false
$global:WorldUp     = $false
$global:PrevMySqlUp = $false
$global:PrevAuthUp  = $false
$global:PrevWorldUp = $false
$global:LedPhase    = $false

# NTFY baseline / suppression controls
$global:NtfyBaselineInitialized = $false
$global:NtfySuppressUntil       = $null

# -------------------------------------------------
# Ensure config.json exists (basic skeleton)
# -------------------------------------------------
if (-not (Test-Path $ConfigPath)) {
    $default = [pscustomobject]@{
        MySQL       = ""
        Authserver  = ""
        Worldserver = ""
        NTFY        = [pscustomobject]@{
            Server            = ""
            Topic             = ""
            EnableMySQL       = $true
            EnableAuthserver  = $true
            EnableWorldserver = $true
            SendOnDown        = $true
            SendOnUp          = $false
        }
    }
    $default | ConvertTo-Json -Depth 4 | Set-Content -Path $ConfigPath -Encoding UTF8
}

try {
    $Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
} catch {
    $Config = [pscustomobject]@{
        MySQL       = ""
        Authserver  = ""
        Worldserver = ""
    }
}

# Ensure NTFY object exists and has expected fields
$defaultNtfy = [pscustomobject]@{
    Server            = ""
    Topic             = ""
    EnableMySQL       = $true
    EnableAuthserver  = $true
    EnableWorldserver = $true
    SendOnDown        = $true
    SendOnUp          = $false
}

if (-not $Config.PSObject.Properties['NTFY']) {
    $Config | Add-Member -Name NTFY -Value $defaultNtfy -MemberType NoteProperty
} else {
    foreach ($p in $defaultNtfy.PSObject.Properties.Name) {
        if (-not $Config.NTFY.PSObject.Properties[$p]) {
            $Config.NTFY | Add-Member -Name $p -Value $defaultNtfy.$p -MemberType NoteProperty
        }
    }
}

# -------------------------------------------------
# XAML – Dark/Blue, Rounded, Custom Title Bar, Gradient Panels, NTFY block, Autoscaling
# -------------------------------------------------
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="MoP Watchdog"
        Height="680"
        Width="940"
        MinHeight="600"
        MinWidth="800"
        ResizeMode="CanResizeWithGrip"
        WindowStartupLocation="CenterScreen"
        WindowStyle="None"
        AllowsTransparency="True"
        Background="Transparent">
  <Border CornerRadius="12" Background="#FF0B0F18" Padding="0">
    <Border.Effect>
      <DropShadowEffect Color="#AA000000" BlurRadius="18" ShadowDepth="0" Opacity="0.7"/>
    </Border.Effect>
    <Grid>
      <Grid.RowDefinitions>
        <RowDefinition Height="40"/>
        <RowDefinition Height="*"/>
        <RowDefinition Height="15"/>
      </Grid.RowDefinitions>

      <!-- Custom Title Bar -->
      <Grid x:Name="TitleBar" Grid.Row="0">
        <Grid.Background>
          <LinearGradientBrush StartPoint="0,0" EndPoint="1,0">
            <GradientStop Color="#FF101622" Offset="0.0" />
            <GradientStop Color="#FF152238" Offset="0.4" />
            <GradientStop Color="#FF1B3554" Offset="1.0" />
          </LinearGradientBrush>
        </Grid.Background>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>

        <TextBlock Grid.Column="0"
                   Text="MoP Watchdog"
                   Margin="16,0,8,0"
                   VerticalAlignment="Center"
                   Foreground="#FFEEF7FF"
                   FontSize="15"
                   FontWeight="SemiBold"/>

        <TextBlock Grid.Column="1"
                   Text="MySQL / Auth / World Monitor"
                   VerticalAlignment="Center"
                   Foreground="#FF7FA7D9"
                   FontSize="12"
                   Opacity="0.85"/>

        <!-- Minimize -->
        <Button x:Name="BtnTitleMinimize"
                Grid.Column="2"
                Width="36" Height="24"
                Margin="0,8,4,8"
                Background="#00102030"
                Foreground="#FFB0C4E0"
                BorderBrush="#00305070"
                BorderThickness="1"
                Padding="0"
                HorizontalAlignment="Center"
                VerticalAlignment="Center"
                FontSize="14">
          <TextBlock Text="&#x2013;" HorizontalAlignment="Center" VerticalAlignment="Center"/>
        </Button>

        <!-- Close -->
        <Button x:Name="BtnTitleClose"
                Grid.Column="3"
                Width="40" Height="24"
                Margin="0,8,12,8"
                Background="#20E81123"
                Foreground="#FFF5F5F5"
                BorderBrush="#40FF4B5C"
                BorderThickness="1"
                Padding="0"
                HorizontalAlignment="Center"
                VerticalAlignment="Center"
                FontSize="14">
          <TextBlock Text="X" HorizontalAlignment="Center" VerticalAlignment="Center"/>
        </Button>
      </Grid>

      <!-- Main Content -->
      <Grid Grid.Row="1" Margin="12">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <!-- Top section (scrollable if needed) -->
        <ScrollViewer Grid.Row="0"
                      VerticalScrollBarVisibility="Auto"
                      HorizontalScrollBarVisibility="Auto">
          <Grid>
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
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
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="Auto"/>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="Auto"/>
                  <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <!-- MySQL -->
                <TextBlock Grid.Row="0" Grid.Column="0" Text="MySQL script:"
                           VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
                <TextBox  x:Name="TxtMySQL" Grid.Row="0" Grid.Column="1" Margin="4,2"
                          Background="#FF0F141F" Foreground="White" BorderBrush="#FF345A8A"/>
                <Button   x:Name="BtnBrowseMySQL" Grid.Row="0" Grid.Column="2" Content="Browse..."
                          Margin="4,2" MinWidth="90"
                          Background="#FF2B537A" Foreground="White"/>
                <Ellipse  x:Name="EllipseMySQL" Grid.Row="0" Grid.Column="3"
                          Width="14" Height="14" Fill="Gray" Stroke="Black" VerticalAlignment="Center" Margin="4,0,0,0"/>

                <!-- Authserver -->
                <TextBlock Grid.Row="1" Grid.Column="0" Text="Authserver exe:"
                           VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
                <TextBox  x:Name="TxtAuth" Grid.Row="1" Grid.Column="1" Margin="4,2"
                          Background="#FF0F141F" Foreground="White" BorderBrush="#FF345A8A"/>
                <Button   x:Name="BtnBrowseAuth" Grid.Row="1" Grid.Column="2" Content="Browse..."
                          Margin="4,2" MinWidth="90"
                          Background="#FF2B537A" Foreground="White"/>
                <Ellipse  x:Name="EllipseAuth" Grid.Row="1" Grid.Column="3"
                          Width="14" Height="14" Fill="Gray" Stroke="Black" VerticalAlignment="Center" Margin="4,0,0,0"/>

                <!-- Worldserver -->
                <TextBlock Grid.Row="2" Grid.Column="0" Text="Worldserver exe:"
                           VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
                <TextBox  x:Name="TxtWorld" Grid.Row="2" Grid.Column="1" Margin="4,2"
                          Background="#FF0F141F" Foreground="White" BorderBrush="#FF345A8A"/>
                <Button   x:Name="BtnBrowseWorld" Grid.Row="2" Grid.Column="2" Content="Browse..."
                          Margin="4,2" MinWidth="90"
                          Background="#FF2B537A" Foreground="White"/>
                <Ellipse  x:Name="EllipseWorld" Grid.Row="2" Grid.Column="3"
                          Width="14" Height="14" Fill="Gray" Stroke="Black" VerticalAlignment="Center" Margin="4,0,0,0"/>
              </Grid>
            </GroupBox>

            <!-- Watchdog + Service -->
            <GroupBox Grid.Row="1" Margin="0,0,0,10" Foreground="White" HorizontalAlignment="Stretch">
              <GroupBox.Header>
                <TextBlock Text="Watchdog and Service Control"
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
                </Grid.RowDefinitions>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>

                <!-- Row 0: Buttons (WrapPanel for autoscaling) -->
                <WrapPanel Grid.Row="0" Grid.Column="0" Margin="0,0,0,6">
                  <Button x:Name="BtnSaveConfig" Content="Save Config" MinWidth="120" Margin="0,0,8,4"
                          Background="#FF2B537A" Foreground="White" />
                  <Button x:Name="BtnStartWatchdog" Content="Start Watchdog" MinWidth="140" Margin="0,0,8,4"
                          Background="#FF3478BF" Foreground="White" />
                  <Button x:Name="BtnStopWatchdog" Content="Stop Watchdog" MinWidth="120" Margin="0,0,8,4"
                          Background="#FF7A3A3A" Foreground="White" />
                  <Button x:Name="BtnExitGui" Content="Exit GUI" MinWidth="100" Margin="0,0,8,4"
                          Background="#FF444444" Foreground="White" />
                </WrapPanel>

                <!-- Row 1: Status + Service buttons -->
                <Grid Grid.Row="1" Grid.ColumnSpan="2" Margin="0,8,0,0">
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                  </Grid.ColumnDefinitions>

                  <!-- Status -->
                  <StackPanel Grid.Column="0" Orientation="Vertical" Margin="0,0,8,0">
                    <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
                      <TextBlock Text="Watchdog:" Foreground="White" Margin="0,0,6,0" />
                      <TextBlock x:Name="TxtWatchdogStatus" Text="Stopped" Foreground="Orange" FontWeight="Bold"/>
                    </StackPanel>
                    <StackPanel Orientation="Horizontal">
                      <TextBlock Text="Service:" Foreground="White" Margin="0,0,6,0" />
                      <TextBlock x:Name="TxtServiceStatus" Text="Not installed" Foreground="Orange" FontWeight="Bold"/>
                    </StackPanel>
                  </StackPanel>

                  <!-- Service buttons -->
                  <WrapPanel Grid.Column="1" HorizontalAlignment="Right">
                    <Button x:Name="BtnInstallService" Content="Install Service" MinWidth="120" Margin="4,0,0,4"
                            Background="#FF2B537A" Foreground="White" />
                    <Button x:Name="BtnUninstallService" Content="Uninstall" MinWidth="100" Margin="4,0,0,4"
                            Background="#FF7A3A3A" Foreground="White" />
                    <Button x:Name="BtnStartService" Content="Start Svc" MinWidth="90" Margin="4,0,0,4"
                            Background="#FF3478BF" Foreground="White" />
                    <Button x:Name="BtnStopService" Content="Stop Svc" MinWidth="90" Margin="4,0,0,4"
                            Background="#FF7A3A3A" Foreground="White" />
                  </WrapPanel>
                </Grid>
              </Grid>
            </GroupBox>

            <!-- NTFY Notifications -->
            <GroupBox Grid.Row="2" Margin="0,0,0,10" Foreground="White" HorizontalAlignment="Stretch">
              <GroupBox.Header>
                <TextBlock Text="NTFY Notifications"
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
                </Grid.RowDefinitions>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="Auto"/>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <!-- NTFY Server -->
                <TextBlock Grid.Row="0" Grid.Column="0" Text="NTFY Server:"
                           VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
                <TextBox  x:Name="TxtNtfyServer" Grid.Row="0" Grid.Column="1" Margin="4,2"
                          Background="#FF0F141F" Foreground="White" BorderBrush="#FF345A8A"
                          ToolTip="Example: https://ntfy.sh or your self-hosted URL"/>

                <!-- NTFY Topic -->
                <TextBlock Grid.Row="1" Grid.Column="0" Text="Topic:"
                           VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
                <TextBox  x:Name="TxtNtfyTopic" Grid.Row="1" Grid.Column="1" Margin="4,2"
                          Background="#FF0F141F" Foreground="White" BorderBrush="#FF345A8A"
                          ToolTip="Example: mop-watchdog"/>

                <!-- Checkboxes + Test -->
                <StackPanel Grid.Row="2" Grid.Column="0" Grid.ColumnSpan="3"
                            Orientation="Horizontal" Margin="0,4,0,0">
                  <CheckBox x:Name="ChkNtfyMySQL" Content="MySQL" Margin="0,0,10,0"
                            VerticalAlignment="Center" Foreground="White"/>
                  <CheckBox x:Name="ChkNtfyAuthserver" Content="Authserver" Margin="0,0,10,0"
                            VerticalAlignment="Center" Foreground="White"/>
                  <CheckBox x:Name="ChkNtfyWorldserver" Content="Worldserver" Margin="0,0,20,0"
                            VerticalAlignment="Center" Foreground="White"/>

                  <CheckBox x:Name="ChkNtfyOnDown" Content="Send on DOWN" Margin="0,0,10,0"
                            VerticalAlignment="Center" Foreground="White"/>
                  <CheckBox x:Name="ChkNtfyOnUp" Content="Send on UP" Margin="0,0,20,0"
                            VerticalAlignment="Center" Foreground="White"/>

                  <Button x:Name="BtnTestNtfy" Content="Test Notification" MinWidth="140"
                          Background="#FF3478BF" Foreground="White" />
                </StackPanel>
              </Grid>
            </GroupBox>
          </Grid>
        </ScrollViewer>

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
            <TextBox x:Name="LogBox"
                     AcceptsReturn="True"
                     VerticalScrollBarVisibility="Auto"
                     HorizontalScrollBarVisibility="Auto"
                     IsReadOnly="True"
                     FontFamily="Consolas"
                     Background="#FF0D111A"
                     Foreground="LightGray"/>
          </Grid>
        </GroupBox>
      </Grid>
    </Grid>
  </Border>
</Window>
"@

# -------------------------------------------------
# Load XAML
# -------------------------------------------------
[xml]$xamlXml = $xaml
$xmlReader     = New-Object System.Xml.XmlNodeReader $xamlXml
$Window        = [Windows.Markup.XamlReader]::Load($xmlReader)

# -------------------------------------------------
# Apply program icon (MoPWatcher.ico)
# -------------------------------------------------
$IconPath = Join-Path $ScriptDir "MoPWatcher.ico"
if (Test-Path $IconPath) {
    try {
        $Window.Icon = $IconPath
        Add-GuiLog "Program icon applied: $IconPath"
    } catch {
        Add-GuiLog "ERROR setting icon: $_"
    }
} else {
    Add-GuiLog "Icon not found: $IconPath"
}


# -------------------------------------------------
# Bind controls
# -------------------------------------------------
$TitleBar          = $Window.FindName("TitleBar")
$BtnTitleMinimize  = $Window.FindName("BtnTitleMinimize")
$BtnTitleClose     = $Window.FindName("BtnTitleClose")

$TxtMySQL          = $Window.FindName("TxtMySQL")
$TxtAuth           = $Window.FindName("TxtAuth")
$TxtWorld          = $Window.FindName("TxtWorld")
$BtnBrowseMySQL    = $Window.FindName("BtnBrowseMySQL")
$BtnBrowseAuth     = $Window.FindName("BtnBrowseAuth")
$BtnBrowseWorld    = $Window.FindName("BtnBrowseWorld")
$BtnSaveConfig     = $Window.FindName("BtnSaveConfig")
$BtnStartWatchdog  = $Window.FindName("BtnStartWatchdog")
$BtnStopWatchdog   = $Window.FindName("BtnStopWatchdog")
$BtnExitGui        = $Window.FindName("BtnExitGui")
$EllipseMySQL      = $Window.FindName("EllipseMySQL")
$EllipseAuth       = $Window.FindName("EllipseAuth")
$EllipseWorld      = $Window.FindName("EllipseWorld")
$LogBox            = $Window.FindName("LogBox")

$BtnInstallService   = $Window.FindName("BtnInstallService")
$BtnUninstallService = $Window.FindName("BtnUninstallService")
$BtnStartService     = $Window.FindName("BtnStartService")
$BtnStopService      = $Window.FindName("BtnStopService")
$TxtWatchdogStatus   = $Window.FindName("TxtWatchdogStatus")
$TxtServiceStatus    = $Window.FindName("TxtServiceStatus")

# NTFY controls
$TxtNtfyServer        = $Window.FindName("TxtNtfyServer")
$TxtNtfyTopic         = $Window.FindName("TxtNtfyTopic")
$ChkNtfyMySQL         = $Window.FindName("ChkNtfyMySQL")
$ChkNtfyAuthserver    = $Window.FindName("ChkNtfyAuthserver")
$ChkNtfyWorldserver   = $Window.FindName("ChkNtfyWorldserver")
$ChkNtfyOnDown        = $Window.FindName("ChkNtfyOnDown")
$ChkNtfyOnUp          = $Window.FindName("ChkNtfyOnUp")
$BtnTestNtfy          = $Window.FindName("BtnTestNtfy")

# Initial values from config
$TxtMySQL.Text     = $Config.MySQL
$TxtAuth.Text      = $Config.Authserver
$TxtWorld.Text     = $Config.Worldserver

$TxtNtfyServer.Text           = $Config.NTFY.Server
$TxtNtfyTopic.Text            = $Config.NTFY.Topic
$ChkNtfyMySQL.IsChecked       = [bool]$Config.NTFY.EnableMySQL
$ChkNtfyAuthserver.IsChecked  = [bool]$Config.NTFY.EnableAuthserver
$ChkNtfyWorldserver.IsChecked = [bool]$Config.NTFY.EnableWorldserver
$ChkNtfyOnDown.IsChecked      = [bool]$Config.NTFY.SendOnDown
$ChkNtfyOnUp.IsChecked        = [bool]$Config.NTFY.SendOnUp

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

# -------------------------------------------------
# GUI log helper
# -------------------------------------------------
function Add-GuiLog {
    param([string]$Message)

    if (-not $Window) { return }

    $Window.Dispatcher.Invoke([Action]{
        $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $LogBox.AppendText("[$ts] $Message`r`n")
        $LogBox.ScrollToEnd()
    })
}

# -------------------------------------------------
# Helper functions
# -------------------------------------------------
function Browse-File {
    param(
        [Parameter(Mandatory=$true)]$TextBox,
        [string]$Filter
    )

    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = $Filter
    if ($TextBox.Text -and (Test-Path $TextBox.Text)) {
        $dlg.InitialDirectory = Split-Path -Parent $TextBox.Text
    } else {
        $dlg.InitialDirectory = $ScriptDir
    }

    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $TextBox.Text = $dlg.FileName
    }
}

function Get-ProcessSafe {
    param([string]$name)
    try {
        Get-Process -Name $name -ErrorAction SilentlyContinue
    } catch {
        $null
    }
}

function Update-WatchdogStatusLabel {
    if ($global:WatchdogPID) {
        $p = Get-Process -Id $global:WatchdogPID -ErrorAction SilentlyContinue
        if ($p) {
            $TxtWatchdogStatus.Text       = "Running (PID $($global:WatchdogPID))"
            $TxtWatchdogStatus.Foreground = [System.Windows.Media.Brushes]::LimeGreen
            return
        } else {
            $global:WatchdogPID = $null
        }
    }
    $TxtWatchdogStatus.Text       = "Stopped"
    $TxtWatchdogStatus.Foreground = [System.Windows.Media.Brushes]::Orange
}

function Update-ServiceStatusLabel {
    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $svc) {
            $TxtServiceStatus.Text       = "Not installed"
            $TxtServiceStatus.Foreground = [System.Windows.Media.Brushes]::Orange
        } else {
            $TxtServiceStatus.Text = $svc.Status.ToString()
            if ($svc.Status -eq 'Running') {
                $TxtServiceStatus.Foreground = [System.Windows.Media.Brushes]::LimeGreen
            } elseif ($svc.Status -eq 'Stopped') {
                $TxtServiceStatus.Foreground = [System.Windows.Media.Brushes]::Red
            } else {
                $TxtServiceStatus.Foreground = [System.Windows.Media.Brushes]::Yellow
            }
        }
    } catch {
        $TxtServiceStatus.Text       = "Error"
        $TxtServiceStatus.Foreground = [System.Windows.Media.Brushes]::Red
    }
}

# -------------------------------------------------
# NTFY helpers
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
        "MySQL" {
            if (-not $ChkNtfyMySQL.IsChecked) { return }
        }
        "Authserver" {
            if (-not $ChkNtfyAuthserver.IsChecked) { return }
        }
        "Worldserver" {
            if (-not $ChkNtfyWorldserver.IsChecked) { return }
        }
    }

    $prev = if ($OldState) { "UP" } else { "DOWN" }
    $curr = if ($NewState) { "UP" } else { "DOWN" }
    $ts   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    $server = $TxtNtfyServer.Text.TrimEnd('/')
    $topic  = $TxtNtfyTopic.Text.Trim('/')
    $url    = "$server/$topic"

    $title   = "Service status change: $ServiceName"
    $message = @"
$ServiceName server status changed:
Previous state: $prev
New state: $curr
Timestamp: $ts
"@

    try {
        Invoke-RestMethod -Uri $url -Method Post -Body $message -Headers @{ "Title" = $title } -ErrorAction Stop | Out-Null
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

    $title   = "MoP Watchdog NTFY Test"
    $ts      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $message = "This is a test notification from MoP Watchdog GUI at $ts."

    try {
        Invoke-RestMethod -Uri $url -Method Post -Body $message -Headers @{ "Title" = $title } -ErrorAction Stop | Out-Null
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
        $global:MySqlUp     = [bool](Get-ProcessSafe "mysqld")
        $global:AuthUp      = [bool](Get-ProcessSafe "authserver")
        $global:WorldUp     = [bool](Get-ProcessSafe "worldserver")

        $global:PrevMySqlUp = $global:MySqlUp
        $global:PrevAuthUp  = $global:AuthUp
        $global:PrevWorldUp = $global:WorldUp

        $global:NtfyBaselineInitialized = $true
        $global:NtfySuppressUntil       = (Get-Date).AddSeconds(2)
        Add-GuiLog "NTFY baseline initialized (MySQL=$($global:MySqlUp), Auth=$($global:AuthUp), World=$($global:WorldUp))."
    } catch {
        Add-GuiLog "ERROR: Failed to initialize NTFY baseline: $_"
    }
}

# -------------------------------------------------
# Start/Stop watchdog
# -------------------------------------------------
function Start-Watchdog {
    if ($global:WatchdogPID) {
        $p = Get-Process -Id $global:WatchdogPID -ErrorAction SilentlyContinue
        if ($p) {
            Add-GuiLog "Watchdog already running (PID $($global:WatchdogPID))."
            return
        } else {
            $global:WatchdogPID = $null
        }
    }

    if (-not (Test-Path $WatchdogPath)) {
        Add-GuiLog "ERROR: watchdog.ps1 not found at $WatchdogPath"
        return
    }

    Add-GuiLog "Starting watchdog..."

    $psExe = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $args  = "-NoProfile -ExecutionPolicy Bypass -File `"$WatchdogPath`""

    try {
        $proc = Start-Process -FilePath $psExe -ArgumentList $args -PassThru -WindowStyle Hidden
        $global:WatchdogPID = $proc.Id
        Add-GuiLog "Watchdog started (PID $($proc.Id))."
    } catch {
        Add-GuiLog "ERROR: Failed to start watchdog: $_"
    }

    Update-WatchdogStatusLabel
}

function Stop-Watchdog {
    Add-GuiLog "Writing stop signal for watchdog..."
    New-Item -Path $StopSignalFile -ItemType File -Force | Out-Null
    $global:WatchdogPID = $null
    Update-WatchdogStatusLabel
}

# -------------------------------------------------
# Service control helpers (NSSM-based; require nssm.exe)
# -------------------------------------------------

# Path to nssm (must be placed next to this script)
$NssmPath = Join-Path $ScriptDir "nssm.exe"

function Get-NssmPath {
    if (Test-Path $NssmPath) {
        return $NssmPath
    } else {
        Add-GuiLog "ERROR: nssm.exe not found in $ScriptDir"
        Add-GuiLog "Download NSSM from https://nssm.cc and place nssm.exe in this folder."
        return $null
    }
}

function Install-WatchdogService {
    if (-not (Test-Path $WatchdogPath)) {
        Add-GuiLog "ERROR: watchdog.ps1 not found at $WatchdogPath"
        return
    }

    $nssm = Get-NssmPath
    if (-not $nssm) { return }

    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Add-GuiLog "Service '$ServiceName' already exists."
        Update-ServiceStatusLabel
        return
    }

    $psExe = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $args  = "-NoProfile -ExecutionPolicy Bypass -File `"$WatchdogPath`""

    try {
        Add-GuiLog "Installing service via NSSM..."
        & $nssm install $ServiceName $psExe $args | Out-Null

        # Ensure correct working directory
        & $nssm set $ServiceName AppDirectory $ScriptDir | Out-Null

        Add-GuiLog "Service '$ServiceName' installed via NSSM."
    } catch {
        Add-GuiLog "ERROR installing service via NSSM: $_"
    }

    Update-ServiceStatusLabel
}

function Uninstall-WatchdogService {
    $nssm = Get-NssmPath
    if (-not $nssm) { return }

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Add-GuiLog "Service '$ServiceName' is not installed."
        Update-ServiceStatusLabel
        return
    }

    try {
        if ($svc.Status -eq 'Running') {
            Stop-Service $ServiceName -ErrorAction SilentlyContinue
        }

        Add-GuiLog "Removing service via NSSM..."
        & $nssm remove $ServiceName confirm | Out-Null
        Add-GuiLog "Service removed."
    } catch {
        Add-GuiLog "ERROR removing service via NSSM: $_"
    }

    Update-ServiceStatusLabel
}

function Start-WatchdogService {
    try {
        Start-Service $ServiceName -ErrorAction Stop
        Add-GuiLog "Service '$ServiceName' started."
    } catch {
        Add-GuiLog "ERROR starting service: $_"
    }

    Update-ServiceStatusLabel
}

function Stop-WatchdogService {
    try {
        Stop-Service $ServiceName -ErrorAction Stop
        Add-GuiLog "Service '$ServiceName' stopped."
    } catch {
        Add-GuiLog "ERROR stopping service: $_"
    }

    Update-ServiceStatusLabel
}

# -------------------------------------------------
# Wire up UI events
# -------------------------------------------------
# Title bar: drag window
$TitleBar.Add_MouseLeftButtonDown({
    param($sender, $e)
    if ($e.ButtonState -eq [System.Windows.Input.MouseButtonState]::Pressed) {
        try { $Window.DragMove() } catch {}
    }
})

# Title bar buttons
$BtnTitleMinimize.Add_Click({
    $Window.WindowState = 'Minimized'
})

$BtnTitleClose.Add_Click({
    $global:ExitRequested = $true
    Stop-Watchdog
    $Window.Close()
})

# Browse buttons
$BtnBrowseMySQL.Add_Click({
    Browse-File -TextBox $TxtMySQL -Filter "Batch files (*.bat)|*.bat|All files (*.*)|*.*"
})

$BtnBrowseAuth.Add_Click({
    Browse-File -TextBox $TxtAuth -Filter "Executable files (*.exe)|*.exe|All files (*.*)|*.*"
})

$BtnBrowseWorld.Add_Click({
    Browse-File -TextBox $TxtWorld -Filter "Executable files (*.exe)|*.exe|All files (*.*)|*.*"
})

# Save config (including NTFY)
$BtnSaveConfig.Add_Click({
    $cfg = [pscustomobject]@{
        MySQL       = $TxtMySQL.Text
        Authserver  = $TxtAuth.Text
        Worldserver = $TxtWorld.Text
        NTFY        = [pscustomobject]@{
            Server            = $TxtNtfyServer.Text
            Topic             = $TxtNtfyTopic.Text
            EnableMySQL       = [bool]$ChkNtfyMySQL.IsChecked
            EnableAuthserver  = [bool]$ChkNtfyAuthserver.IsChecked
            EnableWorldserver = [bool]$ChkNtfyWorldserver.IsChecked
            SendOnDown        = [bool]$ChkNtfyOnDown.IsChecked
            SendOnUp          = [bool]$ChkNtfyOnUp.IsChecked
        }
    }
    $cfg | ConvertTo-Json -Depth 4 | Set-Content -Path $ConfigPath -Encoding UTF8
    Add-GuiLog "Configuration saved."
})

# Watchdog buttons
$BtnStartWatchdog.Add_Click({ Start-Watchdog })
$BtnStopWatchdog.Add_Click({ Stop-Watchdog })

# Exit button
$BtnExitGui.Add_Click({
    $global:ExitRequested = $true
    Stop-Watchdog
    $Window.Close()
})

# Service buttons
$BtnInstallService.Add_Click({ Install-WatchdogService })
$BtnUninstallService.Add_Click({ Uninstall-WatchdogService })
$BtnStartService.Add_Click({ Start-WatchdogService })
$BtnStopService.Add_Click({ Stop-WatchdogService })

# NTFY test button
$BtnTestNtfy.Add_Click({
    Send-NTFYTest
})

# Clean closing: always stop watchdog, tear down timers
$Window.Add_Closing({
    param($sender, $e)

    if (-not $global:ExitRequested) {
        Stop-Watchdog
    }

    if ($StatusTimer) { $StatusTimer.Stop() }
    if ($LedTimer)    { $LedTimer.Stop() }
    if ($LogTimer)    { $LogTimer.Stop() }
})

# -------------------------------------------------
# Status polling timer (updates flags and triggers NTFY on state change)
# -------------------------------------------------
$StatusTimer = New-Object System.Windows.Threading.DispatcherTimer
$StatusTimer.Interval = [TimeSpan]::FromMilliseconds(1500)
$StatusTimer.Add_Tick({
    try {
        # New states
        $newMySql  = [bool](Get-ProcessSafe "mysqld")
        $newAuth   = [bool](Get-ProcessSafe "authserver")
        $newWorld  = [bool](Get-ProcessSafe "worldserver")

        # Trigger NTFY on state change
        if ($global:PrevMySqlUp -ne $newMySql) {
            Send-NTFYAlert -ServiceName "MySQL" -OldState $global:PrevMySqlUp -NewState $newMySql
        }
        if ($global:PrevAuthUp -ne $newAuth) {
            Send-NTFYAlert -ServiceName "Authserver" -OldState $global:PrevAuthUp -NewState $newAuth
        }
        if ($global:PrevWorldUp -ne $newWorld) {
            Send-NTFYAlert -ServiceName "Worldserver" -OldState $global:PrevWorldUp -NewState $newWorld
        }

        # Update flags (current + previous)
        $global:MySqlUp     = $newMySql
        $global:AuthUp      = $newAuth
        $global:WorldUp     = $newWorld

        $global:PrevMySqlUp = $newMySql
        $global:PrevAuthUp  = $newAuth
        $global:PrevWorldUp = $newWorld

        Update-WatchdogStatusLabel
        Update-ServiceStatusLabel
    } catch {
        # ignore
    }
})
# Baseline before starting timer
Initialize-NtfyBaseline
$StatusTimer.Start()

# -------------------------------------------------
# LED pulse timer (uses flags to animate)
# -------------------------------------------------
$LedTimer = New-Object System.Windows.Threading.DispatcherTimer
$LedTimer.Interval = [TimeSpan]::FromMilliseconds(400)
$LedTimer.Add_Tick({
    try {
        $global:LedPhase = -not $global:LedPhase

        if ($global:MySqlUp) {
            $EllipseMySQL.Fill = if ($global:LedPhase) { $BrushLedGreen1 } else { $BrushLedGreen2 }
        } else {
            $EllipseMySQL.Fill = $BrushLedRed
        }

        if ($global:AuthUp) {
            $EllipseAuth.Fill = if ($global:LedPhase) { $BrushLedGreen1 } else { $BrushLedGreen2 }
        } else {
            $EllipseAuth.Fill = $BrushLedRed
        }

        if ($global:WorldUp) {
            $EllipseWorld.Fill = if ($global:LedPhase) { $BrushLedGreen1 } else { $BrushLedGreen2 }
        } else {
            $EllipseWorld.Fill = $BrushLedRed
        }
    } catch {
        # ignore
    }
})
$LedTimer.Start()

# -------------------------------------------------
# Log tail timer
# -------------------------------------------------
$LogTimer = New-Object System.Windows.Threading.DispatcherTimer
$LogTimer.Interval = [TimeSpan]::FromMilliseconds(1000)
$LogTimer.Add_Tick({
    try {
        if (Test-Path $LogPath) {
            $content = Get-Content $LogPath -ErrorAction SilentlyContinue
            if ($content) {
                $Window.Dispatcher.Invoke([Action]{
                    $LogBox.Text = ($content -join "`r`n")
                    $LogBox.ScrollToEnd()
                })
            }
        }
    } catch {
        # ignore read errors
    }
})
$LogTimer.Start()

# -------------------------------------------------
# Show GUI
# -------------------------------------------------
Update-WatchdogStatusLabel
Update-ServiceStatusLabel
$Window.ShowDialog() | Out-Null
