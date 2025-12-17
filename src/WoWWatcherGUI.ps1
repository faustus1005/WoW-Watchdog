<# 
    WoW Watchdog GUI (PowerShell 5.1)
    --------------------------------

    Pairs with watchdog.ps1 in the same folder.

    Uses config.json:
        {
          "ServerName"  : "",
          "Expansion"   : "Unknown",
          "MySQL"       : "C:\\path\\to\\MySQL.bat",
          "Authserver"  : "C:\\path\\to\\authserver.exe",
          "Worldserver" : "C:\\path\\to\\worldserver.exe",
          "NTFY"        : {
              "Server"            : "https://ntfy.sh",
              "Topic"             : "wow-watchdog",
              "Tags"              : "wow,watchdog",
              "PriorityDefault"   : 4,
              "EnableMySQL"       : true,
              "EnableAuthserver"  : true,
              "EnableWorldserver" : true,
              "ServicePriorities" : {
                  "MySQL"       : 0,
                  "Authserver"  : 0,
                  "Worldserver" : 0
              },
              "SendOnDown"        : true,
              "SendOnUp"          : false
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
          - Expansion label (preset dropdown + custom)
          - Tags + Priority (global)
          - Per-service toggles
          - Per-service priority overrides (Auto/1-5)
          - Send On Down / Send On Up
          - Includes Server/Host/IP/Expansion in alerts

#>

# -------------------------------------------------
# Self-elevate to Administrator (EXE-safe + PS1-safe)
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
# Paths / constants
# -------------------------------------------------
# -------------------------------------------------
# Canonical paths (ProgramData-safe)
# -------------------------------------------------
$AppName = "WoWWatchdog"

$ExePath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$InstallDir = Split-Path -Parent $ExePath
$ScriptDir  = $InstallDir
$DataDir    = Join-Path $env:ProgramData $AppName

if (-not (Test-Path $DataDir)) {
    New-Item -Path $DataDir -ItemType Directory -Force | Out-Null
}

$ConfigPath     = Join-Path $DataDir "config.json"
$LogPath        = Join-Path $DataDir "watchdog.log"
$StopSignalFile = Join-Path $DataDir "stop_watchdog.txt"
$HeartbeatFile = Join-Path $DataDir "watchdog.heartbeat"
$StatusFile    = Join-Path $DataDir "watchdog.status.json"

$ServiceName      = "WoWWatchdog"
$LegacyServiceName = "MoPWatchdog"

# Status flags for LED + NTFY baseline
$global:MySqlUp       = $false
$global:AuthUp        = $false
$global:WorldUp       = $false
$global:NtfyBaselineInitialized = $false
$global:NtfySuppressUntil = $null

# -------------------------------------------------
# Ensure config.json exists
# -------------------------------------------------
if (-not (Test-Path $ConfigPath)) {
    $default = [pscustomobject]@{
        # Optional identity metadata (used for alert context)
        ServerName  = ""
        Expansion   = "Unknown"

        MySQL       = ""
        Authserver  = ""
        Worldserver = ""

        NTFY        = [pscustomobject]@{
            Server            = ""
            Topic             = ""
            Tags              = "wow,watchdog"
            PriorityDefault   = 4

            # Per-service enable switches
            EnableMySQL       = $true
            EnableAuthserver  = $true
            EnableWorldserver = $true

            # Per-service priority overrides (0 = Auto)
            ServicePriorities = [pscustomobject]@{
                MySQL       = 0
                Authserver  = 0
                Worldserver = 0
            }

            # State-change triggers
            SendOnDown        = $true
            SendOnUp          = $false
        }
    }
    $default | ConvertTo-Json -Depth 6 | Set-Content -Path $ConfigPath -Encoding UTF8
}

try {
    $Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
} catch {
    $Config = [pscustomobject]@{
        ServerName  = ""
        Expansion   = "Unknown"
        MySQL       = ""
        Authserver  = ""
        Worldserver = ""
    }
}

# Ensure root-level metadata exists (backward compatible)
$defaultRoot = [pscustomobject]@{
    ServerName = ""
    Expansion  = "Unknown"
}
foreach ($p in $defaultRoot.PSObject.Properties.Name) {
    if (-not $Config.PSObject.Properties[$p]) {
        $Config | Add-Member -Name $p -Value $defaultRoot.$p -MemberType NoteProperty
    }
}

# Ensure NTFY object exists and has expected fields
$defaultNtfy = [pscustomobject]@{
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
        Title="WoW Watchdog"
        Width="920" Height="720"
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

        <ScrollViewer Grid.Row="0"
                      VerticalScrollBarVisibility="Auto"
                      HorizontalScrollBarVisibility="Disabled">
          <Grid>
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <!-- Paths + Actions -->
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
                  <RowDefinition Height="Auto"/>
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

                <TextBlock Grid.Row="1" Grid.Column="0" Text="Authserver:" VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
                <TextBox x:Name="TxtAuth" Grid.Row="1" Grid.Column="1" Margin="4,2"
                         Background="#FF0F141F" Foreground="White" BorderBrush="#FF345A8A"/>
                <Button x:Name="BtnBrowseAuth" Grid.Row="1" Grid.Column="2" Content="Browse" MinWidth="80"
                        Background="#FF1B2A42" Foreground="White" BorderBrush="#FF2B3E5E" Margin="6,2,0,2"/>

                <TextBlock Grid.Row="2" Grid.Column="0" Text="Worldserver:" VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
                <TextBox x:Name="TxtWorld" Grid.Row="2" Grid.Column="1" Margin="4,2"
                         Background="#FF0F141F" Foreground="White" BorderBrush="#FF345A8A"/>
                <Button x:Name="BtnBrowseWorld" Grid.Row="2" Grid.Column="2" Content="Browse" MinWidth="80"
                        Background="#FF1B2A42" Foreground="White" BorderBrush="#FF2B3E5E" Margin="6,2,0,2"/>

                <StackPanel Grid.Row="3" Grid.Column="0" Grid.ColumnSpan="3" Orientation="Horizontal" Margin="0,8,0,0">
                  <Button x:Name="BtnSaveConfig" Content="Save Config" MinWidth="120"
                          Background="#FF3478BF" Foreground="White" Margin="0,0,10,0"/>
                  <Button x:Name="BtnStartWatchdog" Content="Start Watchdog" MinWidth="140"
                          Background="#FF2D7A3A" Foreground="White" Margin="0,0,10,0"/>
                  <Button x:Name="BtnStopWatchdog" Content="Stop Watchdog" MinWidth="140"
                          Background="#FF7A3A3A" Foreground="White" />
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
    <RowDefinition Height="Auto"/>
    <RowDefinition Height="Auto"/>
    <RowDefinition Height="Auto"/>
  </Grid.RowDefinitions>

  <!-- Watchdog runtime status -->
  <WrapPanel Grid.Row="0" Margin="0,0,0,6">
    <TextBlock Text="Watchdog:" Foreground="White" Margin="0,0,6,0"/>
    <TextBlock x:Name="TxtWatchdogStatus"
               Text="Stopped"
               Foreground="Orange"
               FontWeight="Bold"/>
  </WrapPanel>

  <!-- Windows service status (secondary, quieter) -->
  <WrapPanel Grid.Row="1" Margin="0,0,0,8">
    <TextBlock Text="Service:"
               Foreground="#FF86B5E5"
               Margin="0,0,6,0"/>
    <TextBlock x:Name="TxtServiceStatus"
               Text="Not installed"
               Foreground="#FFFFB347"
               FontWeight="SemiBold"/>
  </WrapPanel>

  <!-- Process LEDs -->
  <WrapPanel Grid.Row="2">
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
      <GradientStop Color="#FF151B28" Offset="0.0"/>
      <GradientStop Color="#FF111623" Offset="1.0"/>
    </LinearGradientBrush>
  </GroupBox.Background>

  <Grid Margin="10">
    <Grid.RowDefinitions>
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

    <!-- NTFY Topic -->
    <TextBlock Grid.Row="2" Grid.Column="0" Text="Topic:"
               VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
    <TextBox Grid.Row="2" Grid.Column="1"
             x:Name="TxtNtfyTopic"
             Margin="4,2"
             Background="#FF0F141F"
             Foreground="White"
             BorderBrush="#FF345A8A"/>

    <!-- NTFY Tags -->
    <TextBlock Grid.Row="3" Grid.Column="0" Text="Tags:"
               VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
    <TextBox Grid.Row="3" Grid.Column="1"
             x:Name="TxtNtfyTags"
             Margin="4,2"
             Background="#FF0F141F"
             Foreground="White"
             BorderBrush="#FF345A8A"/>

    <!-- Default Priority -->
    <TextBlock Grid.Row="4" Grid.Column="0" Text="Priority:"
               VerticalAlignment="Center" Foreground="White" Margin="0,0,4,0"/>
    <ComboBox Grid.Row="4" Grid.Column="1"
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
    <Grid Grid.Row="5" Grid.Column="0" Grid.ColumnSpan="3" Margin="0,6,0,0">
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
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="*"/>
            </Grid.RowDefinitions>

            <TextBlock Text="watchdog.log (updates every second)"
                       Foreground="#FF86B5E5"
                       Grid.Row="0" Margin="0,0,0,6"/>

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


# -------------------------------------------------
# Apply program icon (WoWWatcher.ico preferred; fallback to MoPWatcher.ico)
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

# -------------------------------------------------
# Get controls
# -------------------------------------------------
$BtnMinimize        = $Window.FindName("BtnMinimize")
$BtnClose           = $Window.FindName("BtnClose")

$TxtMySQL           = $Window.FindName("TxtMySQL")
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
$TxtNtfyTags           = $Window.FindName("TxtNtfyTags")
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

# Initial values from config
$TxtMySQL.Text  = $Config.MySQL
$TxtAuth.Text   = $Config.Authserver
$TxtWorld.Text  = $Config.Worldserver

$TxtServiceStatus = $Window.FindName("TxtServiceStatus")

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
        if ($svc.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force
        }
        Add-GuiLog "Service stopped."
    } catch {
        Add-GuiLog "ERROR: Failed to stop service: $_"
    }
}


# Expansion + NTFY values from config
Set-ExpansionUiFromConfig

$TxtNtfyServer.Text            = $Config.NTFY.Server
$TxtNtfyTopic.Text             = $Config.NTFY.Topic
$TxtNtfyTags.Text              = $Config.NTFY.Tags

# Default priority
$prioDefault = [int]$Config.NTFY.PriorityDefault
if ($prioDefault -lt 1 -or $prioDefault -gt 5) { $prioDefault = 4 }
[void](Select-ComboItemByContent -Combo $CmbNtfyPriorityDefault -Content ([string]$prioDefault))

# Per-service enable switches
$ChkNtfyMySQL.IsChecked        = [bool]$Config.NTFY.EnableMySQL
$ChkNtfyAuthserver.IsChecked   = [bool]$Config.NTFY.EnableAuthserver
$ChkNtfyWorldserver.IsChecked  = [bool]$Config.NTFY.EnableWorldserver

# Per-service priority overrides
$svcPri = $Config.NTFY.ServicePriorities
if (-not $svcPri) { $svcPri = [pscustomobject]@{} }

Set-PriorityOverrideCombo -Combo $CmbPriMySQL      -Value ([int]($svcPri.MySQL))
Set-PriorityOverrideCombo -Combo $CmbPriAuthserver -Value ([int]($svcPri.Authserver))
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

# -------------------------------------------------
# GUI log helper
# -------------------------------------------------
function Add-GuiLog {
    param([string]$Message)

    if (-not $Window) { return }

    $Window.Dispatcher.Invoke([action]{
        $ts = (Get-Date).ToString("HH:mm:ss")
        $TxtLiveLog.AppendText("[$ts] $Message`r`n")
        $TxtLiveLog.ScrollToEnd()
    })
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
        Invoke-RestMethod -Uri $url -Method Post -Body $message -Headers @{
            "Title"    = $title
            "Priority" = "$prio"
            "Tags"     = $tagsHeader
        } -ErrorAction Stop | Out-Null
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
        Invoke-RestMethod -Uri $url -Method Post -Body $message -Headers @{
            "Title"    = $title
            "Priority" = "$prio"
            "Tags"     = $tags
        } -ErrorAction Stop | Out-Null
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

    # MySQL
    if ($newMySql -ne $global:MySqlUp) {
        Send-NTFYAlert -ServiceName "MySQL" -OldState $global:MySqlUp -NewState $newMySql
        $global:MySqlUp = $newMySql
    }

    # Auth
    if ($newAuth -ne $global:AuthUp) {
        Send-NTFYAlert -ServiceName "Authserver" -OldState $global:AuthUp -NewState $newAuth
        $global:AuthUp = $newAuth
    }

    # World
    if ($newWorld -ne $global:WorldUp) {
        Send-NTFYAlert -ServiceName "Worldserver" -OldState $global:WorldUp -NewState $newWorld
        $global:WorldUp = $newWorld
    }

    # LEDs
    if ($global:MySqlUp) { $EllipseMySQL.Fill = $BrushLedGreen1 } else { $EllipseMySQL.Fill = $BrushLedRed }
    if ($global:AuthUp)  { $EllipseAuth.Fill  = $BrushLedGreen1 } else { $EllipseAuth.Fill  = $BrushLedRed }
    if ($global:WorldUp) { $EllipseWorld.Fill = $BrushLedGreen1 } else { $EllipseWorld.Fill = $BrushLedRed }
}


# -------------------------------------------------
# Events
# -------------------------------------------------
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

    $cfg = [pscustomobject]@{
        # Optional identity metadata used for richer alerts
        ServerName  = $Config.ServerName
        Expansion   = $expVal

        MySQL       = $TxtMySQL.Text
        Authserver  = $TxtAuth.Text
        Worldserver = $TxtWorld.Text

        NTFY        = [pscustomobject]@{
            Server            = $TxtNtfyServer.Text
            Topic             = $TxtNtfyTopic.Text
            Tags              = $TxtNtfyTags.Text
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

# -------------------------------------------------
# Timer – update status + log view
# -------------------------------------------------
Initialize-NtfyBaseline

$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(1)

$timer.Add_Tick({
    try {
        Update-ServiceStates
        Update-WatchdogStatusLabel
        Update-ServiceStatusLabel

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
