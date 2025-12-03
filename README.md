MoP Watchdog GUI
<p align="center"> <img src="https://img.shields.io/badge/PowerShell-5.1+-blue?logo=powershell&style=flat-square"/> <img src="https://img.shields.io/badge/Windows-10%20%7C%2011-lightgrey?logo=windows&style=flat-square"/> <img src="https://img.shields.io/badge/Status-Stable-success?style=flat-square"/> <img src="https://img.shields.io/badge/Notifications-NTFY-orange?style=flat-square"/> </p>

A modern WPF-powered GUI and service watchdog for MoP private servers (MySQL, Authserver, Worldserver).
Automatically monitors services, restarts crashed processes, and optionally sends ntfy notifications on status changes.

📸 Screenshots

You can replace these placeholders with your actual images later.

GUI Screenshot	Log Viewer

	
✨ Features
🎮 Server Monitoring

Live process monitoring: mysqld, authserver, worldserver

Automatic restarts if a service crashes

Real-time status LEDs (Running, Stopped, Unknown)

Smooth low-CPU pulsing animation for “Running”

🖥️ Modern GUI

Custom dark/blue window chrome

Rounded corners & custom title bar

Auto-scaling layout using WrapPanels

Independent scrollable log viewer

Responsive at all window sizes

🔔 NTFY Notifications (Optional)

Supports ntfy.sh or self-hosted ntfy servers

Notifications on UP and DOWN events

2-second suppression on startup prevents false alerts

“Test Notification” button built right into UI

🛠️ Windows Service Support

Install/Start/Stop/Uninstall the watchdog as a Windows Service

Start on boot

Service controls require admin mode

📜 Config + Logging

config.json auto-generated

watchdog.log automatically written and displayed in GUI

GUI always reflects real watchdog state

Clean stop using stop_watchdog.txt signaling

🚀 Quick Start
1. Download / Clone
C:\MoPWatcher\


Place the following files:

MoPWatcherGUI.ps1
watchdog.ps1
MopWatcher.ico


The rest will generate automatically:

config.json
watchdog.log
stop_watchdog.txt

2. Run the GUI

Right-click → Run with PowerShell
or:

powershell -ExecutionPolicy Bypass -File "C:\MoPWatcher\MoPWatcherGUI.ps1"

3. Enter Paths (First-Time Setup)
Field	Example
MySQL Start Script	C:\path\to\mysql_start.bat
Authserver	C:\mop\bin\authserver.exe
Worldserver	C:\mop\bin\worldserver.exe

Click Save Config.

4. (Optional) Enable Notifications

Enter:

NTFY Server → e.g., https://ntfy.sh

Topic → e.g., mop-watchdog

Choose:

Services (MySQL, Authserver, Worldserver)

Triggers (DOWN/UP)

Click Test Notification.

5. Start Monitoring

Press Start Watchdog.

You’ll see:

Watchdog: Running (PID ####)


LEDs light up as each service is detected.

📁 Folder Structure
C:\MoPWatcher\
 ├─ MoPWatcherGUI.ps1
 ├─ watchdog.ps1
 ├─ config.json
 ├─ watchdog.log
 ├─ MopWatcher.ico
 └─ stop_watchdog.txt

🧩 Detailed Guide
1. Running the GUI

The UI includes:

Dark/blue theming

Custom minimize/close buttons

Resizable, auto-scaling panels

Scrollable option areas

2. First-Time Configuration

Fill in your three paths and click Save Config.
Settings are written to config.json automatically.

3. NTFY Notification Logic

Baseline capture prevents “DOWN” messages on startup

2-second suppression window

Alerts only fire when the state actually changes

4. Watchdog Start/Stop Logic
Start

Launches hidden PowerShell instance

Monitors MySQL, Authserver, Worldserver

Restarts services as needed

GUI updates live

Stop

Creates a stop_watchdog.txt signal

Watchdog exits cleanly

5. Windows Service Support

Service name:

MoPWatchdog


Buttons:

Install Service

Start Svc

Stop Svc

Uninstall

Requires admin rights.

6. Live Log Viewer

Displays watchdog.log

Updates once per second

Dedicated scroll bar

Auto-scroll to end

Expands with window size

7. Service Status LEDs
LED	Status
🟢 pulsing	Running
🔴 solid	Stopped
⚪ gray	Unknown/not yet detected
8. Auto-Scaling Layout

Built using:

Responsive WrapPanels

ScrollViewer for top controls

Dedicated log zone

Rounded window chrome

Dark/Blue gradient panels

Remains clean at all sizes.

📜 License

MIT License (or whichever you want — let me know if you want a pre-written LICENSE file).

🙌 Contributions

PRs and improvements welcome!
If you add features or fix bugs, feel free to submit a pull request.
