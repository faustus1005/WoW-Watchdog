# <p align="center">🛡️ WoW-Watchdog</p>

<p align="center"> <img src="https://img.shields.io/badge/PowerShell-5.1+-blue?logo=powershell&style=flat-square"/> <img src="https://img.shields.io/badge/Windows-10%20%7C%2011-lightgrey?logo=windows&style=flat-square"/> <img src="https://img.shields.io/badge/Service-NSSM-success?style=flat-square"/> <img src="https://img.shields.io/badge/GUI-WPF-blueviolet?style=flat-square"/> <img src="https://img.shields.io/badge/Notifications-NTFY-orange?style=flat-square"/> <img src="https://img.shields.io/badge/Status-Stable-success?style=flat-square"/> </p>

## 📖 Overview

WoW-Watchdog is a robust PowerShell-based application designed to monitor the status of your favorite World of Warcraft private servers. WoW-Watchdog provides timely notifications, ensuring you're always informed using NTFY integration.

This tool runs quietly in the background, periodically checking specified servers and alerting you to changes such as a server going offline, or optionally, when the server is back online.

It is geared mostly towards the SPP Legion Repack, so many of the features will not work with other repacks without modification, but the core feature of starting/stopping/notifying should work for most WoW Private servers.

## Features

### Watchdog & Service Control
- GUI-based watchdog for WoW server stacks (World/Auth/DB)
- Runs as a Windows Service via **NSSM**
- Process alias detection (e.g., `authserver` / `bnetserver`, `mysqld`/MariaDB variants)
- Crash-loop protection with restart cooldowns
- Reliable stop/start behavior (no unintended immediate restarts)
- Graceful shutdown preserved when stopping via the app or Windows Services

### Monitoring & Live Operations
- Service status + health indicators (GUI ↔ service heartbeat)
- Online player count (when DB is configured/reachable; safe fallback when not)
- CPU/Memory usage snapshots (periodic refresh)
- Worldserver console integration (RA):
  - Connect/configure RA console
  - View console output in-app
  - Send commands from the launcher

### Notifications & Security
- **NTFY** notifications with:
  - Basic auth (username/password)
  - Token auth
  - Auth mode selector with dynamic fields
- Sensitive values stored encrypted in `secrets.json` (auto-used on reload)

### Updates
- Check for and update to the latest **GitHub Release** from within the app
- Update workflow stops the watchdog safely and maintains graceful shutdown behavior

### Backup & Restore
- Database backup/restore:
  - Select destination
  - ZIP compression by default
  - Retention policy (default 14 days)
  - Restore from `.sql` or `.zip`
- Full server/repack backup:
  - Graceful stop order: **World → Auth → DB**
  - ZIP the entire repack folder
  - Restart order: **DB → Auth → World**
- Option to back up only Auth/World configuration files
- Backup destinations support **UNC paths** (e.g., `\\server\share\folder`)

### Tools
- Integrated tooling tab for companion utilities
- SPP V2 Legion Management app support (managed install/launch)
- Battle Shop Editor support (installed/managed under ProgramData)

### Deployment & Portability
- Standard installer via **Inno Setup**
- ProgramData-based config/logs/tools layout for consistent machine-wide storage
- **Portable mode** supported (no installer required)

![Main](https://github.com/user-attachments/assets/013e7cb3-9dbb-48c2-a31a-94980dacde08)
![Conf](https://github.com/user-attachments/assets/045be4d1-a628-4623-9ba6-46896a797c72)
![Tools](https://github.com/user-attachments/assets/1485eb82-eddc-4219-9555-3e31f8bcffdb)
![WorldserverConsole](https://github.com/user-attachments/assets/676e162a-486b-4660-8a2b-b98fcabbd8cc)
![Updates](https://github.com/user-attachments/assets/51757596-6baf-4370-8ff3-f93c251c0f79)

## 🛠️ Tech Stack

**Core Language:**

![PowerShell](https://img.shields.io/badge/PowerShell-012456?style=for-the-badge&logo=powershell&logoColor=white)

**Configuration:**

![JSON](https://img.shields.io/badge/JSON-000000?style=for-the-badge&logo=json&logoColor=white)

## 🚀 Quick Start

### Prerequisites

*   **PowerShell**:
    
    *   Windows PowerShell 5.1 (or newer)
        

### Installation

1.  **Download the [Latest Release](https://github.com/faustus1005/WoW-Watchdog/releases/latest)**
    
    ```bash
    
    Run the installer as you would any for any Windows application. Admin rights required to install the Service.
    
    ```
    
3.  **Configure the Watchdog Server Paths**
    
    ```bash
    1. Once the install is complete, the service starts automatically. Open the new "Wow Watchdog" icon on your desktop.

    2. Ensure you select your services by clicking the Browse buttons in the top-right corner of the GUI. This lets the
        watchdog know how to start/monitor your services.
    
    ```
    
4.  **Optional: Configure NTFY Notifications**
    
    ```bash
    1. Select your expansion from the drop down, or, select custom and fill out the box that appears to the right. This is
        purely used for notification purposes and does not effect your monitoring.

    2. Fill out the NTFY Server information and change the topic/tags as required for your system.

    3. Select your auth mode if you are using basic auth or token auth. If you are using basic auth, fill in the Username and Password fields.
       for token auth, copy your token into the Token field.
    4. Save config with the button at the top. This will ensure your settings are saved for the next re-load.
        
    ```

## 📁 Project Source Structure

```javascript
WoW-Watchdog/
├── .gitignore          # Git ignore rules
├── CHANGELOG.md        # Detailed version history
├── LICENSE             # Project's MIT License
├── README.md           # This documentation file
├── build/              # Output directory for packaged application builds
├── config.json         # Main configuration file for server monitoring and notifications
├── docs/               # Supplementary documentation files
├── installer/          # Scripts and resources for application installation
└── src/                # Core source code of the WoW-Watchdog application
    └── WoW-Watchdog.ps1 # (Inferred) Main script for the watchdog functionality

```

## ⚙️ Configuration

The `config.json` file is where you define how WoW-Watchdog operates. This does not need to be edited manually unless you aren't using the GUI.

### `config.json` Structure

```json
{
    "ServerName":  "",
    "Expansion":  "Unknown",
    "MySQL":  "",
    "Authserver":  "",
    "Worldserver":  "",
    "NTFY":  {
                 "Server":  "",
                 "Topic":  "",
                 "Tags":  "wow,watchdog",
                 "PriorityDefault":  4,
                 "EnableMySQL":  true,
                 "EnableAuthserver":  true,
                 "EnableWorldserver":  true,
                 "ServicePriorities":  {
                                           "MySQL":  0,
                                           "Authserver":  0,
                                           "Worldserver":  0
                                       },
                 "SendOnDown":  true,
                 "SendOnUp":  false
             }
}

```

## 🔧 Development

### Development Setup for Contributors

1.  **Clone the repository:**
    
    ```bash
    git clone https://github.com/faustus1005/WoW-Watchdog.git
    cd WoW-Watchdog
    
    ```
    
2.  **Open in an IDE:** Use an editor like Visual Studio Code with the PowerShell extension for syntax highlighting and scripting assistance.
    

### Running in Development

The scripts, as written, are intended to be run in conjunction with one another, and do not functional seprately. I will outline general instructions below, but I do not provide detailed assistance for this.

```bash
WowWatcher.ps1 must be converted to executable format using PS2EXE
Compile using Inno Setup Compiler and the included .iss file.
```

## 🤝 Contributing

We welcome contributions to make WoW-Watchdog even better! Please consider the following:

1.  **Fork the repository** and clone it to your local machine.
    
2.  **Create a new branch** for your feature or bug fix: `git checkout -b feature/your-feature-name`
    
3.  **Implement your changes** in PowerShell within the `src/` directory.
    
4.  **Update** `config.json` **examples** or add new ones if your feature introduces new configuration options.
    
5.  **Test your changes** thoroughly.
    
6.  **Update the** `CHANGELOG.md` with your modifications.
    
7.  **Commit your changes** with a clear and descriptive message: `git commit -m "feat: Add new notification type"`
    
8.  **Push your branch** to your fork: `git push origin feature/your-feature-name`
    
9.  **Open a Pull Request** against the `main` branch of this repository.
    

## 📄 License

This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.

## 🙏 Acknowledgments

*   Authored by [faustus1005](https://github.com/faustus1005).
    

## 📞 Support & Contact

*   🐛 Issues: [GitHub Issues](https://github.com/faustus1005/WoW-Watchdog/issues)
    
*   💬 Discussions: [GitHub Discussions](https://github.com/faustus1005/WoW-Watchdog/discussions)
    

**⭐ Star this repo if you find it helpful!**

Made with ❤️ by faustus1005

\`\`\`
