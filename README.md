# 🛡️ WoW-Watchdog

[![GitHub stars](https://img.shields.io/github/stars/faustus1005/WoW-Watchdog?style=for-the-badge)](https://github.com/faustus1005/WoW-Watchdog/stargazers)

[![GitHub forks](https://img.shields.io/github/forks/faustus1005/WoW-Watchdog?style=for-the-badge)](https://github.com/faustus1005/WoW-Watchdog/network)

[![GitHub issues](https://img.shields.io/github/issues/faustus1005/WoW-Watchdog?style=for-the-badge)](https://github.com/faustus1005/WoW-Watchdog/issues)

[![GitHub license](https://img.shields.io/github/license/faustus1005/WoW-Watchdog?style=for-the-badge)](LICENSE)

**Your ultimate companion for monitoring World of Warcraft private servers.**

## 📖 Overview

WoW-Watchdog is a robust PowerShell-based application designed to monitor the status of your favorite World of Warcraft private servers. WoW-Watchdog provides timely notifications, ensuring you're always informed using NTFY integration.

This tool runs quietly in the background, periodically checking specified servers and alerting you to changes such as a server going offline, or optionally, when the server is back online.

## ✨ Features

*   📡 **Server Status Checks**: Accurately detect if a server is online or offline.
    
*   🔔 **Configurable Notifications**: Receive alerts for server status changes.
    
*   💾 **JSON-based Configuration**: Easy and flexible setup using a human-readable `config.json` file.
    
*   📦 **Easy Use**: Designed for easy deployment and setup.
    

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

1.  **Download the latest release**
    
    ```bash
    https://github.com/faustus1005/WoW-Watchdog/releases/latest
    Run the installer as you would any for any Windows application. Admin rights required to install the Service.
    
    ```
    
2.  **Configure the Watchdog Server Paths**
    
    ```bash
    1. Once the install is complete, the service starts automatically. Open the new "Wow Watchdog" icon on your desktop.
    2. Ensure you select your services by clicking the Browse buttons in the top-right corner of the GUI. This lets the
        watchdog know how to start/monitor your services.
    
    ```
    
3.  **Optional: Configure NTFY Notifications**
    
    ```bash
    1. Select your expansion from the drop down, or, select custom and fill out the box that appears to the right. This is
        purely used for notification purposes and does not effect your monitoring.
    2. Fill out the NTFY Server information and change the topic/tags as required for your system.
    3. If you are using basic auth, fill in the Username and Password fields. If you aren't using basic auth, leave these blank.
        Token auth is not yet supported, but expected in the next release.
    
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
