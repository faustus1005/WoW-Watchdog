# 🛡️ WoW-Watchdog

<div align="center">

<!-- TODO: Add project logo (e.g., a shield or eye icon related to WoW) -->

[![GitHub stars](https://img.shields.io/github/stars/faustus1005/WoW-Watchdog?style=for-the-badge)](https://github.com/faustus1005/WoW-Watchdog/stargazers)

[![GitHub forks](https://img.shields.io/github/forks/faustus1005/WoW-Watchdog?style=for-the-badge)](https://github.com/faustus1005/WoW-Watchdog/network)

[![GitHub issues](https://img.shields.io/github/issues/faustus1005/WoW-Watchdog?style=for-the-badge)](https://github.com/faustus1005/WoW-Watchdog/issues)

[![GitHub license](https://img.shields.io/github/license/faustus1005/WoW-Watchdog?style=for-the-badge)](LICENSE)

**Your ultimate companion for monitoring World of Warcraft private servers.**

</div>

## 📖 Overview

WoW-Watchdog is a robust PowerShell-based application designed to monitor the status and player counts of your favorite World of Warcraft private servers. Whether you're a player looking to jump in when the server is active, or a server administrator keeping an eye on your realm, WoW-Watchdog provides timely notifications and insights, ensuring you're always informed.

This tool runs quietly in the background, periodically checking specified servers and alerting you to changes, such as a server going offline, coming back online, or reaching specific player count thresholds.

## ✨ Features

-   🎯 **Multi-Server Monitoring**: Configure and monitor multiple WoW private servers simultaneously.
-   📡 **Server Status Checks**: Accurately detect if a server is online or offline.
-   👥 **Player Count Tracking**: Keep tabs on the current number of players logged into each monitored server.
-   🔔 **Configurable Notifications**: Receive alerts for server status changes or when player counts cross user-defined thresholds.
-   ⚙️ **Customizable Polling Interval**: Adjust how frequently the watchdog checks server statuses.
-   💾 **JSON-based Configuration**: Easy and flexible setup using a human-readable `config.json` file.
-   📦 **Distributable**: Designed for easy deployment and setup for end-users.

## 🛠️ Tech Stack

**Core Language:**

![PowerShell](https://img.shields.io/badge/PowerShell-012456?style=for-the-badge&logo=powershell&logoColor=white)

**Configuration:**

![JSON](https://img.shields.io/badge/JSON-000000?style=for-the-badge&logo=json&logoColor=white)

## 🚀 Quick Start

### Prerequisites
-   **PowerShell**:
    -   Windows PowerShell 5.1 (or newer)
    -   PowerShell Core 7+ (for cross-platform compatibility)

### Installation

1.  **Clone the repository**
    ```bash
    git clone https://github.com/faustus1005/WoW-Watchdog.git
    cd WoW-Watchdog
    ```

2.  **Configuration setup**
    The primary configuration is handled via `config.json`. You'll need to edit this file to define the servers you want to monitor and your notification preferences.
    ```bash
    # Open config.json in your preferred text editor
    notepad config.json # On Windows
    # or
    code config.json    # If using VS Code
    ```
    Refer to the [Configuration](#-configuration) section below for details on how to set up `config.json`.

3.  **Run the Watchdog**
    Once configured, you can start the WoW-Watchdog application by running its main script:
    ```bash
    .\src\WoW-Watchdog.ps1
    ```
    For persistent monitoring, you might consider running this script as a scheduled task or a background service on your operating system.

## 📁 Project Structure

```
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

The `config.json` file is where you define how WoW-Watchdog operates.

### `config.json` Structure
```json
{
  "PollingIntervalSeconds": 60,
  "Servers": [
    {
      "Name": "My Awesome Server",
      "Address": "server.example.com",
      "Port": 8085,
      "Notifications": {
        "DiscordWebhookUrl": "YOUR_DISCORD_WEBHOOK_URL",
        "MinPlayersAlert": 50,
        "MaxPlayersAlert": 500,
        "NotifyOnStatusChange": true,
        "NotifyOnPlayerCountChange": true
      }
    }
    // Add more server objects as needed
  ],
  "GlobalNotificationSettings": {
    "DefaultDiscordWebhookUrl": "GLOBAL_DEFAULT_DISCORD_WEBHOOK_URL", // Optional global fallback
    "EnableLogging": true,
    "LogFilePath": "watchdog.log"
  }
}
```

### Configuration Options

| Key                            | Description                                                                                                                                              | Type    | Default      | Required |

|--------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|---------|--------------|----------|

| `PollingIntervalSeconds`       | The interval (in seconds) at which the watchdog will check server statuses.                                                                              | Integer | `60`         | Yes      |

| `Servers`                      | An array of objects, each representing a WoW private server to monitor.                                                                                  | Array   | `[]`         | Yes      |

| `Servers[].Name`               | A user-friendly name for the server.                                                                                                                     | String  | -            | Yes      |

| `Servers[].Address`            | The IP address or hostname of the server.                                                                                                                | String  | -            | Yes      |

| `Servers[].Port`               | The port number used by the server's status endpoint (often the world server port).                                                                      | Integer | -            | Yes      |

| `Servers[].Notifications`      | An object defining notification settings specific to this server.                                                                                        | Object  | -            | Yes      |

| `Notifications.DiscordWebhookUrl` | The URL for a Discord webhook to send notifications to. Overrides `DefaultDiscordWebhookUrl` if specified.                                         | String  | -            | No       |

| `Notifications.MinPlayersAlert` | An integer. If player count drops below this, a notification is sent (set to `0` or omit to disable).                                                  | Integer | `0`          | No       |

| `Notifications.MaxPlayersAlert` | An integer. If player count rises above this, a notification is sent (set to `0` or omit to disable).                                                  | Integer | `0`          | No       |

| `Notifications.NotifyOnStatusChange` | Boolean. If `true`, sends notifications when the server's online/offline status changes.                                                           | Boolean | `true`       | No       |

| `Notifications.NotifyOnPlayerCountChange` | Boolean. If `true`, sends notifications when the player count changes (in addition to `Min`/`Max` alerts).                                 | Boolean | `true`       | No       |

| `GlobalNotificationSettings`   | Global settings for all notifications.                                                                                                                   | Object  | -            | No       |

| `GlobalNotificationSettings.DefaultDiscordWebhookUrl` | A Discord webhook URL to use if `DiscordWebhookUrl` is not specified for a server.                                                         | String  | -            | No       |

| `GlobalNotificationSettings.EnableLogging` | Boolean. If `true`, enables logging of watchdog activities.                                                                                  | Boolean | `true`       | No       |

| `GlobalNotificationSettings.LogFilePath` | Path to the log file.                                                                                                                            | String  | `watchdog.log` | No       |

### Example Configuration

To monitor two servers, one sending notifications to a specific Discord channel and another using a global default webhook, your `config.json` might look like this:

```json
{
  "PollingIntervalSeconds": 300,
  "Servers": [
    {
      "Name": "Northdale (Classic)",
      "Address": "northdale.elysium-project.org",
      "Port": 8085,
      "Notifications": {
        "DiscordWebhookUrl": "https://discord.com/api/webhooks/YOUR_NORTHDALE_WEBHOOK_ID/YOUR_NORTHDALE_WEBHOOK_TOKEN",
        "MinPlayersAlert": 100,
        "NotifyOnStatusChange": true
      }
    },
    {
      "Name": "Stormforge (WotLK)",
      "Address": "stormforge.gg",
      "Port": 3724,
      "Notifications": {
        "MaxPlayersAlert": 2000,
        "NotifyOnPlayerCountChange": false
      }
    }
  ],
  "GlobalNotificationSettings": {
    "DefaultDiscordWebhookUrl": "https://discord.com/api/webhooks/YOUR_GLOBAL_WEBHOOK_ID/YOUR_GLOBAL_WEBHOOK_TOKEN",
    "EnableLogging": true,
    "LogFilePath": "WoW-Watchdog.log"
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
2.  **Open in an IDE:**
    Use an editor like Visual Studio Code with the PowerShell extension for syntax highlighting and scripting assistance.

### Running in Development

To test changes, simply execute the main script from the `src/` directory:
```bash
.\src\WoW-Watchdog.ps1
```
Ensure your `config.json` is set up correctly for testing purposes.

## 🚀 Deployment

The `build/` and `installer/` directories indicate that this project is designed for straightforward distribution. While specific build commands are not provided, these directories would typically contain compiled executables or installation scripts for end-users.

For production deployment, it's recommended to:
1.  **Generate a release build** (if specific build scripts exist within `build/`).
2.  **Use the installer** (if available in `installer/`) to deploy the application on the target machine.
3.  **Configure `config.json`** with production settings for your servers and notification channels.
4.  **Run the application persistently** using Windows Task Scheduler, a system service, or similar mechanisms.

## 🤝 Contributing

We welcome contributions to make WoW-Watchdog even better! Please consider the following:

1.  **Fork the repository** and clone it to your local machine.
2.  **Create a new branch** for your feature or bug fix: `git checkout -b feature/your-feature-name`
3.  **Implement your changes** in PowerShell within the `src/` directory.
4.  **Update `config.json` examples** or add new ones if your feature introduces new configuration options.
5.  **Test your changes** thoroughly.
6.  **Update the `CHANGELOG.md`** with your modifications.
7.  **Commit your changes** with a clear and descriptive message: `git commit -m "feat: Add new notification type"`
8.  **Push your branch** to your fork: `git push origin feature/your-feature-name`
9.  **Open a Pull Request** against the `main` branch of this repository.

## 📄 License

This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.

## 🙏 Acknowledgments

-   Authored by [faustus1005](https://github.com/faustus1005).

## 📞 Support & Contact

-   🐛 Issues: [GitHub Issues](https://github.com/faustus1005/WoW-Watchdog/issues)
-   💬 Discussions: [GitHub Discussions](https://github.com/faustus1005/WoW-Watchdog/discussions)

---

<div align="center">

**⭐ Star this repo if you find it helpful!**

Made with ❤️ by faustus1005

</div>
```

