# InRadar — Linux Authentication Monitoring

InRadar is a root-owned, systemd-based Linux service that monitors authentication events and sends alerts to Telegram. It never reads, stores, or sends passwords.

## 1. Installation

### Requirements

- A systemd-based Linux distribution.
- Python 3.8 or newer.
- `journalctl` and `tail`.
- Network access to `api.telegram.org`.
- Root or `sudo` privileges.

The installer checks for required dependencies and does not assume a specific Ubuntu version. Authentication log formats and paths may still require distribution-specific configuration.

### Install from Git

Clone the repository and enter the project directory:

```bash
git clone https://github.com/djsinghinfo/inradar.git
cd inradar
```

Run the installer:

```bash
sudo ./install.sh --hostname myProject
```

To install without changing the server hostname:

```bash
sudo ./install.sh --skip-hostname
```

You can specify a different hostname with `--hostname NAME`.

The installer prompts for your Telegram bot token and chat ID during the initial installation. Follow the Telegram Bot Setup section below if you need to create these credentials.

Existing Telegram configuration is preserved during reinstallation.

### Verify the Installation

```bash
hostnamectl --static
sudo systemctl status inradar.service --no-pager
sudo systemctl is-enabled inradar.service
sudo journalctl -u inradar.service -n 30 --no-pager
```

Check file ownership and permissions:

```bash
sudo stat -c '%U:%G %a %n' \
  /usr/local/sbin/inradar.py \
  /etc/inradar/telegram.env \
  /etc/systemd/system/inradar.service
```

Expected permissions:

| File | Owner | Permissions |
|---|---|---|
| Monitor script | `root:root` | `750` |
| Telegram configuration | `root:root` | `600` |
| systemd service | `root:root` | `644` |

## 2. Telegram Bot Setup

### Step 1: Create a Telegram Bot

1. Open [@BotFather](https://t.me/BotFather) on Telegram.
2. Send `/newbot`.
3. Follow the instructions to choose a bot name and username.
4. Copy the bot token provided by BotFather.

**Keep the bot token private.** Anyone who obtains it may be able to control your bot.

### Step 2: Add the Bot to Your Telegram Group

1. Open your Telegram group.
2. Go to **Group Name → Add Members**.
3. Add your newly created bot.
4. If your group configuration requires it, go to **Group Name → Edit → Administrators** and add the bot as an administrator.
5. Grant only the permissions required for your setup.
6. Send a message in the group to generate an update.

### Step 3: Find the Group Chat ID

Open the following URL in your browser, replacing `YOUR_BOT_TOKEN` with your actual bot token:

```text
https://api.telegram.org/botYOUR_BOT_TOKEN/getUpdates
```

Find the `message` → `chat` → `id` field in the JSON response. This is your chat ID. Group chat IDs are commonly negative numbers.

If `getUpdates` returns no messages, check whether a webhook is configured or another process is consuming updates. Do not share the response publicly because it may contain private chat information.

### Step 4: Configure Telegram

During installation, enter the bot token and numeric chat ID when prompted.

To update the configuration later:

```bash
sudoedit /etc/inradar/telegram.env
sudo chown root:root /etc/inradar/telegram.env
sudo chmod 600 /etc/inradar/telegram.env
sudo systemctl restart inradar.service
```

The configuration uses these environment variable names:

```bash
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

Never commit this configuration file to Git. If the bot token is exposed, revoke or regenerate it using BotFather.

## 3. Supported Monitoring

InRadar monitors authentication events found in the system journal and configured FTP log files.

### SSH/SFTP

- Successful SSH authentication.
- Failed SSH authentication.
- Username, remote IP, authentication method, timestamp and hostname.
- SSH key fingerprint when OpenSSH includes it in the log.

### PAM Authentication

- PAM authentication failures.
- Some remote PAM session-open events when the logs contain a remote host field.

### FTP/FTPS

- vsftpd `OK LOGIN` and `FAIL LOGIN` records from `/var/log/vsftpd.log`.
- Some ProFTPD authentication events from:
  - `/var/log/proftpd/proftpd.log`
  - `/var/log/proftpd/auth.log`

### Service and Reboot Notifications

- Monitor startup notifications.
- Server reboot notifications when the boot ID changes.

**Coverage depends on the configured log sources.** This is not a universal audit of every login mechanism, application, database, web panel or container.

## 4. Testing and Troubleshooting

### Follow InRadar Logs

```bash
sudo journalctl -u inradar.service -f
```

### Check SSH Authentication Events

From a separate machine, attempt one failed SSH login and one successful SSH login using an authorized account.

Inspect the SSH logs:

```bash
sudo journalctl -u ssh.service --since '10 minutes ago' --no-pager
```

Compare them with the InRadar service logs:

```bash
sudo journalctl -u inradar.service --since '10 minutes ago' --no-pager
```

### Test FTP/FTPS

Use a test account to attempt one failed and one successful login. Verify that the FTP daemon writes the expected authentication events to a monitored log file or the system journal.

Configure daemon logging separately if necessary. Avoid enabling verbose protocol logging without checking whether it could expose sensitive session data.

## 5. Compatibility

InRadar is designed for systemd-based Linux distributions with Python 3.8 or newer, `journalctl` and `tail`.

It is not compatible with non-systemd systems. Different distributions and authentication stacks may use different journal fields, service names and FTP log paths. Validate successful and failed login detection for every enabled service before relying on the alerts.

On minimal systems, ensure that systemd-journald is installed, enabled and accessible, and configure persistent logging if required.

## 6. Security Model and Limitations

- The monitor script and Telegram configuration are intended to be root-owned.
- systemd sandboxing provides defense in depth; the monitor requires elevated access to read system authentication logs.
- InRadar never reads, stores or sends passwords.
- Alerts require network access to `api.telegram.org`.
- Network outages may cause missed notifications. This implementation does not guarantee delivery and does not provide a durable retry queue.
- Brute-force attacks may generate many Telegram messages because matching events are sent immediately.
- A hostile root user can stop, modify or remove a local root service. `chattr +i` is not a robust defense against root and may complicate legitimate updates.
- For stronger tamper detection, forward authentication logs to a separate host or managed logging service using credentials unavailable to the monitored server. Monitor remote heartbeats to detect missing events or service interruptions.

## 7. Uninstallation

From the repository directory, run:

```bash
sudo ./uninstall.sh
```

Uninstallation does not revert a hostname change made during installation.

## 8. Project Notes

InRadar parses known authentication log formats. It should be tested against the actual OpenSSH, vsftpd or ProFTPD version before being used for incident response.

Repository: [https://github.com/djsinghinfo/inradar](https://github.com/djsinghinfo/inradar)
