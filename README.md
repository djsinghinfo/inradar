# InRadar (systemd-based Linux)

Root-owned systemd service that sends Telegram alerts for authentication events found in the system journal and configured FTP log files. It never reads, stores, or sends passwords. The installer is distribution-version agnostic and is intended for systemd-based Linux distributions with Python 3.6+, `journalctl`, and `tail` (including supported Ubuntu and Debian releases). It is not compatible with non-systemd systems, and does not guarantee every Linux distribution or authentication stack works without configuration.

## What it can report

- SSH/SFTP: `Accepted ...` and `Failed ...` sshd journal events, username, source IP, method, timestamp, hostname, and SSH fingerprint when OpenSSH includes one in the log.
- PAM failures and some remote PAM session-open events when the service writes those events to the journal with a remote host field.
- vsftpd `OK LOGIN` / `FAIL LOGIN` records from `/var/log/vsftpd.log`.
- Some ProFTPD authentication log formats from `/var/log/proftpd/proftpd.log` and `/var/log/proftpd/auth.log`.
- Monitor startup and changed boot ID (reboot) notifications.

**Coverage is log-source dependent.** FTP/FTPS daemons vary in log format and location. Verify the actual daemon and test a failed and successful login on the deployed server. This is not a universal audit of every login mechanism, database, web panel, container, or application. A local systemd service shutdown cannot reliably notify Telegram after it has stopped; use remote log collection/heartbeats for tamper detection.

## Compatibility

The installer no longer hard-codes Ubuntu 24.04. It checks for systemd, `journalctl`, Python 3.8 or newer, and `tail`. Authentication journal fields and FTP/FTPS daemon log locations vary by distribution and daemon; validate a failed and successful login for each enabled service before relying on alerts. On minimal systems, install/enable systemd-journald and ensure logs are persistent/accessible. This is broad Linux compatibility, not a claim that every OS/version or every login mechanism is automatically covered.

## Install from a Git checkout

After pushing this repository to your own Git host:

```bash
git clone https://github.com/djsinghinfo/inradar.git
cd inradar
sudo ./install.sh --hostname myProject
```

The installer sets the operating-system hostname to `inradar` by default. To install without changing hostname:

```bash
sudo ./install.sh --skip-hostname
```

You can specify another hostname with `--hostname NAME`.

The installer prompts for a Telegram bot token and numeric chat ID on first install. Create the bot with [@BotFather](https://t.me/BotFather) and start a chat with it before installing. Existing config is preserved on re-install.

## Verify

```bash
hostnamectl --static
sudo systemctl status inradar.service
sudo systemctl is-enabled inradar.service
sudo journalctl -u inradar.service -f
sudo stat -c '%U:%G %a %n' /usr/local/sbin/inradar.py /etc/inradar/telegram.env /etc/systemd/system/inradar.service
```

Expected file permissions: monitor `root:root 750`, token file `root:root 600`, unit `root:root 644`.

## Test events

From a separate machine, attempt one failed and one successful SSH login. Observe Telegram and compare against:

```bash
sudo journalctl -u ssh.service --since '10 minutes ago' --no-pager
sudo journalctl -u inradar.service --since '10 minutes ago' --no-pager
```

For FTP/FTPS, use a test account and verify that the daemon emits auth logs to one of the monitored paths or the system journal. Configure the daemon's logging separately if needed. Do not enable verbose protocol logging without checking whether it can expose sensitive session data.

## Change Telegram configuration

```bash
sudoedit /etc/inradar/telegram.env
sudo chown root:root /etc/inradar/telegram.env
sudo chmod 600 /etc/inradar/telegram.env
sudo systemctl restart inradar.service
```

Rotate the bot token with @BotFather if it is exposed. Never commit `telegram.env` to Git.

## Remove

```bash
sudo ./uninstall.sh
```

Uninstall does not revert the server hostname.

## Security model and limitations

- The service and config are root-owned. Ordinary unprivileged users cannot edit them.
- systemd sandbox options provide defense in depth; the monitor needs root access to read system logs.
- **A hostile root user can stop, modify, or remove a local root service.** `chattr +i` is not a robust defense against root and can complicate legitimate upgrades. For meaningful tamper detection, forward journald/auth logs to a separate host or managed logging service with credentials not available on this server, and alert on missing heartbeats.
- Alerts require network access to `api.telegram.org`. Network outages can cause missed notifications; this implementation does not provide a durable retry queue or guaranteed delivery.
- Every matching event is sent immediately, as requested. Brute-force attacks may generate many Telegram messages.
- The script parses known log formats. Validate against the actual OpenSSH, vsftpd, or ProFTPD version before relying on it for incident response.


## get telegram chat id
- https://api.telegram.org/bot<YourBOTToken>/getUpdates
- if you want to send message in group using bot
- first assign bot as group admin and send any simple message in group
- get group chat id from above give url, goup chat id start with (-)

