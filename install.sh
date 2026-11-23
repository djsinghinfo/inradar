#!/usr/bin/env bash
set -Eeuo pipefail

# InRadar service installer for Ubuntu 24.04.
# Usage: sudo ./install.sh [--hostname inradar] [--skip-hostname]

if [[ $EUID -ne 0 ]]; then echo "Run with sudo: sudo $0" >&2; exit 1; fi
if [[ ! -r /etc/os-release ]]; then echo "Cannot identify operating system." >&2; exit 1; fi
. /etc/os-release
if [[ "${ID:-}" != ubuntu || "${VERSION_ID:-}" != "24.04" ]]; then
  echo "This installer targets Ubuntu 24.04; detected ${PRETTY_NAME:-unknown}." >&2
  exit 1
fi

SET_HOSTNAME=1
NEW_HOSTNAME="inradar"
while (($#)); do
  case "$1" in
    --hostname) [[ $# -ge 2 ]] || { echo "--hostname needs a value" >&2; exit 2; }; NEW_HOSTNAME="$2"; shift 2 ;;
    --skip-hostname) SET_HOSTNAME=0; shift ;;
    -h|--help) echo "Usage: sudo ./install.sh [--hostname NAME] [--skip-hostname]"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$NEW_HOSTNAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]{0,62}$ ]] || { echo "Invalid hostname: $NEW_HOSTNAME" >&2; exit 2; }
command -v systemctl >/dev/null || { echo "systemd is required." >&2; exit 1; }
command -v journalctl >/dev/null || { echo "journalctl is required." >&2; exit 1; }
command -v python3 >/dev/null || { echo "Python 3 is required." >&2; exit 1; }
command -v tail >/dev/null || { echo "GNU tail is required." >&2; exit 1; }

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ -r "$SCRIPT_DIR/inradar.py" && -r "$SCRIPT_DIR/inradar.service" ]] || { echo "Run install.sh from the repository directory; required files are missing." >&2; exit 1; }

if [[ $SET_HOSTNAME -eq 1 ]]; then
  if [[ "$(hostnamectl --static 2>/dev/null || hostname)" != "$NEW_HOSTNAME" ]]; then
    hostnamectl set-hostname "$NEW_HOSTNAME"
    echo "Hostname set to $NEW_HOSTNAME. This changes the system hostname; it does not rename cloud inventory/DNS records."
  fi
fi

# Migrate an earlier InRadar package naming scheme if present. Preserve secrets and state.
OLD_SERVICE="inradar-login-monitor.service"
OLD_CONFIG="/etc/inradar-login-monitor/telegram.env"
OLD_STATE="/var/lib/inradar-login-monitor"
if [[ -f "/etc/systemd/system/$OLD_SERVICE" ]]; then
  systemctl disable --now "$OLD_SERVICE" 2>/dev/null || true
fi
install -d -o root -g root -m 0700 /etc/inradar /var/lib/inradar
if [[ ! -s /etc/inradar/telegram.env && -s "$OLD_CONFIG" ]]; then
  install -o root -g root -m 0600 "$OLD_CONFIG" /etc/inradar/telegram.env
  echo "Migrated existing Telegram configuration to /etc/inradar/telegram.env."
fi
if [[ -d "$OLD_STATE" && ! -e /var/lib/inradar/boot-id ]]; then
  cp -a "$OLD_STATE"/. /var/lib/inradar/
  chown -R root:root /var/lib/inradar
  chmod 0700 /var/lib/inradar
fi

if [[ ! -s /etc/inradar/telegram.env ]]; then
  echo "Create a Telegram bot with @BotFather and start a chat with it first."
  read -r -p "Telegram bot token: " BOT_TOKEN
  read -r -p "Telegram numeric chat ID: " CHAT_ID
  [[ -n "$BOT_TOKEN" && -n "$CHAT_ID" ]] || { echo "Token and chat ID are required." >&2; exit 1; }
  [[ "$BOT_TOKEN" != *[[:space:]]* && "$CHAT_ID" != *[[:space:]]* ]] || { echo "Whitespace is not allowed in token/chat ID." >&2; exit 1; }
  [[ "$CHAT_ID" =~ ^-?[0-9]+$ ]] || { echo "Chat ID must be numeric (group IDs may be negative)." >&2; exit 1; }
  umask 077
  printf 'TELEGRAM_BOT_TOKEN=%s\nTELEGRAM_CHAT_ID=%s\n' "$BOT_TOKEN" "$CHAT_ID" > /etc/inradar/telegram.env
  chown root:root /etc/inradar/telegram.env
  chmod 0600 /etc/inradar/telegram.env
  unset BOT_TOKEN CHAT_ID
else
  echo "Keeping existing Telegram configuration. Edit /etc/inradar/telegram.env as root to change it."
fi

install -o root -g root -m 0750 "$SCRIPT_DIR/inradar.py" /usr/local/sbin/inradar.py
install -o root -g root -m 0644 "$SCRIPT_DIR/inradar.service" /etc/systemd/system/inradar.service
systemctl daemon-reload
systemctl enable --now inradar.service
# Remove obsolete unit and executable only after the replacement is active.
if systemctl is-active --quiet inradar.service; then
  rm -f "/etc/systemd/system/$OLD_SERVICE" /usr/local/sbin/inradar-login-inradar.py
  systemctl daemon-reload
fi
sleep 1
if ! systemctl is-active --quiet inradar.service; then
  echo "Service failed to start; recent logs:" >&2
  journalctl -u inradar.service -n 60 --no-pager >&2
  exit 1
fi

if systemctl is-active --quiet vsftpd; then
  echo "vsftpd is active. Confirm login events are written to /var/log/vsftpd.log or journald."
elif systemctl is-active --quiet proftpd; then
  echo "ProFTPD is active. Confirm auth logs are written under /var/log/proftpd/ or journald."
else
  echo "No active vsftpd/ProFTPD service detected. Configure the log source for your actual FTP/FTPS daemon."
fi

echo
echo "Installed: inradar.service"
echo "Status:    systemctl status inradar.service"
echo "Logs:      journalctl -u inradar.service -f"
echo "Config:    /etc/inradar/telegram.env (root:root 0600)"
echo "Hostname:  $(hostnamectl --static 2>/dev/null || hostname)"
echo "Reminder:  local root can still disable/remove the monitor; use remote log forwarding for tamper detection."
