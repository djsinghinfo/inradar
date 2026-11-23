#!/usr/bin/env bash
set -Eeuo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run with sudo: sudo $0" >&2; exit 1; fi
read -r -p "Remove InRadar service and its Telegram configuration/state? [y/N] " answer
[[ "$answer" =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 0; }
systemctl disable --now inradar.service 2>/dev/null || true
rm -f /etc/systemd/system/inradar.service /usr/local/sbin/inradar.py /etc/systemd/system/inradar-login-monitor.service /usr/local/sbin/inradar-login-inradar.py
rm -rf /etc/inradar /var/lib/inradar /etc/inradar-login-monitor /var/lib/inradar-login-monitor
systemctl daemon-reload
systemctl reset-failed inradar.service 2>/dev/null || true
systemctl reset-failed inradar-login-monitor.service 2>/dev/null || true
echo "InRadar service removed. Hostname was not changed back."
