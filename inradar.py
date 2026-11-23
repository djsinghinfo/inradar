        method, user, ip, _port = m.groups()
        fp = RE_FP.search(msg)
        send_event("SUCCESS", user, ip, method, fingerprint=fp.group(0) if fp else "", source="sshd")
        return
    m = RE_SSH_FAIL.search(msg)
    if m:
        method, user, ip, _port = m.groups()
        fp = RE_FP.search(msg)
        send_event("FAILED", user, ip, method, reason="authentication rejected", fingerprint=fp.group(0) if fp else "", source="sshd")
        return
    m = RE_INVALID_USER.search(msg)
    if m and "sshd" in low:
        user, ip = m.groups()
        send_event("FAILED", user, ip, "SSH (invalid user)", reason="invalid username", source="sshd")
        return

    m = RE_VSFTPD.search(msg)
    if m:
        user, result, client = m.groups()
        ip_match = re.search(r"([0-9a-fA-F:.]+)", client)
        ip = ip_match.group(1) if ip_match else client
        ok = result.upper().startswith("OK")
        send_event("SUCCESS" if ok else "FAILED", user or "unknown", ip, "FTP/FTPS", reason="login accepted" if ok else "login rejected", source="vsftpd")
        return

    if "proftpd" in low or "proftpd" in source.lower():
        m = RE_PROFTPD.search(msg)
        rhost = RE_RHOST.search(msg)
        ipm = re.search(r"\((?:[^()]*)?([0-9a-fA-F:.]+)(?:\[[^]]*\])?\)", msg)
        ip = rhost.group(1) if rhost else (ipm.group(1) if ipm else "")
        if m and ip:
            user, result = m.groups()
            ok = result.lower() == "login successful"
            send_event("SUCCESS" if ok else "FAILED", user or "unknown", ip, "FTP/FTPS", reason=result, source="proftpd")
            return

    if RE_PAM_FAIL.search(msg):
        rh, us = RE_RHOST.search(msg), RE_USER.search(msg)
        ip = rh.group(1) if rh else "local/unknown"
        user = us.group(1) if us else "unknown"
        if "sshd" not in low:
            method_match = re.search(r"pam_[^\s(]+\(([^):]+)", msg)
            method = method_match.group(1) if method_match else "PAM"
            send_event("FAILED", user, ip, method, reason="PAM authentication failure", source=source)
        return

    # This is a session event, not a universal proof of remote authentication.
    if "session opened for user" in msg.lower() and "sshd" not in low:
        rh = RE_RHOST.search(msg)
        us = re.search(r"session opened for user\s+(\S+)", msg, re.I)
        if rh:
            method_match = re.search(r"pam_[^\s(]+\(([^):]+)", msg)
            send_event("SUCCESS", us.group(1) if us else "unknown", rh.group(1), method_match.group(1) if method_match else "PAM session", source=source)


def journal_worker():
    while True:
        proc = None
        try:
            proc = subprocess.Popen(["/usr/bin/journalctl", "-f", "-n", "0", "-o", "json", "--no-pager"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
            assert proc.stdout is not None
            for raw in proc.stdout:
                try:
                    entry = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                parse_line(entry.get("MESSAGE", ""), entry.get("SYSLOG_IDENTIFIER", ""), entry.get("_COMM", ""))
            proc.wait()
        except Exception as exc:
            print(f"journal reader error: {type(exc).__name__}", file=sys.stderr, flush=True)
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
        time.sleep(2)


def watch_file(label, path):
    while True:
        proc = None
        try:
            proc = subprocess.Popen(["/usr/bin/tail", "-Fn0", "--retry", "--", path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
            assert proc.stdout is not None
            for line in proc.stdout:
                parse_line(line, label, label, source_override=path)
            proc.wait()
        except Exception as exc:
            print(f"file reader error ({label}): {type(exc).__name__}", file=sys.stderr, flush=True)
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
        time.sleep(3)


def main():
    if os.geteuid() != 0:
        print("Must run as root", file=sys.stderr)
        return 2
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(STATE_DIR, 0, 0)
    os.chmod(STATE_DIR, 0o700)
    try:
        boot_id = BOOT_ID_PATH.read_text().strip()
    except OSError:
        boot_id = "unknown"
    old_boot = BOOT_FILE.read_text().strip() if BOOT_FILE.exists() else ""
    BOOT_FILE.write_text(boot_id + "\n")
    os.chown(BOOT_FILE, 0, 0)
    os.chmod(BOOT_FILE, 0o600)
    if old_boot and old_boot != boot_id:
        telegram(f"[SERVER REBOOT DETECTED]\nServer: {hostname()}\nBoot ID: {boot_id}\nTime: {now_text()}")
    telegram(f"[MONITOR SERVICE STARTED]\nServer: {hostname()}\nTime: {now_text()}\nMonitoring: SSH/SFTP, journal authentication events, configured FTP/FTPS logs")
    threading.Thread(target=journal_worker, name="journal-reader", daemon=True).start()
    for label, path in LOG_FILES:
        threading.Thread(target=watch_file, args=(label, path), name=f"log-{label}", daemon=True).start()
    while True:
        time.sleep(3600)

if __name__ == "__main__":
    sys.exit(main())
