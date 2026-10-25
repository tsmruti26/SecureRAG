# Linux Authentication, Logs and Persistence Playbook

ATT&CK: T1078, T1110, T1098.004 (SSH authorized keys), T1053.003 (cron), T1543.002 (systemd service), T1136.001 (local account), T1548.003 (sudo), T1070.003 (clear command history), T1574.006 (LD_PRELOAD).

## Where to look
- Authentication: /var/log/auth.log (Debian/Ubuntu) or /var/log/secure (RHEL/CentOS); `journalctl -u ssh` or `-u sshd`.
- Login history: `last`, `lastb` (failed), `lastlog`, `w`, `who`.
- Commands: shell history (unreliable, attackers clear it), auditd logs at /var/log/audit/audit.log, `sudo` entries in auth logs.
- System: /var/log/syslog or messages, `journalctl --since "2 hours ago"`.

## SSH attack indicators
- Many "Failed password" / "Invalid user" lines from one IP: brute force. Count by source: `grep "Failed password" auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head`.
- "Accepted publickey" or "Accepted password" from a new IP after failures: possible success.
- New keys in ~/.ssh/authorized_keys, especially for root or service accounts.

## Persistence checks
- Cron: /etc/crontab, /etc/cron.*, `crontab -l -u <user>` for every user.
- systemd: `systemctl list-unit-files --type=service`, new units under /etc/systemd/system and ~/.config/systemd/user.
- Startup: /etc/rc.local, ~/.bashrc, ~/.profile, /etc/profile.d.
- Accounts: new UID 0 users (`awk -F: '$3==0' /etc/passwd`), recently modified /etc/passwd, /etc/shadow, /etc/sudoers and /etc/sudoers.d.
- Preload and library hijacks: /etc/ld.so.preload, LD_PRELOAD in environment, unexpected shared objects.
- Suspicious processes and network: `ps auxf`, `ss -tulpn`, `lsof -i`; processes running from /tmp, /dev/shm, deleted binaries (`ls -l /proc/<pid>/exe`).

## Containment and evidence
- Isolate by security group or firewall rule rather than rebooting; capture memory (LiME/AVML) and a disk snapshot before changes.
- Rotate SSH keys and secrets that were present on the host; check cloud metadata credentials and instance roles.
- Rebuild from a trusted image if root compromise is suspected.
