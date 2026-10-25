# Windows Event ID and Sysmon Reference for Investigations

## Authentication and accounts (Security log)
- 4624 successful logon. Logon types: 2 interactive, 3 network, 4 batch, 5 service, 7 unlock, 8 network cleartext, 9 new credentials (runas /netonly), 10 remote interactive (RDP), 11 cached interactive.
- 4625 failed logon (check Status/SubStatus: 0xC000006D bad username or auth, 0xC000006A wrong password, 0xC0000234 account locked).
- 4634 / 4647 logoff. 4648 logon using explicit credentials. 4672 special privileges assigned.
- 4740 account locked out. 4767 account unlocked.
- 4720 user created, 4722 enabled, 4724 password reset attempt, 4723 password change attempt, 4738 user changed.
- 4728 / 4732 / 4756 member added to a security-enabled global / local / universal group (watch Domain Admins, Administrators).
- 4768 Kerberos TGT requested, 4769 service ticket requested (RC4 encryption type 0x17 on service tickets can indicate Kerberoasting), 4771 Kerberos pre-authentication failed, 4776 NTLM credential validation.

## Execution, persistence and defence evasion
- 4688 process creation (enable command-line auditing). 4689 process exit.
- 4697 service installed (Security) and 7045 service installed (System).
- 4698 scheduled task created, 4702 updated, 4699 deleted.
- 1102 Security log cleared; 104 System log cleared. Either is high-priority (T1070.001).
- 4104 PowerShell script block logging, 4103 module logging, 400/403 engine lifecycle.
- 4663 object access (needs SACL), 5140/5145 network share access, 4656 handle requested.
- 4719 audit policy changed. 4946-4950 firewall rule changes.

## Sysmon
- 1 process create, 3 network connection, 5 process terminate, 6 driver loaded, 7 image loaded, 8 CreateRemoteThread, 10 ProcessAccess (watch target lsass.exe), 11 FileCreate, 12/13/14 registry events, 15 FileCreateStreamHash, 17/18 pipe events, 19/20/21 WMI events, 22 DNS query, 23 file delete, 25 process tampering.

## Handy detections
- Many 4625 for different usernames from one source IP: password spraying.
- 4624 type 10 from unusual source, off-hours: RDP misuse.
- 4672 plus 4688 of whoami/net/nltest/quser shortly after logon: discovery after access.
- Sysmon 10 to lsass.exe with high access masks from non-system processes: credential dumping.
- 1102 following unusual admin activity: log tampering.
