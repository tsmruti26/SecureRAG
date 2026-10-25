# Ransomware Response Playbook

ATT&CK: T1486 (data encrypted for impact), T1490 (inhibit system recovery), T1489 (service stop), T1021.001/002 (RDP/SMB lateral movement), T1003.001 (LSASS credential dumping), T1567 / T1048 (exfiltration for double extortion), T1562.001 (disable security tools), T1070.001 (clear logs).

## Early warning signs
- Mass file renames/extension changes, ransom notes, spikes in file I/O on file servers.
- vssadmin/wmic/bcdedit commands deleting shadow copies or disabling recovery; backup agents stopped.
- EDR or antivirus tampering, security services stopped, GPO changes pushed domain-wide.
- Unusual RDP/SMB/WinRM activity, new local admin accounts, large outbound transfers before encryption (data theft).

## Immediate actions (first hour)
1. Declare a critical incident and assemble the response team, including leadership, legal and communications.
2. Isolate affected hosts via EDR network containment or by disconnecting the network. Do NOT power off if forensic memory capture is wanted; hibernate/capture first where possible.
3. Disable compromised accounts and rotate privileged credentials (domain admin, service accounts, backup admin). Assume Active Directory is compromised if domain controllers are affected.
4. Protect backups: disconnect or lock backup repositories, verify immutable/offline copies are intact before any restore.
5. Preserve evidence: memory, disk images of patient-zero hosts, logs, ransom note, sample of encrypted file and any binaries.

## Scope
- Identify patient zero and initial access (phishing, exposed RDP/VPN, vulnerable edge device, stolen credentials).
- Determine whether data was exfiltrated; check proxy/firewall/NetFlow for large uploads to cloud storage or unknown hosts.
- Identify the ransomware family from the note and extension; check public decryptor resources (for example the No More Ransom project) before any other decision.

## Recovery
- Rebuild from known-good images; restore data from verified clean backups; reset all credentials; patch the entry vector.
- Re-introduce systems in phases with heightened monitoring.
- Payment decisions belong to executive leadership with legal advice; sanctions and law-enforcement guidance apply. Do not negotiate from the SOC.

## Notifications
- Regulators and CERT-In per the data breach notification playbook; cyber insurer; law enforcement; affected customers if personal data was involved.

## Lessons learned
- Review segmentation, backup immutability, EDR coverage, privileged access, RDP exposure, and patch latency.
