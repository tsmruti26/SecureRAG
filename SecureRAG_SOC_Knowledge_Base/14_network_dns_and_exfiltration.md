# Network, DNS and Data Exfiltration Playbook

ATT&CK: T1071.001 (web protocols C2), T1071.004 (DNS C2), T1572 (protocol tunnelling), T1048 (exfiltration over alternative protocol), T1567.002 (exfiltration to cloud storage), T1041 (exfiltration over C2 channel), T1568 (dynamic resolution), T1090 (proxy).

## Detection signals
- Beaconing: connections at regular intervals (for example every 60 seconds with small jitter) to the same destination, similar byte sizes.
- DNS tunnelling: very long or high-entropy subdomains, many unique subdomains under one domain, high volume of TXT/NULL queries, unusually large DNS responses.
- Newly registered or rarely seen domains, DGA-like names, fast-flux IPs with very short TTLs.
- Large outbound transfers outside business hours, uploads to personal cloud storage, paste sites or file-sharing services, or to unfamiliar countries.
- Unusual protocols on common ports (SSH/HTTPS tunnels on 443, ICMP with large payloads).

## Triage
1. Identify the internal host, user, process (from EDR) and the external destination.
2. Check destination reputation, age, ASN and certificate; compare against the baseline of normal traffic for the host.
3. Quantify volume and duration; identify which data stores the host/user can reach.
4. Look for staging: archive creation (zip/rar/7z), large file collection, unusual access to file shares or databases before the transfer.

## Containment
- Block the destination at firewall/proxy/DNS; isolate the source host if compromise is suspected.
- Disable or restrict the user/service account involved.
- Preserve full packet capture or flow data and proxy logs for the period.

## Impact assessment
- Determine what data left (classification, personal data, secrets, source code). If personal data is involved, start the breach notification playbook.

## Hardening
- Egress filtering and DNS filtering/logging, TLS inspection where lawful, DLP rules for sensitive patterns, alert on first-seen domains, rate limit DNS per host.
