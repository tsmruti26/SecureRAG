# Insider Threat and Data Loss Playbook

ATT&CK: T1078 (valid accounts), T1005 (data from local system), T1213 (data from information repositories), T1052 (exfiltration over physical medium), T1567 (exfiltration to web service), T1537 (transfer data to cloud account), T1098 (account manipulation).

## Indicators (treat as signals, never as proof)
- Bulk downloads or access to repositories unrelated to the role; access outside normal hours or after resignation notice.
- Use of personal cloud storage, USB mass storage, personal email forwarding, or screenshots of sensitive systems.
- Attempts to bypass controls, privilege requests, disabling endpoint tools, creating shadow accounts.
- Policy violations combined with grievances, departure, or financial pressure (HR context must be handled by HR and legal, not guessed by the SOC).

## Handling principles
- Involve HR, legal and management early; keep the circle small and confidential.
- Follow proportional and lawful monitoring policy; do not access personal content beyond what policy permits.
- Preserve evidence using the chain of custody playbook; avoid tipping off the subject before containment is planned.

## Investigation
1. Define the allegation and the data at risk.
2. Pull relevant logs: file access, DLP alerts, email/gateway, proxy/cloud access security broker, endpoint USB and print logs, authentication history.
3. Build a timeline, compare against the user's baseline and peers.
4. Establish intent only through HR/legal processes; the SOC reports facts.

## Containment
- Restrict or suspend access in coordination with HR/legal; revoke tokens, VPN, shared secrets; retrieve devices.
- Recover or require deletion of data from personal accounts through legal channels.

## Prevention
- Least privilege, access reviews, offboarding checklists, DLP, logging of sensitive repository access, separation of duties.
