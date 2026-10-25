# Severity, Priority and Escalation Matrix

Severity reflects impact multiplied by confidence. Priority drives response timing.

## Severity
- Critical (P1): confirmed compromise of crown-jewel systems or data, active ransomware or destructive activity, confirmed financial fraud in progress, widespread account takeover.
- High (P2): likely compromise of a privileged or sensitive account, confirmed malware with lateral movement, sensitive data exposure, exploited internet-facing vulnerability.
- Medium (P3): suspicious activity with limited scope, phishing with users who interacted but no confirmed compromise, policy violation with moderate impact.
- Low (P4): informational, unconfirmed or blocked attempts, false positives under review.

## Response targets (adjust to your SLA)
- P1: acknowledge in 15 minutes, incident commander assigned immediately, updates every 30-60 minutes, executive notification within 1 hour.
- P2: acknowledge in 30 minutes, updates every 2-4 hours, leadership informed same day.
- P3: acknowledge within 4 hours, resolve or escalate within 2 business days.
- P4: next business day, batch review.

## Escalate when
- Privileged, executive, finance or service accounts are involved.
- Personal or regulated data may be affected (start breach notification clocks).
- Containment requires business-impacting actions (isolating servers, disabling many accounts).
- Evidence of attacker persistence or lateral movement appears.
- The analyst is uncertain; escalate early rather than late.

## Roles
- Analyst: triage, investigation, propose actions.
- SOC lead / incident commander: approve containment, verify AI-assisted content, close incidents.
- Legal / privacy: notifications and regulatory decisions.
- Communications: internal and external messaging.
- IT owners: execute approved containment; humans execute, tooling only proposes.

## Closure criteria
- Root cause identified or documented as unknown with reasons; containment and eradication verified; monitoring period completed; lessons learned and detection improvements recorded.
