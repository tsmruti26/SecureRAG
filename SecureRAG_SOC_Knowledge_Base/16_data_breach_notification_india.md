# Data Breach Notification Playbook (India-focused, verify current law)

This document is operational guidance, not legal advice. Laws and rules change; confirm current requirements with legal counsel before notifying.

## Frameworks commonly involved
- CERT-In Directions (April 2022, under section 70B of the IT Act): report specified cyber security incidents to CERT-In within 6 hours of noticing them; maintain ICT system logs securely for 180 days; synchronise clocks with NTP. Incident types include targeted scanning, compromise of critical systems, unauthorised access, data breach or leak, ransomware, phishing attacks, attacks on servers/applications, and others listed in the directions.
- Digital Personal Data Protection (DPDP) Act, 2023 and its Rules: a data fiduciary must notify the Data Protection Board and each affected data principal of a personal data breach, with a detailed report to the Board within the timeline set by the Rules (verify the current timeline, commonly cited as 72 hours for the detailed report). Reasonable security safeguards are required.
- Sector regulators may add duties (for example RBI for banks/payments, SEBI for market entities, IRDAI for insurers).
- If EU/UK residents' data is involved: GDPR requires notifying the supervisory authority within 72 hours of becoming aware, unless the breach is unlikely to result in risk.

## Steps
1. Confirm the incident involves personal or regulated data; record date/time of awareness (start the clocks).
2. Contain the incident and preserve evidence.
3. Assess: categories of data, number of individuals, sensitivity (financial, health, credentials, government IDs), likelihood and severity of harm, whether data was encrypted, whether data was actually accessed or exfiltrated.
4. Convene legal, privacy/DPO, communications and leadership. Decide notification duties for each regulator and each affected group.
5. Report to CERT-In within 6 hours where the incident type is in scope (use the official reporting channel and form; an initial report with limited detail is acceptable, followed by updates).
6. Notify other regulators and affected individuals as required. Notices should state what happened, what data, what the organisation is doing, what individuals should do (change passwords, watch statements), and contact points.
7. Keep a breach register with decisions and rationale, including cases where notification was judged unnecessary.

## Evidence for regulators
- Timeline, scope analysis, containment steps, root cause, remediation plan, logs retained, communications sent.
