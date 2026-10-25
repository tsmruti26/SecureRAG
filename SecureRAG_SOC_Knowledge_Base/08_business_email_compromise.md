# Business Email Compromise (BEC) Playbook

ATT&CK: T1566, T1078.004 (cloud accounts), T1114.003 (email forwarding rule), T1534 (internal spearphishing), T1657 (financial theft), T1598 (phishing for information).

## Variants
- Vendor/invoice fraud: a real supplier thread is hijacked and bank details are changed.
- CEO/executive impersonation: urgent wire or gift-card request, often from a lookalike domain or display-name spoof.
- Payroll diversion: an employee "changes" direct-deposit details.
- Account takeover based: a compromised mailbox is used to send convincing messages from the genuine address.

## Triage
1. Is the message from a lookalike domain, a spoofed display name, or the genuine compromised mailbox? Compare Return-Path, From, Reply-To, DKIM/SPF/DMARC results and sender IP.
2. Identify the requested action: payment, bank change, credentials, gift cards.
3. If money moved or is about to: treat as critical and go straight to the financial steps below.

## Financial containment (time critical)
- Contact the finance team and the bank immediately to request a payment recall/hold. Speed matters: recovery chances fall sharply after 24-72 hours.
- Report the fraud to the national cybercrime channel (India: cybercrime.gov.in or helpline 1930) and the relevant police unit; keep reference numbers.
- Preserve the invoice, bank change request, email thread and payment confirmations.

## Technical investigation
- Check mailbox audit logs and sign-in logs for the impersonated or targeted users.
- Look for inbox rules that hide replies (move to RSS, mark as read, delete), external forwarding, new delegates, new OAuth consents.
- Search the gateway for the same sender or reply-to across other recipients.
- Review recent lookalike-domain registrations for the company (typosquatting scanner) and block them.

## Response
- Reset credentials and revoke sessions for compromised accounts; enforce MFA.
- Remove malicious rules; notify the real counterparties by a verified phone number (not from the email thread).
- Add a mandatory call-back verification control for bank-detail changes and payments above a threshold.

## Prevention
- DMARC at quarantine/reject, external-sender banners, display-name protection, domain monitoring.
- Dual approval for payments and vendor-detail changes.
