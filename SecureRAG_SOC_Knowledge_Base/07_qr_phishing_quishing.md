# QR Code Phishing (Quishing) Playbook

ATT&CK: T1566.002 (phishing link), T1566.001 (attachment, when QR is inside a PDF/image), T1204.001 (user execution), T1078 (valid accounts after credential theft), T1539 (steal web session cookie), T1111 (MFA interception).

## Why QR phishing works
- URL is hidden inside an image, so email gateways that scan text links or attachments often miss it.
- The victim scans with a personal phone, which sits outside corporate proxy, EDR and DNS filtering.
- Common lures: MFA re-enrolment, "shared document", payroll/benefits update, voicemail, parcel delivery, invoice, parking/payment stickers.
- Physical variant: a malicious sticker placed over a legitimate QR code (posters, parking meters, restaurant tables, conference badges).
- Adversary-in-the-middle (AiTM) kits relay the real login page, so the password AND the MFA code/session cookie are captured.

## Triage (first 15 minutes)
1. Collect the email (original .eml with headers), the QR image, sender, recipients, time received. Do not open the link on a corporate device.
2. Decode the QR in an isolated analysis tool (the SecureRAG QR Phishing page decodes and scores without visiting the URL).
3. Record the decoded payload defanged (hxxps://example[.]com). Check: raw IP host, shortener or redirector, punycode/IDN, risky TLD, deep subdomains, credential keywords, nested redirect parameters, brand name inside a foreign domain.
4. Check domain age, registrar, certificate transparency logs and passive DNS using trusted intelligence sources. Heuristic signals alone do not prove malice; confirm in a sandbox or with threat intelligence.
5. Scope: search the mail gateway for the same sender, subject, attachment hash, QR image hash and decoded domain across all mailboxes.

## Determine exposure
- Who received it, who opened it, who reported it. A user report means at least one person saw it; assume others scanned.
- Search DNS/proxy/firewall logs for the domain and its resolved IPs. Mobile scans on personal phones will not appear; ask recipients directly.
- In the identity provider, review sign-ins for each recipient from the time of delivery: new IP/ASN/country, impossible travel, new device, user agent changes, successful sign-in shortly after the click, "MFA satisfied by claim in token" events.
- Check for post-compromise actions: new inbox rules (forwarding, delete, move to RSS folder), new OAuth app consent, new MFA method registered, new mailbox delegates, password or recovery changes (T1098, T1114.003, T1528).

## Containment (propose, human approves)
- Block the domain and IPs at DNS, proxy and email gateway.
- Purge or quarantine the message from all mailboxes (soft delete first, preserve a copy as evidence).
- For any user who submitted credentials: revoke all refresh tokens and active sessions, force password reset, review and remove unknown MFA methods and OAuth consents, then re-enrol MFA with phishing-resistant methods (FIDO2/passkeys) where possible.
- Remove malicious inbox rules and delegates. Check sent items for onward phishing (T1534).
- Warn staff with a short, plain notice and the real QR image (defanged context only).

## Eradication and recovery
- Confirm no persistence: OAuth apps, forwarding, devices registered in the identity provider, mailbox permissions.
- Monitor affected accounts for 14 days with elevated alerting.
- Submit the domain to takedown channels (registrar abuse, hosting provider, browser safe-browsing report) via the takedown action in the incident.

## Prevention
- Email gateway: enable QR-code and image URL extraction/detonation; flag emails whose body is mostly an image with a QR.
- Conditional access: require compliant/managed devices; block legacy auth; use number matching and phishing-resistant MFA.
- Awareness training on QR codes, physical sticker tampering, and "never scan QR from unexpected email".
- Poster/venue QR codes owned by the company should be inspected periodically.

## Severity guidance
- Low: QR seen, nobody scanned, domain blocked.
- Medium: scanned by one or more users, no credentials confirmed.
- High: credentials or session cookies likely captured, or a privileged account involved.
- Critical: confirmed account takeover with data access, financial fraud, or lateral spread.
