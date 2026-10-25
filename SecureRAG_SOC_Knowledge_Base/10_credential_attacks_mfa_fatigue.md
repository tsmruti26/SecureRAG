# Credential Attacks and MFA Abuse Playbook

ATT&CK: T1110.001 (guessing), T1110.003 (password spraying), T1110.004 (credential stuffing), T1621 (MFA request generation / fatigue), T1556 (modify authentication process), T1078 (valid accounts), T1539 / T1528 (session cookie / token theft).

## Patterns and how to recognise them
- Brute force: many failures for one account (Windows 4625, repeated 4771/4776 for Kerberos/NTLM).
- Password spraying: one or few passwords tried across many accounts, low rate per account, often one IP or a rotating proxy pool; look for many distinct usernames from one source in a short window.
- Credential stuffing: breached username/password pairs against public logins; high-volume failures then occasional success; many different usernames, user agents and IPs.
- MFA fatigue: repeated push prompts, user finally approves; look for bursts of MFA denials/no-response followed by a success from a new IP.
- Token/session theft: sign-in succeeds with MFA satisfied by token claim from a different device or location than the original session.

## Triage
1. Identify target accounts, source IPs/ASNs, user agents, time window, and the success/failure ratio.
2. Check whether any success followed the failures; if yes, treat the account as compromised.
3. Check geo, impossible travel, anonymising proxies/VPN/Tor, and legacy authentication protocols that bypass MFA.
4. Review what the account did after sign-in: mailbox rules, OAuth consents, MFA method changes, data downloads, privilege changes.

## Containment
- Block offending IPs/ASNs at the edge or via conditional access (note that attackers rotate IPs).
- For compromised accounts: revoke sessions and refresh tokens, reset password, remove unknown MFA methods, review recovery options.
- Temporarily tighten conditional access: require compliant devices, block legacy auth, enable number matching and additional context on push prompts.
- If a service account is involved, rotate its secret and review where it is used.

## Prevention
- Phishing-resistant MFA (FIDO2/passkeys) for admins and high-risk roles.
- Smart lockout and rate limiting, breached-password screening, banned password lists.
- Alert on: >N failed logins per account, >N distinct accounts from one IP, new MFA registration followed by sensitive actions, MFA denial bursts.
