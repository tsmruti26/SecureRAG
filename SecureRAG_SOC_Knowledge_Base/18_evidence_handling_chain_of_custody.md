# Evidence Handling and Chain of Custody

## Principles
- Preserve first, analyse second. Work on copies; keep originals read-only.
- Collect in order of volatility: memory, running processes and network connections, temporary files, disk, logs, backups, cloud logs.
- Record who collected what, when, where, how, and the hash of every artefact.
- Time: record the timezone and any clock offset of source systems; use UTC in reports.

## Chain of custody record (minimum fields)
- Evidence ID, description, source system and location.
- Collected by, date/time (UTC), method/tool and version.
- Hash values (SHA-256) at collection and after each transfer.
- Storage location and access list; each hand-off with date, from, to, reason.

## Collection notes
- Memory: capture before shutdown where policy allows. Disk: forensic image with write blocking for physical media or snapshot for cloud volumes.
- Email: export original .eml/.msg with full headers; keep message trace and mailbox audit logs.
- Cloud: export identity provider sign-in logs, audit logs, storage access logs before retention windows expire; snapshot instances before termination.
- Network: PCAP or flow records and proxy/DNS logs for the relevant window.
- Mobile and personal devices: only with consent or legal authority.

## Handling malware samples
- Store in password-protected archives (commonly password "infected"), in an isolated repository; never execute outside an isolated sandbox.
- Do not upload confidential files to public scanning services.

## Reporting
- Separate facts, analysis and hypotheses. Label AI-generated content as such and have a human verify it before it enters a case file or report.
