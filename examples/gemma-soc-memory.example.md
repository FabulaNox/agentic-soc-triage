# SOC Correlation Memory

The agent loads the **Correlation Rules** and **Known Patterns** sections each
run (Stage 1), and appends new benign patterns it identifies to the bottom (IPs
normalised to `/24`). The file lives in the notes vault and is committed to git
on every update, so the learning is versioned and reviewable.

## Correlation Rules

IF/THEN rules the agent applies *first*, before anything else:

- IF rule `100120` source is in `198.51.100.0/24` (VPN range) THEN KNOWN - expected remote-admin auth.
- IF rule `5710` on `win11-lab` AND a gaming launcher is in today's top processes THEN KNOWN - game-client telemetry.
- IF rule `23506` (vuln) AND package already at latest repo version THEN KNOWN - no upstream patch available.

## Known Patterns

Recurring, benign, but not strict enough for an IF/THEN rule:

- Edge-router scan noise (rule `100120`) from rotating internet sources, dropped at the firewall - high count is normal.
- File-integrity triplets after a game-client patch (rule `750`) - not suspicious, just post-update checksums.

## Open Questions

Things the agent has seen but not yet resolved (candidates for an L2 look):

- Occasional outbound from `lab-fedora` to a CDN range - benign so far, watching.

## Learned (auto-appended)

- KNOWN: `.cc` TLD queries from IoT app on `198.51.100.0/24`, benign vendor telemetry - logged 2026-04-08
- KNOWN: rule `100124` burst correlates with router DHCP renewal window - logged 2026-04-10
