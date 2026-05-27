# Security Report - 2026-04-09

*Generated overnight from the last 24h of Wazuh + Suricata data. The agent
consumes the three sections below and appends the "L1 Analysis" block at the
bottom. Hosts, addresses, and IDs here are illustrative.*

## Top Wazuh Rules

| Rule ID | Level | Count | Description |
|---|---|---|---|
| 100120 | 5 | 1,842 | Edge router dropped inbound scan -> 203.0.113.10 |
| 100124 | 3 | 410 | Router DHCP lease event |
| 5710 | 8 | 3 | sshd: connection from unrecognised host |
| 23506 | 7 | 1 | Vulnerability affects libfoo |

## High / Critical Alerts

- **Rule 5710** on `win11-lab`: outbound connection to unrecognised host 198.51.100.200
- **Rule 23506** on `workstation`: vulnerability affects libfoo (CVE-2026-XXXX)

## Top Suricata Signatures

| Count | Signature |
|---|---|
| 42 | ET SCAN Potential SSH Scan |
| 5 | ET DNS Query for .cc TLD |

---

<!-- everything below is appended by soc-agent.sh -->

## L1 Analysis (gemma4:e4b - 2026-04-09 06:03)

**Overall Posture:** ELEVATED

Volume normal (~140k events). Dominant pattern is perimeter scan noise on the
edge router (rule 100120), all blocked. The libfoo vuln was auto-closed (package
already at the latest repo version). One UNKNOWN remains: an outbound connection
from the Windows lab VM worth a human glance.

### Action Items

| # | Priority | Status | Item | Target |
|---|----------|--------|------|--------|
| 1 | Med | Open | Unexpected outbound from lab VM - confirm benign | win11-lab |
| 2 | Info | L1 Closed | Edge scan noise, blocked at perimeter | router |
| 3 | Low | L1 Closed | libfoo CVE present but already at latest repo version | workstation |

### Finding Verdicts

| Finding | Verdict | Inference |
|---------|---------|-----------|
| Rule 5710 on win11-lab | UNKNOWN | Outbound to unrecognised host, no vault note, not in memory |
| Rule 23506 on workstation | KNOWN | Package recently installed, already latest in repo - no patch available |

### Edge Scanner IPs (blocked, last 24h)

| Source IP |
|-----------|
| 203.0.113.55 |
| 203.0.113.91 |

### L2 Review Required
Model flagged 1 finding it could not resolve (threshold: 1).
Open this report in an L2 (Claude) session to review:
Rule 5710 on win11-lab
