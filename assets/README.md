# Screenshots

Drop redacted images here and reference them from the top-level README.

**These show live data** (hostnames, IPs, domains). The text sanitisation gate
that protects the rest of this repo **cannot scan image pixels** - so each
screenshot must be **cropped/blurred by hand** before it is committed. Redact:
real hostnames, internal/public IPs, domain names, agent names, and any token.

Shots worth capturing (in priority order):

1. `telegram-alert.png` - a real-time Hermes alert on the phone (level 7+):
   agent, rule, one-line description. Redact host/IP.
2. `wazuh-dashboard.png` - the Wazuh overview: agents reporting, alert levels
   over time. Redact agent names / IPs.
3. `daily-report-rendered.png` - a daily report with the injected **L1 Analysis**
   block (posture, action items, finding verdicts). Redact hosts/IPs.
4. `l2-escalation.png` - an L2 (Claude) review session opened on a flagged
   finding, showing the verdict written back.

Until redacted images are added, the constructed text examples in
[`../examples/`](../examples/) stand in as the expected output.
