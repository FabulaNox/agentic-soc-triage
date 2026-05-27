<div align="center">

# Agentic SOC triage

**A local-LLM SOC analyst that triages a homelab SIEM's overnight alerts, so a human only sees what needs a human.**

[Why an agent](#why-an-agent-not-just-a-filter) · [The tiers](#the-l1---l2---human-tiers) · [Run it](#run-it) · [Part of NoxLab ↗](https://github.com/FabulaNox/NoxLab)

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

</div>

---

A **local-LLM SOC analyst** that triages a homelab SIEM's overnight alerts so a
human only ever looks at what actually needs a human. An **L1 agent** (a small
local model) classifies every high/critical finding, closes the obvious, learns
benign patterns over time, and **escalates only what it cannot resolve** to an
**L2** reviewer (Claude) and then to me. Runs entirely on the box, on a budget
GPU, for free.

It exists because a homelab SIEM produces a *lot* of noise - on a slow day this
one ingests ~160,000 events - and doing the morning triage by hand (or by paying
a cloud model per token, sending security telemetry off-box) does not scale.

![SOC triage pipeline: a scheduled overnight job builds a daily report (top rules, high/critical alerts, Suricata signatures) that feeds the L1 agent (gemma4:e4b via Ollama) - stage 1 classifies each finding with short-circuits, vault RAG, correlation memory, and month-context; stage 2 assembles posture, summary, and action items; stage 3 escalates if unresolved findings exceed a threshold. The agent injects an L1 Analysis block back into the report for a morning human spot-check, and flags what it cannot resolve for on-demand L2 (Claude) review, then a human verdict.](assets/pipeline.svg)

## Contents

- [Why an agent, not just a filter](#why-an-agent-not-just-a-filter)
- [The L1 -> L2 -> human tiers](#the-l1---l2---human-tiers)
- [What's here](#whats-here)
- [Run it](#run-it)
- [What the agent produces](#what-the-agent-produces)
- [Screenshots](#screenshots)
- [Design notes](#design-notes)

---

## Why an agent, not just a filter

The hard part of SOC triage is not volume, it is **judgement under correlation**:
"this rule fired 200 times" is meaningless until you know it is a gaming session,
a scanner, or a patch burst. So the L1 stage is a genuine agent, not a regex:

- **It reasons over context, in order.** The prompt tells the model to check
  *correlation rules* first, then *known patterns*, then *today's top rules +
  recent reports* for correlated activity - mirroring how an analyst actually
  triages.
- **It is cheap where judgement isn't needed.** Before any model call, two
  short-circuits close findings deterministically: a list of unconditionally
  benign rule IDs, and a CVE pre-check that closes a vuln alert when the affected
  package was just installed and is *already at the latest available version*
  (CVEs present, no upstream patch = nothing to do).
- **It gets sharper over time.** Benign patterns the model identifies are
  normalised (IPs to `/24`) and appended to a **correlation memory** the next run
  loads - and committed to the notes vault, so the learning is versioned.
- **It grounds itself in my own notes.** A **RAG lookup** runs per rule against
  the knowledge-base vault, so the model sees things like *"Rule 5710 is expected
  from the VPN range - benign"* before it decides.
- **It knows its limits.** Anything it classifies `SUSPICIOUS`/`UNKNOWN` above a
  threshold trips an **L2 escalation** - it never adjudicates incidents itself.

## The L1 -> L2 -> human tiers

| Tier | Who | Runs | Job |
|---|---|---|---|
| **L1** | `gemma4:e4b` (local, nightly, free) | every night | filter + summarise, close the obvious, **never adjudicate** |
| **L2** | Claude (on demand) | only the handful L1 couldn't resolve | review the escalation, record a verdict |
| **Human** | me | always | final call |

Every L1 run logs a row to a **baseline CSV** (its decision, timings, and a column
for the later L2 verdict) so L1's calls can be measured against L2 over time -
the model is held accountable, not trusted blindly.

In practice most mornings are **L1-only**: the agent closes everything and I just
read the digest. L2 is the exception - opened only when it flags something it
cannot resolve - so a recent report typically shows exactly the L1 output below.

## What's here

```
scripts/soc-agent.sh        the L1 agent (3 stages: classify, assemble, escalate)
soc-agent.conf.example      config: model, paths, known-rule short-circuits, thresholds
examples/
  sample-daily-report.md    a report before/after the agent runs (the injected L1 block)
  gemma-soc-memory.example.md   the self-updating correlation memory format
assets/                     where the dashboard / alert screenshots go (see assets/README.md)
```

## Run it

```console
$ soc-agent.sh --report ~/notes/.../security-report-2026-04-09.md
[2026-04-09 06:00:01] Starting SOC agent on: security-report-2026-04-09.md
[2026-04-09 06:00:01] Stage 1: classifying findings...
[2026-04-09 06:02:01] Stage 1 done (120034ms): 6 findings
[2026-04-09 06:02:01] Stage 2: assembling draft...
[2026-04-09 06:03:48] Stage 2 done (107442ms)
[2026-04-09 06:03:48] Stage 3: L2 flag triggered (1 unresolved findings)
[2026-04-09 06:03:48] Injected L1 Analysis block into report
[2026-04-09 06:03:49] Memory updated and committed
[2026-04-09 06:03:49] Done
```

A `--dry-run` prints the analysis block to stdout instead of injecting it. The
agent is idempotent: it skips a report that already has an `## L1 Analysis`
section.

## What the agent produces

The agent appends an **L1 Analysis** block to the daily report - posture, a
summary, an action-items table, the per-finding verdicts, and (if triggered) an
L2-review flag. See [`examples/sample-daily-report.md`](examples/sample-daily-report.md)
for the full before/after; the block looks like:

```markdown
## L1 Analysis (gemma4:e4b - 2026-04-09 06:03)

**Overall Posture:** ELEVATED

Volume normal (~140k events). Dominant pattern is perimeter scan noise on the
edge router (rule 100120), all blocked. One UNKNOWN: an outbound connection from
the Windows lab VM worth a human glance.

### Action Items
| # | Priority | Status | Item | Target |
|---|----------|--------|------|--------|
| 1 | Med | Open | Unexpected outbound from lab VM - confirm benign | win11-lab |
| 2 | Info | L1 Closed | Edge scan noise, blocked at perimeter | router |

### Finding Verdicts
| Finding | Verdict | Inference |
|---------|---------|-----------|
| Rule 100120 on router | KNOWN | Perimeter scan, dropped at firewall - recurring |
| Rule 5710 on win11-lab | UNKNOWN | Outbound to unrecognised host, no vault note |

### L2 Review Required
Gemma flagged 1 finding it could not resolve (threshold: 1).
```

## Screenshots

See [`assets/README.md`](assets/README.md). The Telegram real-time alert, the
Wazuh dashboard, and a rendered daily report go there - **redacted** (these show
live hosts/IPs, and an image's pixels are not covered by the text sanitisation
gate, so they must be cropped/blurred by hand before publishing).

## Design notes

- **Local, small, overnight is deliberate.** Local keeps telemetry on-box (no
  third party sees the security events, no per-token cost). `e4b` is enough for
  first-pass triage on a budget GPU - it filters and summarises, it does not
  adjudicate. Overnight uses the GPU while nothing else wants it; the digest is
  ready before the day starts.
- **It is a noise filter and first-pass summariser, not the decision-maker.**
  Escalations and verdicts stay with a human, by design - a small local model is
  good at "obviously benign / obviously worth a look," and is kept on that side
  of the line.

---

*Part of a self-hosted security homelab. Rule IDs are stock Wazuh IDs; hosts,
addresses, and paths are abstracted.*

## License

[MIT](LICENSE) - configs, scripts, and docs are free to adapt.
