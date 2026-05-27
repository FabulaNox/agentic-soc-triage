#!/usr/bin/env bash
# soc-agent.sh - L1 SOC analyst. Reads a daily SIEM report, classifies each
# high/critical finding with a local LLM (with cheap deterministic short-circuits,
# vault RAG, and a self-updating correlation memory), assembles a posture +
# action items, escalates what it cannot resolve to L2, and injects an
# "L1 Analysis" block back into the report. Idempotent; --dry-run prints instead.
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
CONFIG="$HOME/.config/soc-agent.conf"
[[ -f "$CONFIG" ]] || { echo "ERROR: config not found at $CONFIG"; exit 1; }
# shellcheck disable=SC1090  # config path is runtime-determined
source "$CONFIG"

DRY_RUN=false
REPORT_FILE=""

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG" >&2; }

ollama_call() {
  local prompt="$1"
  local payload
  payload=$(jq -n --arg m "$OLLAMA_MODEL" --arg p "$prompt" \
    '{"model":$m,"prompt":$p,"stream":false}')
  curl -sf --max-time "$OLLAMA_TIMEOUT" "$OLLAMA_URL" \
    -H "Content-Type: application/json" \
    -d "$payload" | jq -r '.response'
}

is_known_rule() {
  local rule_id="$1"
  [[ " $KNOWN_RULES " == *" $rule_id "* ]]
}

# Vuln-rule pre-check: if the affected package was recently installed and is already
# at the latest available version, there is no actionable patch - close as KNOWN.
# Returns "KNOWN|<inference>" if resolved, empty string if inconclusive (falls to the model).
check_cve_package() {
  local desc="$1"
  local pkg_name install_date installed candidate cutoff

  pkg_name=$(echo "$desc" | grep -oiE 'affects ([a-z0-9_.+-]+)' | awk '{print $2}' | head -1 || true)
  [[ -z "$pkg_name" ]] && return 0

  install_date=$(grep -iE "(install|upgrade).*${pkg_name}" /var/log/dpkg.log 2>/dev/null | \
    tail -1 | awk '{print $1}' || true)
  [[ -z "$install_date" ]] && return 0

  cutoff=$(date -d '7 days ago' '+%Y-%m-%d')
  [[ "$install_date" < "$cutoff" ]] && return 0

  installed=$(apt-cache policy "$pkg_name" 2>/dev/null | awk '/Installed:/{print $2}' || true)
  candidate=$(apt-cache policy "$pkg_name" 2>/dev/null | awk '/Candidate:/{print $2}' || true)
  [[ -z "$installed" || "$installed" == "(none)" ]] && return 0
  [[ "$installed" != "$candidate" ]] && return 0

  echo "KNOWN|${pkg_name} installed ${install_date}, version ${installed} is latest in repo - CVEs present but no upstream patch available"
}

normalise_cidr() {
  local ip="$1"
  echo "$ip" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $1".0/24"}' || true
}

extract_section() {
  local file="$1" header="$2"
  awk -v h="$header" '
    $0 ~ h   { found=1; next }
    found && /^## / { exit }
    found && /^---$/ { exit }
    found    { print }
  ' "$file"
}

# RAG: surface the analyst's own notes for a rule before the model decides.
vault_lookup() {
  local query="$1"
  grep -r "$query" "$VAULT_DIR"/ --include="*.md" -l 2>/dev/null | \
    grep -v "gemma-soc-memory\|soc-agent\|Daily reports\|triage-baseline" | head -3 | while read -r f; do
    grep -m 2 "$query" "$f" 2>/dev/null | head -2 || true
  done | head -6
}

load_memory_excerpt() {
  awk '/^## Correlation Rules/,/^## Open Questions/' "$MEMORY_FILE" | head -80
}

known_events_empty() {
  local file="$1"
  grep -q "No pre-annotated events" "$file"
}

# Compact digest of the last 3 reports this month - gives the model temporal
# pattern context (same rule firing repeatedly = likely recurring known event).
load_month_context() {
  local current_report="$1"
  local month
  month=$(basename "$current_report" | grep -oE '[0-9]{4}-[0-9]{2}' | head -1)
  [[ -z "$month" ]] && return 0

  local report_files=()
  local current_base
  current_base=$(basename "$current_report")
  while IFS= read -r f; do
    report_files+=("$f")
  done < <(ls "$REPORT_DIR"/security-report-"${month}"-*.md 2>/dev/null | \
    awk -v cur="$current_base" '{if (substr($0, length($0)-length(cur)+1) < cur) print}' | \
    sort | tail -3)
  [[ ${#report_files[@]} -eq 0 ]] && return 0

  echo "RECENT REPORTS - ${month}:"
  for f in "${report_files[@]}"; do
    local rdate posture top3
    rdate=$(basename "$f" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}')
    posture=$(grep -m1 '\*\*Overall Posture:\*\*' "$f" | sed 's/.*Posture:\*\* //' || echo "-")
    top3=$(extract_section "$f" "## Top Wazuh Rules" | grep -E '^\|[^-]' | grep -v 'Rule ID' | head -3 | \
      awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/, "", $2); gsub(/^[ \t]+|[ \t]+$/, "", $5); printf "  Rule %s: %s\n", $2, $5}')
    echo "${rdate} [${posture}]"
    [[ -n "$top3" ]] && echo "$top3"
  done
}

# Collapse the High/Critical section to unique (rule, agent) pairs, capped at MAX_ALERTS.
dedup_alerts() {
  local file="$1"
  local section
  section=$(extract_section "$file" "## High / Critical Alerts")
  declare -A seen=()
  local count=0 rule_id agent key desc
  while IFS= read -r line; do
    [[ "$line" =~ ^-\ \*\* ]] || continue
    rule_id=$(echo "$line" | grep -oE 'Rule [0-9]+' | grep -oE '[0-9]+' | head -1 || true)
    agent=$(echo "$line" | grep -oE 'on `[^`]+`' | tr -d '`' | sed 's/^on //' || true)
    [[ -z "$rule_id" || -z "$agent" ]] && continue
    key="${rule_id}|${agent}"
    [[ -n "${seen[$key]:-}" ]] && continue
    seen[$key]=1
    desc=$(echo "$line" | sed 's/.*`: //' || true)
    (( count++ )) || true
    [[ $count -gt $MAX_ALERTS ]] && break
    printf '%s|%s\n' "$key" "$desc"
  done <<< "$section"
}

# ── Stage 1: classify each finding ────────────────────────────────────────────
stage1_classify() {
  local file="$1"
  local memory_excerpt top_rules vault_ctx prompt raw verdict inference mem_update month_ctx
  memory_excerpt=$(load_memory_excerpt)
  top_rules=$(extract_section "$file" "## Top Wazuh Rules")
  month_ctx=""
  if known_events_empty "$file"; then
    month_ctx=$(load_month_context "$file" || true)
  fi

  declare -a verdict_rows=()

  while IFS='|' read -r rule_id agent desc; do
    [[ -z "$rule_id" ]] && continue

    # Short-circuit: unconditionally benign rules skip the model entirely.
    if is_known_rule "$rule_id"; then
      verdict_rows+=("Rule ${rule_id} on ${agent}: KNOWN - short-circuit (unconditionally benign rule)")
      continue
    fi

    # Short-circuit: vuln rule - close if the package is recent and already latest.
    if [[ "$rule_id" == "23506" ]]; then
      local cve_check
      cve_check=$(check_cve_package "$desc" || true)
      if [[ -n "$cve_check" ]]; then
        verdict_rows+=("Rule ${rule_id} on ${agent}: ${cve_check}")
        continue
      fi
    fi

    # RAG: pull the analyst's notes for this rule.
    vault_ctx=$(vault_lookup "Rule $rule_id" || true)
    [[ -z "$vault_ctx" ]] && vault_ctx="No vault notes found for Rule $rule_id."

    local month_section=""
    [[ -n "$month_ctx" ]] && month_section="
RECENT REPORTS THIS MONTH (use for temporal pattern matching - same rule firing repeatedly = likely recurring known event):
${month_ctx}
"

    prompt="You are a homelab SOC analyst (L1). Classify this security alert.

Step 1: Check CORRELATION RULES in the memory below. If a matching IF/THEN rule applies, use that verdict directly.
Step 2: If no correlation rule matches, check KNOWN PATTERNS.
Step 3: If still uncertain, use TODAY'S TOP RULES and RECENT REPORTS to look for correlated activity.
${month_section}
MEMORY (correlation rules and known patterns):
${memory_excerpt}

TODAY'S TOP RULES (for correlation checks in Step 3):
${top_rules}

VAULT NOTES:
${vault_ctx}

Respond in EXACTLY this format - three lines, nothing else:
VERDICT: [KNOWN|SUSPICIOUS|UNKNOWN]
INFERENCE: [one sentence, max 20 words, explaining your reasoning]
MEMORY_UPDATE: [pattern to remember OR 'NONE']

--- ALERT ---
Rule ${rule_id} on ${agent}: ${desc}"

    raw=$(ollama_call "$prompt") || { log "WARN: ollama_call failed for Rule $rule_id on $agent"; raw=""; }
    verdict=$(echo "$raw" | grep -iE '^VERDICT:' | sed 's/^[^:]*:[[:space:]]*//' | grep -oiE '(KNOWN|SUSPICIOUS|UNKNOWN)' | head -1 | tr '[:lower:]' '[:upper:]' || true)
    inference=$(echo "$raw" | grep -iE '^INFERENCE:' | sed 's/^[^:]*:[[:space:]]*//' | head -1 || true)
    mem_update=$(echo "$raw" | grep -iE '^MEMORY_UPDATE:' | sed 's/^[^:]*:[[:space:]]*//' | head -1 || true)

    [[ -z "$verdict"   ]] && verdict="UNKNOWN"
    [[ -z "$inference" ]] && inference="No inference returned"
    [[ -z "$mem_update" || "$mem_update" =~ ^[Nn][Oo][Nn][Ee]$ ]] && mem_update=""

    verdict_rows+=("Rule ${rule_id} on ${agent}: ${verdict} - ${inference}")
    [[ -n "$mem_update" ]] && echo "MEMORY:${mem_update}"
  done < <(dedup_alerts "$file")

  printf '%s\n' "${verdict_rows[@]}"
}

# ── Stage 2: assemble posture + summary + action items ────────────────────────
stage2_assemble() {
  local verdicts="$1"
  local prompt

  prompt="You are a homelab SOC analyst. Write a security report section based on these classified findings.

FINDINGS:
${verdicts}

Write in EXACTLY this format:

POSTURE: [NORMAL|ELEVATED|CRITICAL]
SUMMARY: [2-3 sentences: total volume context, dominant pattern named, highest finding. Call out inferences like gaming sessions, update bursts, scanner activity.]
ACTION_ITEMS_START
[emoji] [High|Med|Low|Info] | [Open|L1 Closed] | [finding description and reasoning] | [Machine]
ACTION_ITEMS_END"

  local raw
  raw=$(ollama_call "$prompt") || { log "WARN: stage2 ollama_call failed"; echo ""; return 1; }
  echo "$raw"
}

parse_stage2() {
  local raw="$1"
  local posture summary
  posture=$(echo "$raw" | grep -iE '^POSTURE:' | sed 's/^[^:]*:[[:space:]]*//' | grep -oiE '(NORMAL|ELEVATED|CRITICAL)' | head -1 | tr '[:lower:]' '[:upper:]' || true)
  [[ -z "$posture" ]] && posture="UNKNOWN"
  summary=$(echo "$raw" | grep -iE '^SUMMARY:' | sed 's/^[^:]*:[[:space:]]*//' | head -1 || true)
  [[ -z "$summary" ]] && summary="Summary not generated."
  echo "POSTURE:${posture}"
  echo "SUMMARY:${summary}"
  echo "ACTION_ITEMS_START"
  echo "$raw" | awk '/ACTION_ITEMS_START/{found=1;next} /ACTION_ITEMS_END/{found=0} found{print}'
  echo "ACTION_ITEMS_END"
}

# ── Stage 3: escalate what L1 could not resolve ───────────────────────────────
stage3_escalation() {
  local verdicts="$1"
  local count
  count=$(echo "$verdicts" | grep -cE ': (SUSPICIOUS|UNKNOWN) -' || true)
  echo "$count"
}

# Append benign patterns to the correlation memory (IPs normalised to /24), versioned in git.
update_memory() {
  local memory_updates="$1" report_date="$2"
  [[ -z "$memory_updates" ]] && return
  {
    echo ""
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      local ip
      if echo "$line" | grep -qE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
        ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        line="${line//$ip/$(normalise_cidr "$ip")}"
      fi
      echo "- ${line} - logged ${report_date}"
    done <<< "$memory_updates"
  } >> "$MEMORY_FILE"
}

extract_scanner_ips() {
  local file="$1"
  local rules_section
  rules_section=$(extract_section "$file" "## Top Wazuh Rules")
  # Source IPs from edge-router scan rows; strip everything from '->' on to avoid the WAN IP.
  echo "$rules_section" | grep -E '\| 10012[0-9] ' | while IFS= read -r line; do
    echo "$line" | sed 's/->.*//' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true
  done | grep -v '^$' | sort -u
}

build_finding_table() {
  local verdicts="$1"
  local rule_agent rest verdict inference
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    rule_agent=$(echo "$line" | cut -d: -f1)
    rest=$(echo "$line" | cut -d: -f2-)
    verdict=$(echo "$rest" | grep -oE '(KNOWN|SUSPICIOUS|UNKNOWN)' | head -1 || true)
    inference=$(echo "$rest" | sed -E 's/[[:space:]]*(KNOWN|SUSPICIOUS|UNKNOWN)[[:space:]]*-[[:space:]]*//' || true)
    printf '| %s | %s | %s |\n' "$rule_agent" "${verdict:-UNKNOWN}" "$inference"
  done <<< "$verdicts"
}

inject_report() {
  local file="$1" posture="$2" summary="$3" action_items="$4" finding_table="$5" l2_flag="$6" scanner_ips="$7"
  local ts block tmp
  ts=$(date '+%Y-%m-%d %H:%M')

  block="
## L1 Analysis (${OLLAMA_MODEL} - ${ts})

**Overall Posture:** ${posture}

${summary}

### Action Items

| # | Priority | Status | Item | Target |
|---|----------|--------|------|--------|"

  local i=1 priority status item target
  while IFS='|' read -r priority status item target; do
    [[ -z "${priority// }" ]] && continue
    block="${block}
| ${i} | ${priority} | ${status} | ${item} | ${target} |"
    (( i++ )) || true
  done <<< "$action_items"

  block="${block}

### Finding Verdicts

| Finding | Verdict | Inference |
|---------|---------|-----------|
${finding_table}"

  if [[ -n "$scanner_ips" ]]; then
    block="${block}

### Edge Scanner IPs (blocked, last 24h)

| Source IP |
|-----------|"
    while IFS= read -r ip; do
      [[ -z "$ip" ]] && continue
      block="${block}
| ${ip} |"
    done <<< "$scanner_ips"
  fi

  [[ -n "$l2_flag" ]] && block="${block}

${l2_flag}"

  if [[ "$DRY_RUN" == "true" ]]; then echo "$block"; return; fi

  tmp=$(mktemp); cat "$file" > "$tmp"; printf '%s\n' "$block" >> "$tmp"; mv "$tmp" "$file"
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --report)   REPORT_FILE="$2"; shift 2 ;;
      --dry-run)  DRY_RUN=true; shift ;;
      *)          echo "Unknown arg: $1"; exit 1 ;;
    esac
  done

  if [[ -z "$REPORT_FILE" ]]; then
    local TODAY; TODAY=$(date '+%Y-%m-%d')
    REPORT_FILE="${REPORT_DIR}/security-report-${TODAY}.md"
  fi
  [[ -f "$REPORT_FILE" ]] || { log "ERROR: report not found: $REPORT_FILE"; exit 1; }
  [[ -f "$MEMORY_FILE"  ]] || { log "ERROR: memory file not found: $MEMORY_FILE"; exit 1; }

  if grep -q "^## L1 Analysis" "$REPORT_FILE" && [[ "$DRY_RUN" == "false" ]]; then
    log "Already analysed: $REPORT_FILE - skipping"; exit 0
  fi

  log "Starting SOC agent on: $REPORT_FILE"
  local report_date
  report_date=$(basename "$REPORT_FILE" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' || date '+%Y-%m-%d')

  log "Stage 1: classifying findings..."
  local t0 t1 stage1_raw verdicts memory_updates
  t0=$(date +%s%3N); stage1_raw=$(stage1_classify "$REPORT_FILE"); t1=$(date +%s%3N)
  verdicts=$(echo "$stage1_raw" | grep -v '^MEMORY:' | grep -v '^[[:space:]]*$' || true)
  memory_updates=$(echo "$stage1_raw" | grep '^MEMORY:' | sed 's/^MEMORY://' || true)
  local finding_count; finding_count=$(echo "$verdicts" | grep -c '.' || true)
  log "Stage 1 done ($(( t1 - t0 ))ms): ${finding_count} findings"

  local stage2_raw parsed posture summary action_items
  if [[ "$finding_count" -eq 0 ]]; then
    log "Stage 2: no findings - skipping model call"
    posture="NORMAL"; summary="No high or critical alerts in this reporting window."; action_items=""
  else
    log "Stage 2: assembling draft..."
    t0=$(date +%s%3N); stage2_raw=$(stage2_assemble "$verdicts") || stage2_raw=""; t1=$(date +%s%3N)
    parsed=$(parse_stage2 "$stage2_raw")
    posture=$(echo "$parsed" | grep '^POSTURE:' | sed 's/^POSTURE://' || true)
    summary=$(echo "$parsed" | grep '^SUMMARY:' | sed 's/^SUMMARY://' || true)
    action_items=$(echo "$parsed" | awk '/^ACTION_ITEMS_START/{found=1;next} /^ACTION_ITEMS_END/{found=0} found{print}')
    [[ -z "$posture" ]] && posture="UNKNOWN"
    [[ -z "$summary" ]] && summary="Stage 2 did not return a summary."
    log "Stage 2 done ($(( t1 - t0 ))ms)"
  fi

  local unresolved l2_flag flagged
  unresolved=$(stage3_escalation "$verdicts"); l2_flag=""
  if (( unresolved >= ESCALATION_THRESHOLD )); then
    flagged=$(echo "$verdicts" | grep -E ': (SUSPICIOUS|UNKNOWN) -' | sed 's/:.*//' | tr '\n' ', ' | sed 's/,$//' || true)
    l2_flag="### L2 Review Required
Model flagged ${unresolved} finding(s) it could not resolve (threshold: ${ESCALATION_THRESHOLD}).
Open this report in an L2 (Claude) session to review:
${flagged}"
    log "Stage 3: L2 flag triggered (${unresolved} unresolved findings)"
  else
    log "Stage 3: no escalation needed"
  fi

  local finding_table scanner_ips
  finding_table=$(build_finding_table "$verdicts")
  scanner_ips=$(extract_scanner_ips "$REPORT_FILE")
  inject_report "$REPORT_FILE" "$posture" "$summary" "$action_items" "$finding_table" "$l2_flag" "$scanner_ips"
  log "Injected L1 Analysis block into report"

  if [[ "$DRY_RUN" == "false" ]]; then
    update_memory "$memory_updates" "$report_date"
    git -C "$VAULT_DIR" add "${MEMORY_FILE#"$VAULT_DIR"/}" 2>/dev/null || true
    git -C "$VAULT_DIR" commit -m "chore: soc-agent memory update ${report_date}" 2>/dev/null || true
    log "Memory updated and committed"
  fi
  log "Done"
}

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && main "$@"
