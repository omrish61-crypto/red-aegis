# 4. Step-by-Step Execution Workflow (multi-agent pentest)

The complete execution flow of the INTECTED multi-agent system — from target
entry to final report. Every step names the responsible agent, the module,
the GATE that must pass, the command, and the output it produces. Nothing
executes without a gate; nothing is claimed without evidence.

Legend: [G1]=Supervisor gate · [OP]=operator approval · [G1+OP]=both

```
  P0  Target entry ──► P1  Passive recon ──► P2  Fingerprint+plan
       │                    │                     │
       ▼                    ▼                     ▼
   scope set            facts+evidence        evidence graph
       │                    │                  + ranked plan
       ▼                    ▼                     │
  P3  Targeted testing (per priority, loop) ─────┘
       │   [G1] tool call → [G1+OP] execute → parse → facts
       ▼
  P4  Validation & write-back [OP]
       │
       ▼
  P5  Report / retest
```

---

## PHASE 0 — Target entry (operator)

| | |
|---|---|
| Agent | operator (human) |
| Action | add targets (IP / domain / IP range) to a mission scope |
| Command | dashboard Mission tab → "Add target", or `intected task` |
| Gate | target validated (`scope.validate_target`): rejects URLs, malformed IPs |
| Output | mission `allowed_hosts` scope; Start-test button enabled |

The scope is the deny-by-default boundary for EVERYTHING that follows. A
target not in this list cannot be scanned by any agent at any stage.

---

## PHASE 1 — Passive / gradual recon (Agent 2, READ-ONLY)

| | |
|---|---|
| Agent | Recon Agent — read-only by construction (registry has no injection tools) |
| Gate | [G1] `supervisor.validate_tool_call` — scope, rate ≤ 300 pps, stealth flags |
| Command | `intected run --mission N --tool nmap_ports --target <T>` |
| Executed | `nmap -Pn --top-ports 1000 --max-rate 50 -T3 --data-length 32 --open <T>` |
| Output | raw evidence + parsed facts (ports, banners) with sha256 |

Stealth is structural: `-T3`, `--max-rate 50`, `--data-length 32` are injected
by the ToolConfigurator (`tools._build_command`) — the planner cannot omit
them. Real-time stdout (`tools.execute_streaming`) streams the scan to the
log so the AI sees progress, not just the exit code.

**Decision matrix** (`intected matrix --mission N`) then picks the next tool
by footprint (IF web → content discovery / nuclei; IF network → service
detection; IF WAF → passive probes only; masscan never).

---

## PHASE 2 — Fingerprinting & planning (Planner)

| | |
|---|---|
| Agent | Planner (evidence-based, methodology 11-13) |
| Gate | none (read-only composition) |
| Command | `intected plan --mission N` / `intected evidence --mission N` |
| Output | Evidence Graph (services, technologies+confidence, WAF, surface) + ranked plan (P1..Pn, each with `based_on` fact ids) |

The rule of the system: every finding leads to a test hypothesis; every test
is based on a previous finding. An empty surface yields no hypothesis.

**Live CVE correlation** (only for versions that exist in the evidence):
`intected.cve.lookup_cpe(cpe_from_banner(banner))` → NIST NVD API (throttled,
cached). Failures are loud (`nvd_unavailable`) — no LLM-memory CVEs, ever.

**Pre-flight tool knowledge**: `intected tools probe --tool X` runs
`X --version/--help` in the kali image and feeds the REAL flags to the
planner's context (kills hallucinated flags).

---

## PHASE 3 — Targeted testing (Agent 3, operator-gated loop)

For each plan priority, in rank order, until the plan stabilizes:

| Step | Who | Gate | What |
|---|---|---|---|
| 3.1 propose | Planner/matrix | — | next tool call (registered, typed params) |
| 3.2 validate | Supervisor | [G1] | scope, rate bounds, tool whitelist, DoS/brute bans, `-p-` flag |
| 3.3 approve | operator | [OP] | full scans / exploitation need explicit approval |
| 3.4 execute | Tool registry | [G1+OP] | `execute_streaming` — bounded timeout, real-time logs |
| 3.5 parse | Extractors | — | tool output → facts + sha256 evidence (PII-redacted) |
| 3.6 re-plan | Planner | — | facts update the evidence graph → priorities re-rank |

Loop termination: no pending priorities, or the operator closes the mission.

PII guard applies at 3.5: fact values are scanned and redacted
(email/phone/credit-card/SSN). DB proof (SELECT version()) is the only
data-plane action in the registry — extraction is impossible by construction.

---

## PHASE 4 — Validation & write-back (operator-certified)

| Step | Who | Gate | What |
|---|---|---|---|
| 4.1 severity | Planner/operator | [OP] | findings classified (critical..info) |
| 4.2 scoring | `evidence.score_finding` | — | confidence × impact × exploitability × exposure → P0-P3 |
| 4.3 write-back | operator | [OP] | `intected pc write` → production pentest-core DB (scope gate + severity whitelist) |

Write-back is operator-certified: the reasoning engine can never push
findings to the production DB on its own.

---

## PHASE 5 — Report & retest

- Mission report from real logs/DB (ENGAGEMENT-REPORT pattern)
- Retest after remediation: same engines, same targets → delta is real
  improvement, not coverage noise
- Acceptance: independent control-agent audit vs ground truth → verdict table

---

## The gates, summarized

| Gate | Enforced by | Blocks |
|---|---|---|
| Target validation | `scope.validate_target` | malformed/URL targets at entry |
| Scope | `supervisor` (deny by default) | any out-of-scope target |
| Rate/timing | `tools._build_command` | aggressive scans, DoS, IDS-triggering rates |
| Tool whitelist | `tools.validate_params` | unknown tools, banned params |
| Operator approval | CLI `--operator-approved` | `-p-`, exploitation, write-back |
| Evidence | extractors + sha256 | findings without tool-log support |
| PII | `pii.redact` at parse | PII in stored facts |

## Commands cheat-sheet

```
intected run   --mission N --tool <name> --target <T> [--operator-approved]
intected plan      --mission N        # ranked plan (evidence-based)
intected matrix    --mission N        # next tool call by footprint
intected evidence  --mission N        # structured per-target model
intected tools probe [--tool X]       # real flags from the kali image
intected waf-kb query --query "…"     # WAF knowledge retrieval
intected pc write …                   # operator-certified write-back
```
