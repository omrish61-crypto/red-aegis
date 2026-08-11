# Architecture Review — Multi-Agent Pentest Spec (2026-08-11)

Review of the operator's multi-agent spec (Supervisor / Recon / Expert agents,
zero-hallucination, live NVD, no-availability-impact, GDPR/SOC2, LangChain
function-calling, Redis queue) against INTECTED's existing architecture, and
what was implemented.

## Verdict summary

| Spec element | Verdict | Status |
|---|---|---|
| Supervisor agent gating every command | GOOD — matches INTECTED's design | ✅ implemented (intected/supervisor.py) |
| Zero hallucination (only tool-log facts) | GOOD — already core (sha256 evidence) | ✅ already core + enforced |
| Live NVD CVE lookup (not LLM memory) | GOOD — feasible, real value | ✅ implemented (intected/cve.py) |
| No availability impact (rates, no DoS) | GOOD — enforceable | ✅ implemented (rate caps in tools.py) |
| PII protection (GDPR/SOC2 behavior) | GOOD — SELECT-version-proof, no extraction | ✅ implemented (intected/pii.py) |
| Function calling instead of raw bash | GOOD — but LangChain is NOT needed | ✅ implemented without LangChain |
| Redis/RabbitMQ queue | BAD for this project — overkill | ⚠️ documented (SQLite tasks instead) |
| "Full Kali arsenal exploitation" agent | PARTIALLY BAD — conflicts with operator approval + legal policy | ⚠️ gated, registry-only |

## The GOOD (and what was implemented)

### 1. Supervisor gate (Agent 1) — ✅ intected/supervisor.py
The spec's core insight is correct: no agent has unchecked power; every scan
passes one gate. INTECTED already enforced scope + operator approval at the
command level; this formalizes it at the TOOL-CALL level:
`validate_tool_call(tool, params, allowed_hosts, operator_approved)`.
Live-verified: full `-p-` scan without operator approval → BLOCKED; 5000 pps →
BLOCKED (cap 300); out-of-scope target → BLOCKED; single HTTP request →
approved. Brute-force/data-extraction tools (hydra, sqlmap --dump, …) are not
even in the registry — they cannot be invoked.

### 2. Zero hallucination — already core, now enforced harder
Facts exist only if a tool's log produced them (extractors + sha256 evidence,
"✓ verified on disk"). The new layer: the LLM can ONLY reference registered
tools with typed params — a raw bash string has no execution path
(intected/tools.py). If a tool's log does not state a finding, no fact exists.

### 3. Live NVD integration — ✅ intected/cve.py
`cpe_from_banner()` (honest, banner tokens only) → `lookup_cpe()` against the
NIST NVD API v2 with throttling (7s min interval, under the anonymous
5/30s limit) + in-memory cache. Live-verified: Apache httpd 2.4.7 →
cpe:2.3:a:apache:http_server:2.4.7 → 10 real CVEs from NVD. Network failure →
`nvd_unavailable` (LookupError) — never an invented CVE.

### 4. No availability impact — ✅ rate caps in tools.py
Every scanner is rate-bounded by the registry (nmap `--max-rate`, cap 300 pps;
ffuf `-rate 50`; nikto `-maxtime`; timeout on every subprocess). SYN-flood /
slowloris / hping3 tools are not in the registry. `-p-` requires explicit
operator approval.

### 5. PII guard — ✅ intected/pii.py
Email / phone / credit-card / SSN detection + redaction, applied at parse
time; the DB-proof rule is structural: no data-extraction tool exists in the
registry, so `SELECT version()` is the only data-plane action possible.

### 6. Function calling — implemented WITHOUT LangChain (and that's a good thing)
The spec's intent (no `os.system()` on raw model strings) is fully met: the
planner/reasoning engine produces structured tool references, the Supervisor
validates them, the registry executes predefined Python functions. LangChain
would add a dependency + abstraction layer over a working, tested loop — it
buys nothing here. The existing router → reasoning → gate → registry pipeline
IS the function-calling pattern.

## The BAD (honest — things in the spec that don't survive contact)

### 1. Redis/RabbitMQ queue — rejected
A single-user localhost tool on Windows doesn't need a broker. The spec's real
intent — long scans must not block the UI — is already met: scans run as
background processes (the engagement driver pattern) and the dashboard polls
every 3s. Phases are modeled as SQLite tasks (status pending → in_progress →
completed/blocked) — the queue INTECTED already has. Redis would add an
always-on service for zero benefit. **If** multi-user deployment is ever
needed, a broker becomes justified — that's the trigger, not today.

### 2. "Expert agent with the full Kali arsenal" — partially rejected
The spec says Agent 3 "executes targeted exploitation using the full Kali
Linux arsenal." Two problems: (a) it conflicts with the operator-approval
principle (Agent 1 validates, operator approves — INTECTED's model) and
(b) the user's own standing policy: only legal targets/labs, never
unauthorized ones. "Exploitation" stays operator-approved and registry-gated:
the tool catalogue is deliberately small and recon-grade; exploitation tools
(metasploit, sqlmap --dump) are banned by default and would need an explicit,
documented operator decision to ever be added.

### 3. GDPR/SOC2 "compliance" — scope honesty
The spec's BEHAVIORAL requirements (no PII extraction, no data tampering, no
availability impact) are implementable and now implemented. But claiming
"SOC2/GDPR compliance" for a local lab tool would be false: SOC2 is an audit
certification (controls, processes, evidence trail) — not a code feature.
What's honest to say: the tool enforces privacy-safe behavior. Certification
is a process question, not a code commit.

### 4. NVD matching is fuzzy — documented
Live lookup works, but NVD's cpeName search is a loose substring match: the
Apache 2.4.7 lookup returned 10 CVEs, some only loosely related (e.g. a
Ragnarok Online CVE). The client returns NVD's data verbatim (never
fabricated) — but the planner must present version-correlation results with
the "NVD loose-match" caveat, or filter by description/product terms. The
anti-hallucination rule is about NOT inventing; NVD's own fuzziness is a
separate, documented data-quality note.

## Implemented files

- intected/tools.py — tool registry (6 tools, typed params, rate caps,
  timeouts; the only execution path)
- intected/supervisor.py — Agent 1 gate (scope, rates, DoS, brute-force,
  operator approval)
- intected/cve.py — live NVD v2 client (throttled, cached, honest failures)
- intected/pii.py — PII detect/redact (parse-time, GDPR/SOC2 behavior)
- CLI: `intected run --mission N --tool X --target Y [--rate N] [--operator-approved]`
- tests/test_agents.py — 16 tests (registry, supervisor, CVE, PII)

Suite: 201 passed / 1 skipped.

---

## ADDENDUM REVIEW (sections 6–9: tool selection, stealth, dynamic updating)

| Spec element | Verdict | Status |
|---|---|---|
| Decision matrix (IF/THEN tool selection) | GOOD — deterministic, kills random tool choice | ✅ intected/matrix.py |
| Stealth safe-defaults enforced by Supervisor | GOOD — the single most important operational rule | ✅ tools.SAFE_DEFAULTS + _build_command |
| ToolVersionValidator (pre-flight --help) | GOOD — kills hallucinated flags | ✅ tools.probe_tool / `intected tools probe` |
| Real-time stdout capture (pexpect/subprocess) | GOOD — "the AI can't analyze unseen logs" | ✅ tools.execute_streaming |
| nuclei -ut template updates | GOOD — nuclei as web-CVE ground truth | ⚠️ command documented; run in the kali image as maintenance |
| WAF-bypass RAG (ChromaDB + LangChain + weekly scrape) | PARTIALLY BAD — same infra objection | ✅ local markdown KB + retrieval (`intected waf-kb`) |

### Notes on the addendum

- **Decision matrix**: implemented as strict IF/THEN on the footprint
  (web/network/API/GraphQL/WAF); WAF present → no nikto/wpscan/dirb defaults
  (passive probes instead); masscan is never suggested; metasploit stays
  operator-gated (never auto-suggested). Live on scanme: no WAF, auth surface
  present → `ffuf_content` (rate-limited, delay 1s, filter 403/404).
- **Stealth defaults now structural**: `_build_command()` injects
  `--max-rate 50 -T3 --data-length 32` (nmap), `-t 5 -p 1` + delay (ffuf),
  `-rl 10 -c 5` (nuclei) — the planner cannot omit them; tests assert them.
- **Version pre-flight**: `intected tools probe` runs `<tool> --version/--help`
  in the kali image and caches the parsed flags for the planner's context —
  real flags from THIS image, never memory.
- **Real-time capture**: `execute_streaming()` streams stdout line-by-line
  into `log_lines` — long scans feed progress/failures to the AI continuously.
- **RAG**: ChromaDB+LangChain rejected for the same reasons as before (a
  local single-user tool doesn't need a vector DB); the local KB delivers the
  same retrieval service (`intected waf-kb seed|query`) with zero
  dependencies. Weekly scraping stays an operator-run maintenance task — the
  KB is seeded and the retrieval path is tested.

Suite: 208 passed / 1 skipped.
