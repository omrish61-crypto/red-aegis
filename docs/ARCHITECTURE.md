# INTECTED — Architecture & Flow (full project)

The complete engine map, mechanism inventory, and logic of the PentestDROR
co-pilot. Every item below is implemented code (see the module path).

---

## 1. THE CORE LOGIC (three rules)

1. **Evidence-first** — a finding exists only if a tool's log produced it
   (extractors + sha256 evidence, "✓ verified on disk"). No log → no fact.
2. **Gate-everything** — no agent has unchecked power: scope (deny by
   default) → Supervisor (rate/DoS/tool whitelist) → operator approval
   (full scans, exploitation, write-back).
3. **The plan rule** — every finding leads to a test hypothesis; every test
   is based on a previous finding (Evidence Graph → ranked plan).

## 2. THE ENGINES (what exists)

| Engine | Module | Job |
|---|---|---|
| Scope engine | intected/scope.py | deny-by-default target checks; host-token extraction; aggressive markers; key=value bypass guard |
| Parsing engine | intected/parsing/ (extractors: nmap, nikto, ffuf, gobuster, burp, masscan, nuclei, sqlmap, zap) | tool output → structured facts + warnings; sha256 evidence; nikto 2.6.0 OSVDB support |
| Reasoning engine | intected/reasoning.py + router.py | LLM loop (deepseek-v4-flash via bridge): digest → plan/commands/facts JSON; temperature 0.0, anti-duplicate guard, FK-guarded task deps |
| Evidence engine | intected/evidence.py | fact store → per-target Evidence Graph (services, technologies+confidence, WAF, attack surface) + scoring (conf×impact×exploitability×exposure → P0-P3) |
| Plan engine | intected/planner.py | evidence-based branches (web_api/network) + ranked priorities; every item based_on fact ids |
| Decision matrix | intected/matrix.py | IF/THEN next-tool selection on the footprint (WAF-aware, no masscan) |
| Supervisor | intected/supervisor.py | Agent-1 gate: scope, rate caps (300 pps), DoS/brute bans, operator approval for -p- |
| Tool registry | intected/tools.py | 6 predefined functions (nmap_ports/services, http_headers, nikto, ffuf_content, nuclei); stealth safe-defaults (-T3, --max-rate 50, -rl 10); real-time streaming; ToolVersionValidator pre-flight |
| Recon executor | intected/recon.py | Phase-1 staged gradual recon (ports→services→headers→content), evidence-aware skips, per-stage timeouts |
| NVD client | intected/cve.py | live NIST NVD v2 lookups (banner→CPE 2.3, throttled, cached, honest failures) |
| PII guard | intected/pii.py | email/phone/cc/ssn detect + redact at parse time |
| WAF KB | intected/waf_kb.py | local markdown knowledge base + token-overlap retrieval |
| Secrets vault | intected/secrets.py | DPAPI-encrypted key store + `keys` CLI (masked, audited) |
| pentest-core bridge | intected/pentestcore.py | read-only reader (schema-validated, UNC fallback), idempotent sync, operator-certified write-back |
| Dashboard | intected/dashboard.py + static/ | FastAPI SPA: Process / Results / Mission (targets+assignments) / Plan; evidence modals; auth banner; 3s poll |
| Engagement driver | scripts/engagement_driver.py | automated multi-phase engagement (reasoning turns + whitelisted scans), G1/G4-verified |

## 3. THE FLOW (P0 → P5, with gates)

```
 P0  TARGET ENTRY          dashboard "Add target" → scope.validate_target
     │                      [target validation]
     ▼
 P1  RECON (Agent 2)       intected recon → ports → services → headers → content
     │                      [Supervisor gate each stage] [stealth flags structural]
     │                      [evidence-aware skips] [real-time logs]
     ▼
 P2  FINGERPRINT+PLAN      evidence graph → stack profile → ranked plan
     │                      [read-only composition] [NVD for versions in evidence]
     │                      [tools probe: real flags from kali]
     ▼
 P3  TARGETED TESTING      per priority: propose → [Supervisor] → [operator]
     │  (Agent 3 loop)      → execute_streaming → parse → facts → re-plan
     │
     ▼
 P4  VALIDATION            severity + scoring → [operator] pc write → prod DB
     │                      [PII redaction at parse] [evidence sha256]
     ▼
 P5  REPORT/RETEST         reports from real logs → same-engine retest →
                            control-agent audit vs ground truth
```

## 4. THE DATA MODEL

- **missions** (scope = allowed_hosts, auth_ref, authorizations)
- **tasks** (PTM tree: status pending/in_progress/completed/blocked, category,
  depends_on with FK guard)
- **facts** (tool, fact_type, value_json, confidence, evidence_ref, sha256)
- **commands** (proposed → approved/ran/rejected; the queue)
- **audit** (append-only timeline)
- **evidence/** raw files (mission-N/…, hash-verified)
- **secrets.vault** (DPAPI), **pentest.db** (production, via bridge)

## 5. THE GATES (what stops what)

| Gate | Enforced by | Blocks |
|---|---|---|
| Target validation | scope.validate_target | malformed/URL targets |
| Scope | supervisor (deny by default) | out-of-scope hosts |
| Rate/timing | tools._build_command | aggressive scans, DoS, IDS-triggering rates |
| Tool whitelist | tools.validate_params | unknown tools/params |
| Operator | CLI --operator-approved | -p-, exploitation, write-back |
| Evidence | extractors + sha256 | unsupported findings |
| PII | pii.redact | PII in stored facts |
| Anti-duplicate | reasoning loop | repeated command proposals |

## 6. KEY MECHANISMS (details)

- **No raw bash**: the LLM references registered tools + typed params; the
  registry builds argv (single source of truth); os.system on model text is
  impossible by construction.
- **Stealth by default**: nmap -T3 --max-rate 50 --data-length 32; ffuf
  -rate 50; nuclei -rl 10 -c 5; nikto -maxtime; all timeouts bounded.
- **Zero hallucination**: NVD queried live (never LLM memory); versions only
  from banners; failures loud (nvd_unavailable / tool timeout), never faked.
- **Gradual recon**: stages escalate only via evidence (a stage whose facts
  exist is skipped); rates never escalate without operator flag.
- **Operator-certified write-back**: the engine can never push to the
  production pentest DB.
- **Evidence graph → plan loop**: facts → graph → priorities → tests → new
  facts → re-rank (the dynamic engine).
