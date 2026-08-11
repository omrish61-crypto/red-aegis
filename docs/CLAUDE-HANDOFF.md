# RedAegis — Full Project Handoff Report

**Prepared for:** Claude (successor AI)  
**Date:** 2026-08-11 10:00 UTC+3  
**Repo:** https://github.com/omrish61-crypto/red-aegis  
**Commit:** 8d81e20 · **Tests:** 266 passed, 1 skipped, 19 subtests · **Scorecard:** 90.5%

---

## 1. WHAT THIS PROJECT IS

RedAegis (formerly INTECTED / PentestDROR) is an AI penetration-testing co-pilot with a 4-stage agentic pipeline. The PIVOT direction (per VP of Product memo, this session) is to become a **Tier-1 SMB product**: not a researcher tool, but a "self-serve security compliance app" that produces plain-English reports a business owner can hand to their insurance broker.

**Target audience:** Small-to-medium businesses (dental offices, law firms, accounting firms) managed by MSPs.

---

## 2. PROJECT LOCATIONS

| What | Path |
|---|---|
| Source code | `C:\Users\onris\INTECTED` (Windows 11, git-bash/MSYS shell) |
| DB (production) | `C:\Users\onris\.intected\intected.db` |
| Evidence files | `C:\Users\onris\.intected\evidence\mission-{id}\*.raw` |
| Dashboard token | `C:\Users\onris\.intected\dashboard.token` |
| Hermes config | `C:\Users\onris\AppData\Local\hermes\` |
| Hermes scripts | `C:\Users\onris\AppData\Local\hermes\scripts\` |
| LLM bridge | `http://127.0.0.1:11435/v1` (LiteLLM: deepseek-v4-flash) |
| Ollama (fallback) | `http://127.0.0.1:11434` (llama3.2, gemma3:4b — CPU-only, slow) |
| Kali WSL2 | `wsl -d kali-linux -u root -e bash -lc "..."` |
| Kali tools root | `/usr/bin/` (1390 binaries, 33 verified) |
| Nuclei templates | `/root/.local/nuclei-templates/` (30 dirs, v3.11.1 official binary) |
| Wordlists | `/usr/share/dirb/wordlists/common.txt` + `/usr/share/seclists/` (6184 files, 1.9GB) |

---

## 3. ARCHITECTURE — 21+ CORE MODULES

```
intected/
  __init__.py          version string
  config.py            BRIDGE_URL, state_dir(), tool defaults
  db.py                SQLite schema, migrations (v1→v2→v3), CRUD
  scope.py             scope validation + check_command (deny-by-default)
  supervisor.py        validate_tool_call gate
  tools.py             Tool registry (26 tools), execute_streaming, execute_raw,
                       _stream_with_timeout (reader-thread, hard deadline)
  recon.py             Staged recon executor (5 stages, evidence-aware skips)
  evidence.py          EvidenceGraph (per-target v3), stack_profile
  planner.py           Attack-Plan Engine (decision-tree, scoring)
  matrix.py            Decision matrix (WAF-aware, footprint→tool)
  grading.py           SMB Security Grade Engine (A-F, 41+ patterns, header checks)
  summary.py           Plain-English LLM summary (bridge :11435)
  checklist.py         Fix-It Checklist (19+ remediation templates)
  cve.py               Live NVD CVE client (CPE 2.3 → NIST API v2)
  pii.py               PII guard (email/phone/credit-card/SSN regex)
  waf_kb.py            WAF-bypass knowledge base (local retrieval)
  reasoning.py         LLM reasoning router
  router.py            Task routing logic
  arsenal.py           Attack payload definitions
  pentestcore.py       Pentest-core write-back bridge
  ptm.py               Process threat modeling
  secrets.py           Secure key store (DPAPI on Windows)

  parsing/
    __init__.py        parse_tool_output + verify_evidence (sha256)
    extractors/        nmap, nikto, ffuf, gobuster, nuclei, sqlmap, masscan, burp, zap, common

  static/              Dashboard SPA (vanilla JS, no framework)
    index.html         5 tabs: Process, Results, Mission, Plan, Report
    app.js             fetch-based, auth via ?token=, delegated click handlers
    styles.css         dark theme, responsive

  cli.py               CLI commands: init, recon, run, report, plan, evidence, tools, keys...

  dashboard.py         FastAPI app on :8765, token-gated, closure-style endpoints
    GET  /api/missions                            mission list
    GET  /api/missions/{id}                       mission bundle (tasks/facts/commands/audit)
    GET  /api/missions/{id}/plan                  evidence graph + ranked plan
    POST /api/missions/{id}/plan/{rank}/run       run ONE plan priority
    GET  /api/missions/{id}/evidence/{fid}        raw evidence + sha256 verification
    POST /api/commands/{id}/run                   run ONE queue command
    POST /api/missions/{id}/commands/run-all      run ALL proposed commands
    GET  /api/missions/{id}/report                SMB branded HTML report
```

---

## 4. DATABASE SCHEMA (intected.db)

### Tables
- **missions** (id, name, allowed_hosts_json, authorizations_json, created_at)
- **facts** (id, mission_id, task_id, target, tool, fact_type, value_json, confidence, evidence_ref, sha256, created_at)
  - fact_type: port, service, version, path, param, cve, credential, note
  - **target column (v3):** per-target evidence scoping — default '' for backward compat
- **commands** (id, mission_id, task_id, tool, cmd, rationale, state, exit_code, output_ref, created_at)
  - state: proposed, approved, ran, rejected
- **tasks** (id, mission_id, category, description, status, created_at)
- **audit** (id, ts, source, action, detail)

### State summary (as of handoff)
- Missions: 4 (currently using #8 LAB-REALTEST, scope: [127.0.0.1, 10.100.102.1])
- Facts: 100+ (47 scoped to 127.0.0.1, rest to 10.100.102.1)
- Commands: 36 (3 proposed, 11 ran, 23 rejected/cleaned)
- Tasks: 29
- Evidence: 46+ files on disk, 100% sha256 verified
- Audit: 300+ entries

---

## 5. WHAT HAS BEEN BUILT & VERIFIED

### Multi-Agent Pipeline (4 stages — ALL implemented)
1. **Recon (Passive/OSINT):** recon.py staged scanning (ports→services→headers→content→vuln), supervisor-gated, evidence-aware skips, WSL kali execution
2. **Environment & WAF Analysis:** EvidenceGraph (WAF detection, services/technologies), waf_kb.py (bypass knowledge), matrix.py (honeypot-aware decision)
3. **Dynamic Tool Selection:** planner.py (Attack-Plan Engine, scoring model), matrix.py (IF/THEN from footprint), reasoning.py (LLM routing)
4. **Attack Execution & Validation:** tools.py (26-tool registry, stdlib-only, no raw bash), supervisor.py (deny-by-default, rate caps), evidence.py (sha256 chains)

### SMB Prototype (30-day milestone — ALL deliverables shipped)
| # | Feature | Status |
|---|---|---|
| 1 | Security Grade Engine (A-F) | ✅ 41 version patterns, 6 header checks, raw-fact scanning |
| 2 | Plain-English Summary (LLM) | ✅ Bridge :11435, context-aware fallback |
| 3 | Fix-It Checklist | ✅ 19 remediation templates, deduped, prioritized |
| 4 | Branded HTML Report | ✅ Single-page, print-to-PDF, grade/risk/checklist |
| 5 | Dashboard Report Tab | ✅ Grade preview + "Generate Full Report" button |
| 6 | Auto-Recon Cron (6h) | ✅ Script-only (auto-recon.py), dual-target, QA smoke tests |
| 7 | CLI report command | ✅ `intected report --mission 8` |

### Agent Team (7 professional skills created)
| Agent | Skill Name | Category |
|---|---|---|
| VP Product | `product-integration-lead` | business |
| CTO | `cto-security-architect` | software-development |
| VP QA | `qa-verification-lead` | software-development |
| Professional Services | `ops-infra-support` | devops |
| Alex "Viper" Mercer | `offensive-security-specialist` | security |
| Marcus Vance | `systems-debugging-specialist` | devops |
| Elena Rostova | `kali-core-developer` | devops |

Skills are stored in `C:\Users\onris\AppData\Local\hermes\skills\`.

### Kali Tools (33 verified)
Pipeline tools (registry): nmap_ports, nmap_services, http_headers, nikto, ffuf_content, nuclei — all execute_streaming-compatible.

Dashboard-tested: nmap, curl, nikto, ffuf, whatweb, wafw00f, gobuster, dig, sqlmap.

Direct: john (cracked bcrypt), hashcat (1880 MH/s), msfconsole, masscan, searchsploit, tcpdump, nuclei (v3.11.1, fixed from broken 3.8.0).

New this session: cewl, snmpwalk, dnsenum, fierce, dmitry, davtest, SecLists (6184 wordlists).

---

## 6. HOW TO RUN

### Dashboard (must be running for everything web-based)
```bash
cd C:\Users\onris\INTECTED
uv run intected dashboard --port 8765
# Token: C:\Users\onris\.intected\dashboard.token
# URL: http://127.0.0.1:8765/?token=<token>
```

### Recon against a target
```bash
cd C:\Users\onris\INTECTED
uv run intected recon --mission 8 --target 127.0.0.1 --operator-approved
uv run intected recon --mission 8 --target 10.100.102.1 --operator-approved
```

### Report
```bash
uv run intected report --mission 8
# Or via dashboard: http://127.0.0.1:8765/api/missions/8/report?token=<token>
```

### Full test suite
```bash
cd C:\Users\onris\INTECTED
uv run pytest -q          # Full suite (WARNING: may hang foreground)  
uv run pytest -q --timeout=30  # With timeout
```

### Environment verification
```bash
uv run pytest tests/test_report.py -q   # Report tests (10 tests, fast)
uv run pytest tests/test_grading.py -q  # Grading tests (32 tests, fast)
```

---

## 7. KNOWN ISSUES & QUIRKS

### Path Handling (CRITICAL)
- **MSYS paths (/c/...) do NOT work in Python subprocess on Windows.** Use `C:/...` for bash arguments and `C:\...` (raw string) for Python cwd.
- **search_files with MSYS paths breaks ripgrep** — use `C:/Users/...` instead.
- **Cron jobs** pass paths through bash which eats Windows backslashes — the auto-recon fix used a Python wrapper with `C:/Users/...` paths.

### Test Suite
- **Foreground pytest hangs** occasionally (240-600s timeout). The background run consistently completes in ~12-20s. Root cause: WSL subprocess calls in `test_agents.py` (real nmap execution). Run with `--timeout=30` or use background mode.
- Suite is 266 passed + 1 skipped (test_secrets POSIX perms — expected Windows skip).

### Kali/WSL
- **Nuclei:** v3.11.1 official binary (replaced broken kali 3.8.0). Must run with stdin closed (`< /dev/null` or `stdin=subprocess.DEVNULL`). Does NOT use `-duc` (breaks template index).
- **systemd:** WSL does not support systemd fully. Ignore "Failed to start systemd" warnings.
- **IPv6:** Blackholed in WSL NAT → ip6tables REJECT for fast-fail.
- **Wordlist:** `/usr/share/dirb/wordlists/common.txt` — NOT `/usr/share/wordlists/dirb/`.

### Grading Engine
- **Exchange/OWA false positive FIXED** (added `\b` word boundary to `(?i)\bowa\b` — no longer matches "OWASP").
- **CORS detection FIXED** — now scans path facts in addition to notes.
- **Zero-data targets FIXED** — show "NO DATA" instead of A/100 with fabricated positives.

### Dashboard
- **Single-threaded:** FastAPI with one uvicorn worker — blocking operations (sqlmap 150s) freeze the UI. Fixed by using script-only cron (no LLM blocking).
- **Run-all endpoint:** sequential execution, each command up to 600s timeout.

### Auto-Recon Cron
- **Job ID:** e91ff3a54b13, schedule: every 360m, script: auto-recon.py (Python wrapper)
- The wrapper at `C:\Users\onris\AppData\Local\hermes\scripts\auto-recon.py` calls `C:\Users\onris\INTECTED\scripts\auto-recon.sh`
- Status: **wrapper working** (recon runs confirmed), but **gateway down** so auto-fire won't work. Run: `hermes gateway install` to enable.

---

## 8. WHAT REMAINS TO DO (Priority Ordered)

### P0 — Fixes
1. **Gateway up:** `hermes gateway install` so cron fires automatically
2. **Cron path hardened:** the auto-recon.sh uses `bash C:/Users/...` which works from Python subprocess but sometimes fails — document or wrap completely in Python

### P1 — Next Features
3. **MSP multi-tenant:** client drop-down in dashboard (basic username/password, no SAML)
4. **Cyber insurance questionnaire auto-fill:** LLM reads facts → answers carrier form questions
5. **Target selector in Plan tab:** user picks which scope host to plan for (currently shows _default_target only)
6. **Background plan-run:** make plan-run non-blocking (poll for result, don't freeze UI)

### P2 — Packaging
7. **Docker Compose deploy:** single `docker-compose up` with FastAPI + bridge + Kali tools — no WSL dependency
8. **White-label PDF:** MSP can drop their logo on the report header

### P3 — Hardening
9. **UPnP version false positive:** `1.x` pattern matches UPnP SDK 1.14.17 — refine regex to exclude benign embedded SDKs
10. **Header check robustness:** the header-based deductions fire only when SOME headers are present — fine for now, but may miss targets with zero headers at all
11. **WordPress version in notes vs technologies:** current code scans both, but the test assertions may need updating if note facts change format

---

## 9. COMMAND QUICK REFERENCE

```bash
# Project
cd C:\Users\onris\INTECTED
source .venv/bin/activate  # or use uv run

# Test
uv run pytest -q
uv run pytest tests/test_report.py::GradeTest::test_grade_A -v

# Dashboard
uv run intected dashboard --port 8765 &
TOK=$(cat ~/.intected/dashboard.token)
curl "http://127.0.0.1:8765/api/missions?token=$TOK"

# Recon
uv run intected recon --mission 8 --target 127.0.0.1 --operator-approved

# Report
uv run intected report --mission 8
curl "http://127.0.0.1:8765/api/missions/8/report?token=$TOK"

# Kali
wsl -d kali-linux -u root -e bash -lc "nuclei -version"
wsl -d kali-linux -u root -e bash -lc "apt list --installed | head"

# Git
git log --oneline -5
git push origin main

# Hermes
hermes gateway install     # start gateway for cron
hermes tools enable        # if tools are missing after reboot
```

---

## 10. SESSION LOG (2026-08-11 — this session)

1. **Per-target evidence scoping (v3):** added `target` column to facts, backfilled mission 8 as 127.0.0.1, added scope dual-host (127.0.0.1 + 10.100.102.1)
2. **Plan tab Run buttons:** per-priority Run + run-all, supervisor-gated, evidence-persisted
3. **Full kali tool verification:** 10 dashboard-driven tests + 26 direct tools
4. **SMB pivot:** grading engine (A-F), plain-English summary, fix-it checklist, branded HTML report, dashboard Report tab
5. **Auto-recon cron:** 6h script-only cron (auto-recon.py wrapper)
6. **7-agent skills:** CTO, VP QA, Professional Services, Offensive Security, Systems Debugging, Core Kali Dev, VP Product
7. **CTO+Alex fixes:** Exchange/OWA false positive (word boundary), CORS path-facts, zero-data targets, _persist_run arg fix, nmap arg splitting
8. **Kali expansion:** +7 tools (cewl, snmpwalk, dnsenum, fierce, dmitry, davtest, SecLists) — 33 total, 6184 wordlists
9. **6-agent parallel dispatch validated** — 4.5 minutes, zero deadlocks, cross-layer handoff proven
10. **Sleep disabled** via powercfg

---

**Handoff complete.** The project is in a clean, committed, push-verified state. Suite is green. Both targets have evidence. The pipeline works end-to-end. Good luck.
