# INTECTED / PentestDROR — Build Diary

Process log for the INTECTED co-pilot build. Updated at every milestone. Gates are
recorded with evidence, per the project's control-agent workflow.

---

## 2026-08-10 — Session 1: Kickoff recon + G0 plan (PENDING APPROVAL)

**Activities:**
- Loaded `pentest-platform-planning` + `pentest-automation-build` skills (embedded
  requirements: real engines, no-simulation, approval gates, evidence-based reporting).
- Recon of existing ecosystem:
  - `~/.pentest-core` — production daemon **:9292 OPEN**; `pentest.db` = 32 runs,
    375 findings, 149 audit rows; recent runs against `35.206.100.20` (2026-08-10 19:28).
  - `~/ai-pentest-tools/PentestGPT` — legacy USENIX-2024-style fork + `pentestgpt_agent`
    Supervisor/Executor framework (kept as reference; not modified).
  - `~/ai-pentest-suite` — older dashboard+runner generation (reference only).
- **LLM stack live-measured** (bridge 127.0.0.1:11435/v1, 8-token completion):
  - `deepseek-v4-flash` → **0.9 s** ✔ interactive-capable
  - `llama3.2:latest` → **17.3 s** (async only)
  - `gemma3:4b` → **15.1 s** (async only)
  - `qwen2.5-coder:7b` → **25.7 s** (async only)
  - `deepseek-r1:8b` via bridge → **HTTP 400** ⚠ PITFALL: bridge routes `deepseek-*`
    to the cloud provider → name collision. Direct Ollama `127.0.0.1:11434` → **52.6 s**
    (works, thinking-model, background-only). **Fix: hard-coded direct route.**
- Ollama model inventory (direct :11434): qwen2.5:14b, deepseek-r1:8b, mistral:7b,
  nomic-embed-text, gemma3:4b, qwen3:8b, qwen2.5-coder:7b, llama3.2.

**Deliverables:**
- `README.md` (repo landing, model routing table).
- `docs/PENTESTDROR-PLAN.md` — full build plan (architecture, data model, phases
  P0–P4 with gates G0–G4, QA methodology, risks).

**Decisions pending (G0):** integration depth (A/B/C), dashboard stack, repo location,
start-P0 approval.

**Next:** await G0 gate → P0 (schema, router, CLI skeleton).

---

## 2026-08-10 — Session 1 (cont.): G0 approved (Track B) → P0 delivered → G1 evidence

**G0 decision (user):** Track B — full integration (INTECTED drives engines, writes
findings to pentest-core DB), FastAPI + vanilla JS SPA dashboard, repo
`C:\Users\onris\INTECTED`, start P0.

**P0 deliverables (all verified):**
- `pyproject.toml` (stdlib-only deps for P0; `intected` console script).
- `intected/config.py` — routing table with measured latencies; `deep_reasoning`
  hard-routed to **Ollama direct :11434** (bridge 400s on `deepseek-r1:8b`).
- `intected/db.py` — SQLite schema v1 (missions/tasks/task_deps/facts/commands/audit/
  schema_version), FK enforced, status CHECKs, audit logging.
- `intected/scope.py` — MissionScope: deny-by-default, CIDR + subdomain matching,
  strict-boolean `aggressive` gate (string "true" rejected), file-token exclusion
  (wordlists like `list.txt` no longer false-positive as hosts).
- `intected/router.py` — Router (route resolve + fallback chain), LocalJobQueue
  (async, 2 workers), `router_check()` live probe.
- `intected/cli.py` — `init` (scope+auth_ref), `status`, `task` (add/status),
  `paste` (evidence store w/ sha256, parser stub), `next` (P2 stub),
  `router-check`, `audit`.
- `tests/` — 26 canonical unittest cases.

**QA events (real, not green-trust):**
- First suite run FAILED 4 (2 errors + 2 failures) — all root-caused and fixed:
  1. `_normalize_host` stripped `/24` off CIDR allowed-entries → CIDR match broken.
     Fixed: network match runs on the RAW allowed token.
  2. `ffuf -w list.txt` — wordlist filename matched the hostname regex →
     false ScopeViolation. Fixed: FILE_EXTENSIONS exclusion set.
  3. JobQueue test race (worker beat the first poll) → tolerant intermediate state.
  4. Contradictory test assertion (aggressive=True expected to raise AND pass) →
     removed.
- Final: **26/26 tests OK**.
- CLI smoke (real run): mission created (`ENG-LAB`, hosts 10.0.0.5+dvwa.local,
  auth_ref AUTH-2026-001) → task added → completed → audit shows 3 events. DB at
  `~/.intected/intected.db`.

**G1 evidence — live router probe (all 6 routes):**
| task class | model | ok | latency |
|---|---|---|---|
| reasoning | deepseek-v4-flash | ✔ | 1.6s |
| light | llama3.2:latest | ✔ | 30.6s |
| extract_small | gemma3:4b | ✔ | 33.3s |
| code | qwen2.5-coder:7b | ✔ | 30.7s |
| deep_reasoning | deepseek-r1:8b (direct :11434) | ✔ | 60.2s |
| embeddings | nomic-embed-text | ✔ | 22.7s |

Local models slower than the morning benchmark (30–60s vs 15–53s) — CPU contention;
confirms async-only routing for local models.

**Gate status: G1 met (evidence above). Awaiting user go/no-go for P1 (parsing module).**

---

## 2026-08-10 — Session 1 (cont.): G1 approved → P1 delivered → G2 evidence

**G1 decision (user):** proceed to P1 (parsing module).

**P1 deliverables (all verified):**
- `intected/parsing/__init__.py` — extractor registry (eager imports — no lazy
  try/except swallowing), `parse_tool_output()` (raw file → DB facts, ALWAYS with
  evidence_ref + sha256), `store_evidence()`/`verify_evidence()` (verbatim + hash).
- `intected/parsing/extractors/` — nmap (XML + text), gobuster (dir + error lines),
  ffuf (JSON lines), nuclei (JSONL), sqlmap (injectable/dbms/tech/negative),
  zap (baseline PASS/WARN/FAIL), burp (sitemap XML), nikto.
- CLI `paste` upgraded: store evidence → parse → facts → audit.
- `tests/fixtures/` — 9 REAL lab captures (provenance in fixtures/README.md),
  incl. a FRESH `nmap -sV` scan of the live lab (2026-08-10): Juice Shop :3000,
  Apache httpd 2.4.25 :8001, Apache Tomcat 10.1.36 :8080.
- `tests/test_parsing.py` — 26 tests: real-fixture assertions, format-sample
  conformance (ffuf/burp/nikto — no lab capture exists), fault injection (empty,
  malformed XML, binary garbage, 1MB line, garbage JSONL), evidence store
  verbatim+verify, pipeline enforcement.

**QA events (real, not green-trust):**
- First P1 suite run FAILED 6 — root causes fixed:
  1. Pipeline tests wrote fixtures into a FILE path (NamedTemporaryFile) → temp dir.
  2. `_normalize_host`-style bug was P0; here: sqlmap DBMS regex missed
     "the back-end DBMS is MySQL" (space) + "back-end DBMS: MySQL >= 5.1" form.
  3. NSE script notes: fixture's clamav-exec script FAILED (no vuln markers) —
     extractor now records ANY script output as a fact (failed-script is a fact).
  4. ffuf FUZZ-substitution test expectation (concrete URL, not redirect).
- Final: **52/52 tests OK** (26 P0 + 26 P1).
- **G2 extraction-rate report (live run, 8 real fixtures):** 8/8 meet expected
  minimums; 98 facts extracted vs 24 expected minimum; nuclei fixture honestly = 1
  record (single 29KB finding, verified) — 100% record extraction.
- **Structural check:** `parse_tool_output` writes facts only with evidence_ref +
  sha256; live query on mission 1 after CLI paste: 8 facts, **0 without evidence**.
- CLI E2E: `intected paste` on the fresh nmap fixture → 8 facts in live DB
  (ports 3000/8001/8080; Apache httpd 2.4.25; Tomcat 10.1.36), evidence raw file
  stored verbatim + sha256 verified.

**Gate status: G2 met (≥95% extraction on 5+ real outputs ✔; zero facts without
evidence ✔). Awaiting user go/no-go for P2 (reasoning module).**

---

## 2026-08-10 — Session 1 (cont.): G2 approved → P2 delivered → G3 evidence

**G2 decision (user):** proceed to P2 (reasoning module).

**P2 deliverables (all verified):**
- `intected/ptm.py` — PTM ops: propose/complete/fail/block, unmet-deps gate,
  `next_objective` deterministic fallback, `duplicate_command` anti-loop,
  `task_tree` nesting, `compact_facts` (priority: cve > param > port > version >
  service > path > note; capped + deduped).
- `intected/reasoning.py` — ReasoningEngine: `build_digest` (compact mission
  state: scope + task tree + compacted facts + recent commands), `next_step`
  (flash → STRICT-JSON plan → apply task updates → scope-validate command →
  persist), `parse_plan_json` (fence-tolerant, salvage fallback), **one
  corrective retry** when the model emits prose instead of JSON.
- Command gate chain (order matters): completion guard → unknown-task_id guard
  (hallucination-safe, FK-safe) → duplicate guard → MissionScope check
  (destructive markers need `aggressive is True` strictly) → persist as
  `proposed`.
- CLI: `next --mission N [--input ...]`, `digest --mission N`.
- `tests/test_reasoning.py` — 26 tests (78 total suite): parse, compaction,
  PTM ops, engine gates, retry recovery, router-failure path.

**QA events (real, not green-trust):**
- First run FAILED 3: `propose_task` lacked `parent_id`; `compact_facts` got
  sqlite3.Row (value_json string) not dicts; digest lost row id/tool metadata.
- **Live-run bug found**: first live `next` CRASHED inside `add_command` — the
  model invented a `task_id` (FK violation). Fixed with the unknown-task_id
  rejection guard + regression test.
- **Live model-behavior found**: flash sometimes replies with prose instead of
  JSON — graceful failure path proved (no crash, raw reply surfaced); added
  corrective retry; retry-recovery unit test.
- Final: **78/78 tests OK** (26 P0 + 26 P1 + 26 P2).

**G3 evidence — live end-to-end on the real mission (deepseek-v4-flash, real
facts from P1):**
- Objective: "Enumerate HTTP service on dvwa.local:8001" (cites Apache 2.4.25
  nmap fact in analysis).
- PTM: task 2 created → in_progress (audit: task.create, task.status).
- Command APPROVED: `curl -sS -iL -m 10 http://dvwa.local:8001/` — in-scope,
  with rationale; open question asked back to the tester (co-pilot behavior).
- Malformed model update (`status: None`) gracefully skipped + audited.
- Scope gates exercised live + unit-tested: out-of-scope rejected, duplicate
  rejected, completed-task rejected, hallucinated task_id rejected, destructive
  `aggressive:"true"` string rejected.

**Gate status: G3 met (E2E dry run on localhost lab ✔; 0 scope violations ✔; 0
destructive commands ungated ✔). Awaiting user go/no-go for P3 (dashboard).**

---

## 2026-08-10 — Session 1 (cont.): G3 approved → P3 delivered → G4a evidence

**G3 decision (user):** proceed to P3 (professional dashboard).

**P3 deliverables (all verified):**
- `intected/dashboard.py` — FastAPI app: mission list, mission bundle
  (tasks/facts/commands/audit/stats), evidence endpoint (raw text + sha256 +
  **on-disk hash verification**), SPA static serving. Auth: bearer token
  (?token= or X-INTECTED-Token header, constant-time compare) + Origin
  allowlist. Localhost-only.
- `intected/static/` — dark professional SPA (`#0b0f14` theme, accent teal):
  **Process** view (nested status-colored task tree, command queue, audit
  timeline), **Results** view (facts table + evidence modal with hash
  verification), **Mission** view (scope chips, auth_ref, stat cards). Polls
  every 3s. No build step.
- CLI: `intected dashboard --port 8765` (token auto-created at
  `~/.intected/dashboard.token`).
- deps: fastapi + uvicorn (+httpx for tests) via `uv sync --extra test`.
- `tests/test_dashboard.py` — 12 tests (90 total suite): bundle structure,
  auth (wrong token/bad origin/header), 404s, evidence content + hash match +
  **tamper detection**, SPA serving.

**QA events (real, not green-trust):**
- First run FAILED 1 + hung once: evidence test reused the DB-file path as a
  dir (temp-file-vs-dir trap again — fixed with a real temp dir); a fact with a
  FAKE sha256 vs real file correctly reported mismatch → test fixed to store
  the REAL hash; added a tamper test (corrupt file → `matches: false`).
- Final: **90/90 tests OK** (26 P0 + 26 P1 + 26 P2 + 12 P3).

**G4a evidence — LIVE browser verification (real server, real mission data):**
- Server: `intected dashboard` on 127.0.0.1:8765 (background).
- API: missions ✓, mission-1 bundle ✓ (stats: 8 facts, 2 tasks, 2 commands),
  evidence fact 5 `matches: True` (sha 67723036…) ✓; wrong/no token → 401 ✓.
- Browser (real page): conn pill **"connected"**, task tree 2 nodes
  (completed + in_progress), command queue 2 rows, audit timeline 12 items,
  dark theme bg `rgb(11,15,20)`.
- Results tab: 8 fact rows; evidence modal for fact #8 → sha256 +
  **"✓ verified on disk"** + 4210 raw bytes.
- Mission tab: name ENG-LAB, auth_ref AUTH-2026-001, scope chips
  (10.0.0.5, dvwa.local), stat cards (1 completed / 1 in progress / 8 facts).

**Gate status: G4a met (dashboard live against a real test mission ✔). Awaiting
user go/no-go for P4 (pentest-core integration + hardening + acceptance
scorecard).**

---

## 2026-08-10 — Session 1 (close): user decision — stop, commit, P4 later

**User decision:** stop here; commit everything; continue P4 in a later session.

**Session totals:** P0–P3 delivered and verified · **90/90 canonical tests** ·
6/6 LLM routes live · 9 real lab fixtures · live E2E reasoning on flash · live
browser-verified dashboard · ~20 real QA issues found & fixed (bugs in our code,
model behavior, test traps — all root-caused, never papered over).

**Left running:** dashboard server on 127.0.0.1:8765 (background; token in
`~/.intected/dashboard.token`). Stop: kill the `intected dashboard` process.

**Next session (P4):**
1. pentest-core integration — read runs/findings from `~/.pentest-core/pentest.db`
   (32 runs / 375 findings schema), optional findings write-back; engines via
   pentest-core patterns (nuclei/ZAP via Docker; native nmap/sqlmap).
2. Hardening — scope/auth audit pass, CLI polish.
3. Acceptance — readiness scorecard per plan §2 (G1–G5, quantified).
