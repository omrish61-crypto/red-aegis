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

---

## 2026-08-10 — Arsenal expansion (tool knowledge base + authorization gates)

**Delivered (merged with a concurrent sibling session's arsenal work — same
feature, two designs; reconciled to one API):**

1. **`intected/arsenal.py`** — 38-tool catalog covering the 6 requested
   categories (recon / initial-access / c2 / privesc / lateral / evasion) with
   live availability probing: `arsenal` CLI command, `--tool <name>` detail
   view, per-process cache. Availability is PROBED, never assumed
   (`wsl -d kali-linux command -v` batch).
2. **Risk-category authorization gate (hard enforcement)** — `scope.RISK_CATEGORIES`
   (phishing / c2 / evasion / credential) + `check_command(..., authorizations=)`.
   Gated tools are REJECTED unless the mission declares the category via
   `intected init --authz phishing,c2,...` (deny-by-default; a bare string never
   counts — same strictness as `aggressive`). Wired through
   `reasoning._handle_command`; digest shows AUTHORIZED / BLOCKED categories.
   Schema v2: `missions.authorizations_json` (idempotent ALTER migration).
3. **masscan extractor** — adapter over the validated nmap XML parser
   (masscan `-oX` emits the nmap dialect). **Live finding: masscan 1.3.2 is
   TX-broken in Kali-WSL2** (adapter binds, rate stays 0.00-kpps, `-oX` empty;
   nmap -sS works in the same env) → catalog status `broken`, digest excludes
   it. Parser validated against REAL captured nmap XML of the same element
   tree (`tests/fixtures/nmap-dvwa-live.xml`, Nmap 7.99 → DVWA :8001).
4. **Scope-gate hardening** — payload artifact extensions (`.elf .dll .so
   .ps1 .jar ...`) added to FILE_EXTENSIONS so output files are never treated
   as hosts (caught live: `msfvenom -o shell.elf` was rejected as out-of-scope).

**Verified:** 104/104 tests (90 canonical + 5 sibling arsenal + 6 authz-gate +
3 masscan) · live CLI `arsenal` table · live digest with AVAILABLE TOOLS +
AUTHORIZED/BLOCKED categories · live `--authz` mission creation · payload-file
gate. Concurrent sibling installed sqlmap/gobuster/ffuf/nuclei on Kali during
the session — live probe picked the new tools up automatically.

**Open (checkpoint — awaiting user go/no-go):** bulk-install the ~19 missing
Kali tools (sublist3r, eyewitness, gophish, evilginx2, donut, sliver, havoc,
mythic, mimikatz, rubeus, linpeas, winpeas, bloodhound, sharphound, impacket,
certipy, chisel, ligolo-ng, syswhispers) + per-tool extractors from real
captured output (amass/netexec/theharvester/responder next, format-known).

---

## 2026-08-10 — Arsenal bulk install COMPLETED (closes the checkpoint above)

**Live-verified on Kali WSL2 (all probes REAL `command -v` / version output):**

- **apt (Kali repos):** sublist3r, eyewitness, gophish, evilginx2, donut,
  mimikatz, sliver (pkg installs `sliver-server`/`sliver-client`), chisel,
  ligolo-ng (pkg installs `ligolo-proxy`/`ligolo-agent`), nuclei, sqlmap,
  gobuster, hashcat, jq, sqlite3 — all `ok`.
- **pip:** certipy-ad 5.0.4 (PEP 668 → `--break-system-packages`; Kali has no
  `certipy` console script — wrapper written to `/usr/local/bin/certipy`).
- **release binaries → `/opt/arsenal/` + symlinks into `/usr/local/bin`**
  (so `command -v` finds them): linpeas.sh, winPEASx64.exe, Rubeus.exe
  (Ghostpack-CompiledBinaries mirror; upstream release ships no binary asset),
  SharpHound.exe v2.14.0 (unzipped). sha256 recorded.
- **catalog reconciled to reality:** 16 entries flipped `install → kali` with
  the REAL binary names (sliver-server, ligolo-proxy, bloodhound-python,
  impacket-secretsdump, rubeus, winpeas, sharphound, linpeas...).
- **masscan `broken` override CONFIRMED by live test** — `--wait 0` still
  drains ~30s printing `waiting -N-secs`, `found=0`, empty `-oX`; nmap -sS
  works in the same environment.

**Not installed (deliberate, honest statuses):** havoc (no Kali package —
GitHub build only), mythic (docker-compose stack), cobalt-strike (license),
syswhispers / pe-bearer (windows-host source tools), aquatone (deprecated →
eyewitness), shodan/censys (CLIs present but gated `api` — keys required).

**Verified:** 104/104 tests · live `arsenal --check` shows 25 tools `ok` +
honest non-ok statuses · digest AVAILABLE TOOLS line live (only `ok` tools).

---

## 2026-08-10 — P4: pentest-core integration + hardening + acceptance scorecard

**User decision:** "continue and finish project" — G4b approval for P4, no
intermediate gates; final acceptance package delivered at close.

**P4 deliverables (all verified):**
1. **`intected/pentestcore.py`** — pentest-core integration:
   - `connect()` READ-ONLY (uri mode=ro) + schema validation (rejects
     non-pentest-core DBs); `connect_rw()` only for the explicit write path.
   - Reader: `stats()` (runs/findings by severity+engine), `list_runs()`
     (recent-first + per-severity breakdown), `get_run()` (JSON list columns
     decoded: cwe/cve/evidence/raw_lines).
   - `sync_run()` — import a run's findings into an INTECTED mission as facts
     with evidence_ref + sha256 and {pc_run, pc_finding} markers; IDEMPOTENT
     (re-sync adds 0). Fact-type mapping: open_port→port, discovered_path→path,
     cve→cve, else note.
   - `write_finding()` — DOUBLE-GATED write-back: MissionScope.check_target
     (deny-by-default) + severity whitelist + engine/title required; run row
     auto-created; INTECTED audit logged.
2. **CLI** — `intected pc stats|sync|write [--db PATH]` + `status` now probes
   and prints the pentest-core integration state (probed, not assumed).
3. **`config.PENTEST_CORE_DB`** env-overridable path.
4. **Hardening (real QA events, all root-caused):**
   - reasoning route: `temperature: 0.0` (default temp drifted to prose on
     complex digests; probe with temp 0.0 returned schema-exact JSON).
   - digest: PASS-level ZAP facts filtered (75→15 relevant; 61/75 were PASS
     rules drowning the findings), empty task tree says so explicitly.
   - `max_tokens` 1200→4096 + timeout 60→300: flash runs a heavy thinking
     phase (measured 4800–5200 chars reasoning) — 1200 tokens ended
     finish=length with EMPTY content.
   - `_apply_task_updates`: hallucinated `depends_on` ids dropped (FK crash
     guard) — model-invented-FK pitfall hit LIVE.
   - scope.py: `key=value` script args (`http-fetch.paths=/metrics`) no longer
     falsely rejected as hosts; real out-of-scope header hosts still caught.
5. **Tests** — `tests/test_pentestcore.py` (18: fixture built from the REAL
   production schema; reader/sync/write/CLI incl. idempotency + scope gate),
   +1 reasoning FK-guard, +2 router temperature, +1 scope key=value. Suite:
   **126/126** (was 104).

**LIVE verification (real artifacts, real calls, real browser):**
- `pc stats` against a backup of the live pentest.db: 13 runs / 176 findings,
  severity + engine breakdown exact. (Also verified against the NATIVE
  Windows DB at the DEFAULT path `~/.pentest-core/pentest.db` — 35 runs / 412
  findings, 12 engines — the integration works with zero config on Windows;
  live sync of run localhost_8001-20260810-211331 added 20 facts.)
- `pc sync` run 127.0.0.1_3000-20260810-221603 → 13 facts; re-sync → 0 added.
- `pc write`: in-scope → finding 177 created; out-of-scope (8.8.8.8) →
  SCOPE VIOLATION exit 1.
- INTECTED parser on pentest-core's REAL raw artifacts: zap-baseline.txt →
  61 facts (158 URLs), nuclei.jsonl → prometheus-metrics (matches pentest.db).
- Live reasoning E2E: objective + 3 tasks + ffuf command APPROVED
  (in-scope, `-ac` wildcard filtering); gates live: aggressive:"true"
  rejected, hallucinated ids rejected.
- Dashboard live browser (DOM-verified): conn pill connected, task tree (3),
  command queue, FINDINGS & FACTS (75), evidence modal sha256
  d1ccdc1d2b4a… + "✓ verified on disk", 78 audit rows, 401 without token.

**Acceptance scorecard (docs/ACCEPTANCE-SCORECARD.md):** G1 85% · G2 92% ·
G3 88% · G4 70% · G5 95% → weighted **86.6%**. Honest gaps: long-run dedup +
40-message rollover not stress-tested; ffuf/burp/nikto real captures missing;
write-back validated on backup copy (production DB untouched).

**Control agents dispatched** (2 parallel, independent): code review →
CONTROL-REPORT-CODE.md, policy/evidence/fixture audit →
CONTROL-REPORT-POLICY.md. Fix-forward applies; final commit after verdicts.

---

## 2026-08-10 — Control verdicts + fix-forward (final round)

**Verdicts:** POLICY audit → **APPROVED** (13-item table, 0 FAILs vs the four
iron rules; 3 advisory WARNs). CODE review → **NEEDS-FIX**: 1 HIGH + 3 MEDIUM
+ 4 LOW. Fix-forward applied and re-verified — suite **133/133**.

| Finding | Fix (file) | Verified |
|---|---|---|
| H1 scope bypass: `=`-skip exempted ANY host token (live exploits: `10.0.0.99=x`, `curl --url=http://evil.com=`) | scope.py: skip only if NOT IP literal AND prev char not `/` (not in URL); start-of-command treated as URL context | live re-run of the reviewer's exact 3 exploits → all blocked; legit script-args + ffuf still pass |
| M1 depends_on non-list crashed (`depends_on: 5` → TypeError) | reasoning.py: type-check before iterating; non-list → no deps (audited) | test loop 5/True/"x"/3.14 → ok, tasks created |
| M2 sync_run imported out-of-scope runs | pentestcore.py: `scope.check_target` on run target before import | live: `pc sync` of external run 35.206.100.20 → refused, clean error |
| M3 `\\wsl$\` UNC path broke read-only URI connect | pentestcore.py: fallback plain connect + `PRAGMA query_only=ON` | unit: ro-write rejection test |
| L1 raw tracebacks on pc CLI errors | cli.py: missing-arg guards + clean `pc error:` handler | 2 CLI error-path tests |
| L2 connect_rw FK off | pentestcore.py: `PRAGMA foreign_keys=ON` | PRAGMA test |
| L3 `_fact_value` NULL detail crash | `(f["detail"] or "")[:500]` | — |
| W1 evidence-less write-back | documented OPERATOR-CERTIFIED semantics (module docstring) — CLI-only path, never LLM-reachable | — |
| W12/W13 engine vocab, run_id form | accepted as documented platform behavior (pentest-core itself writes evidence-less rows and mixed run_id forms) | — |

**Tests added (control-driven):** scope `=`-bypass (3 exploit cases + 2 legit),
depends_on non-list ×4, digest PASS-filter, sync out-of-scope refusal,
ro-write rejection, rw FK enforcement, pc missing-args ×2.

**Final state:** suite 133/133 · all control findings closed · docs:
CONTROL-REPORT-CODE.md + CONTROL-REPORT-POLICY.md committed · commit follows.

---

## 2026-08-11 — Overnight closure round (operator asleep; full autonomy, $10 budget)

**Mandate:** close the remaining acceptance gaps (G1 stress, G4 rollover,
real ffuf/burp/nikto captures, live production write-back) + 3 real-user
dashboard tests. Authorized: anything except faking data. Control agents
dispatched per user instruction ("create control over the agents").

### 1. 48-turn lab engagement (G1/G4 stress) — PASS
- `scripts/engagement_driver.py` (new, committed): automated engagement —
  48 reasoning turns on deepseek-v4-flash interleaved with 8 REAL tool phases
  (nmap ×2, gobuster, ffuf, nikto, nuclei, sqlmap, ZAP) against the authorized
  lab (127.0.0.1:8001/3000/8080). Driver NEVER executes model-proposed
  commands; runs only its whitelisted scans; logs everything to
  `<state>/engagement-log.jsonl`; state in the INTECTED DB.
- Mission ENG-OVERNIGHT-20260810-235627: **48/48 turns, 2490.8s wall**,
  12 tasks (10 completed / 1 blocked / 1 pending), 22 approved commands
  **22/22 unique**, **20 duplicate re-proposals rejected** (anti-loop guard),
  0 out-of-scope / 0 aggressive bypasses, **0 reasoning errors / 0 parse
  errors**, digest grew **674 → 3366 chars (+399%) monotonically** — G1 PASS,
  G4 PASS (independently confirmed by CONTROL-REPORT-ENGAGEMENT.md, APPROVED).
- QA events (honest, fixed): driver crashed at turn 6 (phase dispatch bug —
  `PHASES` bound function-name strings; fixed by resolving `RUNNERS`) and was
  relaunched; sqlmap timed out at 480s (CPU), ZAP container arg issue
  (`/zap/wrk`), gobuster/ffuf/nuclei hit missing kali wordlists/templates —
  all logged honestly, no faking.
- Full report: docs/ENGAGEMENT-REPORT.md.

### 2. Real captures + nikto extractor fix (G2) — DONE
- Worker B produced real ffuf (DVWA 9 paths, JuiceShop 16 paths with -ac) +
  nikto 2.6.0 captures; tests added.
- **Real extractor gap found & FIXED**: nikto 2.6.0 prints `[OSVDB-id]`
  prefixed findings and `+ ERROR:` — the extractor now lifts them into facts
  (`nikto_osvdb`) and warnings (both signs); 16 facts from the real capture,
  regression-tested (intected/parsing/extractors/nikto.py).
- Control verdict NEEDS-FIX on freshness (captures dated 2026-08-10 23:56, not
  08-11) → **fix-forward: fresh scans re-run 2026-08-11 01:12**
  (real-ffuf-dvwa-20260811.jsonl sha256 ef6f6f08…, real-nikto-dvwa-20260811.txt
  sha256 c0312733…), tests + README provenance updated, sha256s verified.
  Suite 141/141.
- burp: honestly remains a documented-format sample (no burp CLI on this host).

### 3. LIVE production write-back — PASS (operator-authorized)
- Worker C: pre-flight (journal_mode=wal, integrity_check=ok, daemon :9292
  listening) → real nmap scan evidence (Apache httpd 2.4.25 on :8001) →
  `pc write` (mission WB-LIVE, scope gate passed) → **finding 413** in the
  production pentest.db (runs 35→36, findings 412→413) → independent readback
  + post-write integrity_check=ok + daemon healthy. Docs/WRITEBACK-LIVE.md;
  control APPROVED (CONTROL-REPORT-WRITEBACK.md).

### 4. Real-user dashboard tests (operator request) — 4/4 PASS
- docs/DASHBOARD-USER-TESTS.md + screenshots/: TEST 1 Process view (task tree
  14, command queue 22, pill connected) · TEST 2 Results + evidence modal
  (sha256 d1ccdc1d2b4a… + "✓ verified on disk" + raw payload) · TEST 3 Mission
  view + auth (401 no/wrong token) · TEST 4 live round-trip (CLI task add →
  appears on dashboard within the 3s poll).
- QA event: the earlier temp-state dashboard served a deleted-inode DB (temp
  cleanup replaced the file while the process held it open) → restarted on the
  REAL state dir (~/.intected); documented, not a project defect.
- UX note: facts synced from pentest-core carry run-relative evidence paths
  (verified-integrity sha256 intact; on-disk verification is for local-evidence
  facts).

### 5. Control batch (deleg_a5b768a6) — 3/3 complete
- CONTROL-REPORT-ENGAGEMENT.md: APPROVED (G1/G4 PASS, numbers match ground
  truth exactly, 6 cosmetic discrepancies).
- CONTROL-REPORT-WRITEBACK.md: APPROVED.
- CONTROL-REPORT-FIXTURES.md: NEEDS-FIX on freshness → closed by fix-forward
  (fresh 2026-08-11 captures, section 2 above).

**Final state:** suite 141/141 · scorecard 92.9% weighted (G1 95, G2 95,
G3 90, G4 90, G5 95) · all plan phases P0–P4 + stress/fixtures/write-back
delivered and audited · commit follows.

**Post-commit note (01:17):** one transient suite failure (1 failed / 140
passed) occurred once at ~01:16, immediately before a doc-only commit — no code
had changed since the previous green run. Consistent with the known arsenal
WSL-probe flake (kali was busy with the fresh 01:12 ffuf/nikto scans). It did
not reproduce in 4 subsequent runs (141/141 each; `lastfailed={}`). The exact
test name was cleared from the pytest cache by the passing re-run — recorded
honestly rather than guessed.

---

## 2026-08-11 01:20–01:50 — Secure key upload (secrets vault) + user evidence verification

**Request:** "create a secure way for the key upload" + spot-check the dashboard
evidence modals the user pasted (fact #18 nmap, fact #14 nikto) via review
agents.

### 1. Secrets vault (intected/secrets.py + `intected keys` CLI) — DONE
- Windows: DPAPI (CryptProtectData, current-user scope) — the native
  Credential-Manager-grade store; `<state>/secrets.vault` never holds
  plaintext (live-verified: real master key stored, not present in the file).
- Other platforms: honest degradation (obfuscation + 0600) with a loud
  warning at set-time.
- CLI: `keys set/get/list/rm/import` (--file/--stdin/--show/--delete-after);
  values never echoed (masked last-4), audit rows carry names only, import
  --delete-after is success-gated.
- config: `state_dir()/db_path()` lazy resolution — runtime INTECTED_STATE
  overrides now honored (this ALSO fixed a latent bug where CLI commands
  ignored a mid-process env change).
- Bridge integration: master_key() = env > vault 'deepseek_master' > plaintext
  file; live-proven vault-only (10 models incl. deepseek-v4-flash/pro served
  with the plaintext file moved aside); vault failures now audible (stderr)
  after review WARN.

### 2. Security review (agent deleg_4711a7e6) — APPROVED
- 155 passed / 1 skipped; DPAPI binding correct; no plaintext in vault;
  masking/audit leak-free; tamper detected (probe on a copy of the REAL
  vault); --delete-after success-gated; **no key material in repo/git**.
- WARNs fixed: audible vault failure (bridge), --name required, --show
  audited, hint suppressed for short values → suite 157 passed / 1 skipped.

### 3. Evidence-chain verification (agent deleg_f1f3e8c4) — APPROVED
- fact #14 (nikto): DB sha256 == file sha256 == modal sha256
  (5f1cec9dabf3…), content verbatim, parsed sibling facts consistent.
- Spot-check nmap facts 18–21 (0a2585962281…): PASS.
- WARN: zap-65104def8460.raw orphan (failed ZAP phase artifact — the
  /zap/wrk mount issue already documented honestly in ENGAGEMENT-REPORT.md).
- DB integrity_check ok. docs/CONTROL-REPORT-EVIDENCE.md + SECRETS.md.

**State:** suite 157 passed / 1 skipped · vault live with real key · bridge on
vault · both control reports APPROVED · commit follows.

---

## 2026-08-11 01:55–02:10 — Dashboard: target input (IP / domain / IP range)

**Request:** "הוסף לדשבורד מקום להכניס את פרטי המטרה (IP OR DOMAIN OR IP
RANGE)" — add a target-entry field to the dashboard.

- Backend: `scope.validate_target()` (IPv4 / IPv6 / CIDR v4+v6 / hostname;
  rejects URLs, paths, ports, spaces, malformed IPs like `1.2.3` /
  `10.0.0.999`); `db.add_mission_target()` (deduped scope append + audit);
  `POST /api/missions/{id}/targets` (auth + origin-guarded, 422 on invalid).
- Frontend: Mission view "Targets (scope)" card — chips + input + Add button,
  live feedback ("added X" / server detail on error).
- **Live test caught a real bug**: the POST fetch didn't forward the token
  (GETs use the URL query; the fetch sent none → 401). Fixed: the page reads
  `?token=` from the URL and sends `X-INTECTED-Token`. Re-verified end-to-end
  in the browser (chips update, audit rows 171-172).
- Also cleaned 4 empty test-artifact missions (id 4-7, "LAB") that the old
  pre-fix CLI tests had written into the real state DB yesterday 22:33.
- Tests: 157 → 169 (8 validator + 5 API endpoint tests).

---

## 2026-08-11 02:15–02:30 — "Start test" button (disabled until a target is entered)

**Request:** "הוסף כפתור התחל בדיקה... הכפתור יהיה כבוי עד שיוכנס מטרה" — a
Start-test button, disabled until the mission has at least one target.

- Backend: `db.start_mission_test()` — creates a "Run penetration test
  against <target>" scan task per scope target (deduped by title, idempotent),
  audited (mission.start_test); `POST /api/missions/{id}/start` (auth'd; 422
  when no targets; 404 unknown mission).
- Frontend: "Start test" button (primary green) in the Targets card —
  `renderTargets()` sets `disabled = no targets`; on click → POST → green
  message "test started — N scan task(s) created for M target(s)" → task tree
  refreshes.
- Live-verified in the browser: disabled with empty scope, enabled after
  target add, click → 6 tasks created for the 6 targets, tree updated, audit
  row written.
- Tests: 169 → 173 (start endpoint: no-targets 422, creates tasks, idempotent,
  auth 401).

---

## 2026-08-11 02:30–03:00 — Scan assignments view + target removal + clearer messages

**Requests (live feedback loop):** (1) "test started — 0 scan task(s)" looked
like nothing was assigned → show WHICH scans run against WHICH target;
(2) "אין אפשרות להסיר מטרות" → add target removal to the dashboard.

- **Scan assignments table** (Targets card): target | scan task | status,
  filtered to CURRENT scope targets only (orphaned tasks for removed targets
  hidden) — answers "what runs against what" directly on screen.
- **Message fix**: second Start-test click now reports
  "all N target(s) already have scan task(s) — see scan assignments below"
  (db.start_mission_test returns created AND existing counts; idempotent).
- **Target removal**: ✕ on every scope chip → DELETE
  /api/missions/{id}/targets?target=… (auth'd; 422 when not in scope; CIDR
  survives URL-encoding) → chips + assignments + Start-test disabled-state all
  update live; audited (mission.remove_target). Removing the last target
  re-disables the Start test button.
- QA events: an orphaned uvicorn child (survivor of a killed dashboard) held
  :8765 in a bad state — killed the whole tree before restart; dashboard
  verified LISTENING + API 200.
- Tests: 173 → 176 (remove target, CIDR roundtrip, auth 401).

---

## 2026-08-11 03:10–03:50 — Evidence-based attack planning (user methodology)

**Request:** implement the operator's pentest methodology: Recon →
Fingerprinting → Attack Surface → Validation → evidence-based test plan
(OWASP-aligned). Core rule: every finding leads to a test hypothesis; every
test is based on a previous finding.

- **intected/evidence.py** — Evidence Graph (methodology 12): per-target
  structured model (services, technologies with confidence, WAF indicators
  with multi-signal confidence, attack surface), composed from the fact store,
  every element tracing to sha256 evidence. Plus `score_finding`
  (confidence x impact x exploitability x exposure → P0-P3) and
  `stack_profile` (branch selection).
- **intected/planner.py** — Attack-Plan Engine (methodology 11): web_api vs
  network branch; web priorities Auth/AuthZ → JWT → API authz → GraphQL →
  Injection → Client-side → Infra (the exact decision tree from the doc);
  network branch Service enum → versions → CVE correlation → config → auth →
  validation. Every plan item carries based_on fact ids + concrete commands.
- **CLI**: `intected evidence --mission N` (JSON graph), `intected plan
  --mission N` (ranked plan with why + commands).
- **Dashboard Plan tab**: evidence graph + ranked plan rendered live
  (GET /api/missions/{id}/plan).
- QA events: (1) web-branch false-positive fixed — stack_profile counted any
  TCP banner as "web"; now web = http/https protocol or known web ports.
  (2) note-path extraction regex required the quote right after the path, but
  nikto notes are "/path: message" — fixed to match up to the colon.
- Live verification: re-parsed the REAL nikto evidence of mission 3 with the
  fixed extractor (16 facts incl. 12 path facts: /login.php, /config/, /docs/)
  → the plan now correctly ranks **P1 Authentication/AuthZ** (driven by the
  /login.php evidence) — exactly the evidence-based branching requested.
- Tests: 176 → 185 (evidence graph aggregation, WAF signals, note-path
  lifting, scoring, web/network branches, empty mission, plan endpoint + auth).

---

## 2026-08-11 03:55–04:30 — Multi-agent execution layer + architecture review

**Request:** implement the multi-agent spec (Supervisor/Recon/Expert agents,
zero-hallucination, live NVD, no-DoS, GDPR/SOC2 behavior, function-calling,
queue) AND review it — good and bad.

- intected/tools.py: tool registry (nmap_ports, nmap_services, http_headers,
  nikto, ffuf_content, nuclei) — typed params, rate caps (300 pps), timeouts;
  the ONLY execution path (no raw bash).
- intected/supervisor.py: Agent-1 gate — scope deny-by-default, rate bounds,
  DoS/brute-force/data-extraction bans, full -p- needs operator approval.
- intected/cve.py: live NVD v2 client (7s throttle, cache, honest failures);
  banner->CPE 2.3 (curated alias httpd->http_server). Live: Apache 2.4.7 ->
  10 real CVEs.
- intected/pii.py: email/phone/cc/ssn detect+redact.
- CLI: intected run; tests 185 -> 201.
- Review doc: docs/ARCHITECTURE-REVIEW.md — GOOD: supervisor gate, zero-
  hallucination, NVD, rate caps, PII; BAD (documented): Redis overkill
  (SQLite tasks suffice), "full Kali exploitation" conflicts with operator
  approval + legal policy, SOC2-as-code claims rejected, NVD loose-match
  caveat.

---

## 2026-08-11 04:30–05:00 — Multi-agent addendum: decision matrix, stealth configs, dynamic updating

**Requests (addendum sections 6-9 + log-parsing):** deterministic tool
selection, supervisor-enforced stealth defaults, pre-flight tool version
validation, real-time stdout capture, nuclei template updates, WAF-bypass KB.

- intected/matrix.py: IF/THEN decision matrix on the footprint (WAF-aware;
  no masscan; metasploit stays operator-gated). Live: scanme -> ffuf_content.
- tools.py: SAFE_DEFAULTS (nmap --max-rate 50 -T3 --data-length 32, ffuf
  -t 5 -p 1 delay 1s, nuclei -rl 10 -c 5) enforced in _build_command (tests
  assert the flags); probe_tool() ToolVersionValidator (real --version/--help
  from the kali image, cached for planner context); execute_streaming()
  real-time line-by-line stdout capture.
- intected/waf_kb.py: local markdown KB + token-overlap retrieval (honest
  alternative to ChromaDB/LangChain); `intected waf-kb seed|query`.
- CLI: tools (defaults|probe), matrix, waf-kb; tests 201 -> 208.
- Review updated: docs/ARCHITECTURE-REVIEW.md addendum section.

---

## 2026-08-11 05:30-06:00 — Code-improvement round (operator recommendations)

Four specific recommendations, all implemented + tested (212 -> 217):

1. **Honeypot detection** (matrix.py): service/port mismatch heuristic —
   SSH-like banner on port 445 etc. flagged low-confidence (0.25) and the
   matrix returns a PASSIVE probe only ("HONEYPOT CANDIDATE — no aggressive
   testing"). Wired into `intected matrix` (services passed in).

2. **Nmap text-mode NSE script parsing** (parsing/extractors/nmap.py):
   vulners / ssl-cert / other script blocks -> note facts with `vulnerable`
   flag (CVE- markers), http-title not double-captured, fingerprint-strings
   skipped. Also FIXED the CRLF cross-line bug: `\s*` in the port regex ate
   `\r\n` and `(.*)` captured the NEXT line (ports 8001/9090 were lost and
   banners attached to wrong ports — found during the real lab recon).
   Regression tests for both.

3. **Few-shot negative examples** (reasoning.py SYSTEM_PROMPT): five rejected
   commands with the exact supervisor reason (brute-force, rate caps, --dump
   PII, hallucinated nuclei tag, out-of-scope) — grounds the model at temp
   0.0, fewer wasted reasoning cycles.

4. **WAF-aware scoring** (evidence.py): score_finding(..., waf=True) reduces
   exposure automatically (x0.6 mitigation discount, waf_discounted flag) —
   an internet-reachable port behind a WAF is not scored as fully exposed.

Real lab recon (mission 8 LAB-REALTEST, 127.0.0.1): nmap top-1000 found
3000/8001/8080/9090 (real facts, sha256 evidence); services stage identified
Apache Tomcat on 8080. Verified kali tools in real tests: nmap, nikto,
whatweb, wafw00f, gobuster, nuclei 3.8, ffuf, dig. ffuf against DVWA is
pathologically slow (per-request PHP sessions) — documented, not a tool bug.

---

## 2026-08-11 05:00-05:10 — Kali tools full check + POC (operator request)

Checked the operator's 14-category Kali list in kali-linux WSL: 26 installed,
38 not (minimal install — no GUI/wireless stack). Real bounded POCs against
authorized targets only: nmap/masscan found real ports, nikto produced 13+
DVWA findings, sqlmap ran live injection tests on Juice REST, gobuster/dirb
correctly detected the SPA wildcard, john ran a crack session, tcpdump
captured clean. Policy mapping documented: brute-force (hydra/medusa) and
exploitation (msf) exist but stay OUT of the execution registry
(operator-gated, legal scope only). Honest gaps: nuclei templates missing
(needs `nuclei -ut` + internet), impacket absent, amass libpostal degraded.
Full report: docs/KALI-TOOLS-POC.md.

---

## 2026-08-11 05:20 — Open-items cleanup (operator request)

1. **Command queue (26)**: all stale commands (targets removed from scope)
   rejected with audit entries — 23 rejected (m3's 127.0.0.1/localhost/
   host.docker.internal-era commands); 3 kept proposed because their targets
   ARE in their missions' current scopes (m1 dvwa.local ×2, m2 lab trio ×1).
   Command states: 23 rejected / 3 proposed.
2. **Blocked tasks**: re-scoped against the CURRENT mission-3 scope
   (scanme.nmap.org, 45.33.32.156): tasks 19-22 (127.0.0.1, localhost,
   host.docker.internal, 10.10.10.0/24) → BLOCKED (consistent with the
   engine's scope enforcement); task 24 (scanme.nmap.org) → UNBLOCKED to
   pending (target is back in scope); task 25 (45.33.32.156) stays pending.
   Task 23 (172.16.5.0/24) stays blocked — never authorized.
3. **10.10.10.0/24**: task 22 blocked; plan verified re-ranked to scanme
   (P1 Auth/AuthZ first, Apache+Tomcat, 6 surface paths).
4. **nuclei**: focused -tags cve run against scanme (outdated Apache 2.4.7),
   bounded 240s at rl 10 — result logged when complete.

### nuclei follow-up (05:25)
- scanme.nmap.org -tags cve (240s, rl 10): EXIT 124 (bounded), 0 findings —
  honest zero; scanme's minimal Apache 2.4.7 does not trip conservative CVE
  templates. Nuclei operational (templates load, scans run end-to-end).
- Follow-up: all-tags run against the lab Juice Shop (:3000, 300s, rl 10) —
  designed-vulnerable target; result logged when complete.

### Report fixes (05:40, operator request "בדוק ותקן את הדוחות")
- nmap text extractor: (a) app identification from fingerprint-strings —
  evidence-based signature match (OWASP Juice Shop, Tomcat, nginx, Apache
  httpd, IIS) turns nmap's "ppp?" into a real version fact {service, product}
  with the port from the SF-PortNNNN marker; (b) \xNN escape decoding for
  http-title/script output (multi-byte UTF-8 aware) — "HTTP Status 404
  \xE2\x80\x93" now stores the real en dash (U+2013).
- Regression tests +2 (escaped title, fingerprint identification); CRLF test
  repaired (patch-tool CRLF mangling fixed via line-surgery).
- Re-ingested mission-8 real evidence: facts now include version
  {port:3000, product:"OWASP Juice Shop"} + decoded http-title.
- Suite 219 passed + 1 skipped.

### nuclei FULLY FIXED (06:10-06:25) — root-cause chain
1. kali package nuclei 3.8.0-0kali1 broken (banner-only; wchan do_wait).
   Replaced with official v3.11.1 static build (broken kept as
   nuclei.broken-3.8.0).
2. REAL hang: nuclei blocks on TTY stdin — </dev/null unblocks it
   (execute_streaming now passes stdin=DEVNULL — project fix committed).
3. Startup checks (PD API 65.109.43.133:443 + IPv6 Google DNS) blackholed by
   WSL2 NAT → iptables REJECT (PD IP) + ip6tables REJECT all IPv6 → fail
   fast, scan proceeds.
4. -duc must NOT be used (breaks template index load: "no templates
   provided").
RESULT: 961 templates load; REAL finding — prometheus-metrics [medium] at
http://127.0.0.1:3000/metrics (verified HTTP 200, 26KB real metrics) —
ingested as a fact in mission 8 (evidence: nuclei_juice_20260811.jsonl +
metrics_juice_20260811.raw).
