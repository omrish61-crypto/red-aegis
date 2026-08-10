# CONTROL REPORT — CODE REVIEW (P4 pentest-core integration + hardening)

- **Reviewer:** independent code review (read-only; no repo files modified, no commits)
- **Scope:** P4 changes — `intected/pentestcore.py` (new), `intected/cli.py` (`pc` subcommand + status integration), `intected/config.py` (`PENTEST_CORE_DB`, temperature 0.0, timeout 300), `intected/scope.py` (key=value script-args exclusion), `intected/router.py` (temperature passthrough), `intected/reasoning.py` (PASS-fact digest filter, empty-tree note, depends_on FK guard, max_tokens 4096), plus `tests/test_pentestcore.py`, `tests/test_scope.py`, `tests/test_router.py`, `tests/test_reasoning.py`
- **Evidence gathered:** full source read of all changed files + `db.py`, `ptm.py`, `parsing/__init__.py`, `parsing/extractors/zap.py`; `git diff` of every modified file; targeted test run `uv run pytest tests/test_pentestcore.py -q` → **18 passed**; 6 adversarial edge-case probes executed live against the real code (results cited below)
- **Date:** 2026-08-10

---

## 1. Verdict table

| # | Item | Verdict | File:line | Note |
|---|------|---------|-----------|------|
| 1 | Read-only pentest-core connection (`mode=ro` URI) | **PASS** | `intected/pentestcore.py:50` | Verified live: INSERT on ro connection → `OperationalError: attempt to write a readonly database`. Schema guard (`PC_TABLES`) rejects non-pentest-core DBs before any query (pentestcore.py:54-61, 74-81). |
| 2 | No SQL injection in new SQL | **PASS** | `intected/pentestcore.py:93-138, 243-254` | Every query parameterized with `?`; no f-string/string-concatenated SQL anywhere in the module. |
| 3 | Write gate 1 — MissionScope deny-by-default | **PASS** | `intected/pentestcore.py:237`, `intected/scope.py:114-121` | `check_target` raises `ScopeViolation` before any DB write; out-of-scope write leaves pc DB untouched (verified by test + code order). Empty allowed_hosts refuses everything (scope.py:116-117). |
| 4 | Write gate 2 — severity/engine vocabulary | **PASS** | `intected/pentestcore.py:238-241` | `PC_SEVERITIES` whitelist; empty engine/title rejected; CLI `--severity` choices mirror the whitelist (cli.py:376-377). |
| 5 | No-simulation iron rule — findings only from real output | **PASS** | `intected/pentestcore.py` (whole), `intected/cli.py:277-290` | (a) grep for hardcoded/canned finding data in new module: clean. (b) `write_finding` is reachable ONLY from the human CLI `pc write` — never from `reasoning`/LLM paths (grep of all callers). (c) INTECTED facts originate only from `parsing.parse_tool_output` (mandatory `evidence_ref`+`sha256`, parsing/__init__.py:94-104) or from the production pentest-core DB (real runs). Sync carries evidence_ref/sha256 through (pentestcore.py:195-198). |
| 6 | Sync idempotency | **PASS** | `intected/pentestcore.py:182-198` | `{pc_run, pc_finding}` markers in value_json; re-sync inserts 0, skips 3 (test `test_sync_is_idempotent`). |
| 7 | Connection lifecycle / leaks | **PASS** | `intected/cli.py:251-292`, `intected/cli.py:54-63` | `pc_conn` closed in `finally` on every `cmd_pc` path (incl. rw swap in write branch) and in `cmd_status`; ro conns closed in tests. Pre-existing INTECTED `conn` leak in CLI (documented by test gc comment) is out of P4 scope. |
| 8 | CLI `pc` subcommand (stats/sync/write) | **PASS** | `intected/cli.py:240-293` | End-to-end covered by 3 CLI tests; missing-db path handled cleanly with usage hint. |
| 9 | Router temperature passthrough | **PASS** | `intected/router.py:80-81`, `intected/config.py:45` | `temperature: 0.0` sent for `reasoning` (test asserts payload), omitted for local routes (test asserts absence). `0.0 is not None` guard correct. |
| 10 | Reasoning timeout 300 + max_tokens 4096 | **PASS** | `intected/config.py:39`, `intected/reasoning.py:165` | Consistent; `router_check` caps probe at 90 s (router.py:153) so the CLI probe isn't wedged by the 300 s timeout. |
| 11 | PASS-fact digest filter | **PASS** | `intected/reasoning.py:134-143` | ZAP extractor stores `level` in fact value (zap.py:35) so `level == "PASS"` matches; tolerant of non-dict/malformed value_json (returns False, no crash). |
| 12 | Empty task-tree note | **PASS** | `intected/reasoning.py:121-122` | New mission digest no longer renders a bare `TASK TREE:` with nothing under it. |
| 13 | Strict aggressive boolean | **PASS** | `intected/scope.py:135-140`, `intected/reasoning.py:310` | `aggressive is True` strict; string `"true"` rejected (tests `test_destructive_marker_string_true_rejected`). |
| 14 | depends_on FK guard (hallucinated ids) | **PASS** (with edge, see M1) | `intected/reasoning.py:260-265` | Unknown ids dropped + audited; valid deps kept; `task_deps` INSERT no longer crashes on FK violation (test passes). **But see M1** — non-list `depends_on` still crashes. |
| 15 | **Scope bypass: `=`-skip over-broad** | **FAIL** | `intected/scope.py:162-163` | See H1. Demonstrated live. |
| 16 | **sync_run has no scope gate on the run target** | **WARN** | `intected/pentestcore.py:168-203` | See M2. Demonstrated live. |
| 17 | **UNC `\\wsl$` path via `mode=ro` URI** | **WARN** | `intected/pentestcore.py:50`, `intected/cli.py:248` | See M3. Demonstrated live. |
| 18 | CLI error handling for `pc` (missing args, DB errors) | **WARN** | `intected/cli.py:240-293`, `intected/cli.py:391-395` | See L1. |
| 19 | `connect_rw` FK enforcement | **WARN** | `intected/pentestcore.py:64-81` | See L2. |
| 20 | `_fact_value` NULL-safety on schema drift | **WARN** | `intected/pentestcore.py:155` | See L3. |
| 21 | Test coverage of new module | **WARN** | `tests/test_pentestcore.py` | 18/18 pass, but see L4 for gaps. |

---

## 2. Findings by severity

### HIGH

**H1 — MissionScope bypass: any host token immediately followed by `=` is skipped** (`intected/scope.py:162-163`)
The P4 key=value fix exempts *every* host-like token whose next character is `=`, not just option-name positions. Verified live:

```
scope.check_command('curl -s http://dvwa.local/ -e http://evil.com= http://dvwa.local/', ["dvwa.local"])   # PASSES (evil.com escapes)
scope.check_command('nmap -sV 10.0.0.99=x', ["10.0.0.5"])                                                  # PASSES (out-of-scope host escapes)
```

Realistic exploit: `curl --url=http://evil.com= http://dvwa.local/` — the out-of-scope host in an arg value is silently exempted while the in-scope target is checked, so the command is approved and the hostile host gets contacted. Since the LLM (which proposes commands) consumes facts gathered *from hostile targets*, this is a viable prompt-injection → out-of-scope-action path. The aggressive-marker and risk-category gates are unaffected (still strict), and positional targets of typical nmap/gobuster/ffuf commands are still checked — but the scope gate is the product's core "ethics, non-negotiable" boundary and it is trivially defeatable.
**Fix direction:** only skip when the token is in an option-name position (e.g., preceded by whitespace *and* the token itself contains no `/` or is a known arg-name pattern), never when the token looks like a host/URL (contains `/` or `://`), or restrict the exemption to tokens matching `[a-z0-9.-]+=` with no scheme. Add regression tests for `--url=http://host=`, `-e http://host=`, `host=` as positional.

### MEDIUM

**M1 — depends_on FK guard crashes on non-list types** (`intected/reasoning.py:260-265`)
The guard validates hallucinated *ids* but not the *type* of `depends_on`. Verified live — model output `"depends_on": 5`:

```
TypeError: 'int' object is not iterable   # unhandled, propagates out of next_step → CLI traceback
```

This is exactly the failure class ("never let an INSERT crash") the guard was added to eliminate; the schema in SYSTEM_PROMPT says list, but the guard's stated purpose is adversarial robustness against malformed model JSON. `bool`/`float`/`int` all crash. **Fix:** `if not isinstance(deps, list): deps = []` before iterating; add a test with `depends_on: 5`.

**M2 — sync_run imports findings from runs whose target is outside the mission's scope** (`intected/pentestcore.py:168-203`)
`sync_run` never calls `scope.check_target` on the run's target. Verified live: a pentest-core run targeting `10.0.0.99` synced `facts_added=1` into a mission whose only allowed host is `127.0.0.1`. Out-of-scope target data silently enters the mission fact store and is then fed to the reasoning digest. Command *execution* is still scope-gated (rejected downstream), so this is a defense-in-depth/data-hygiene gap, not a direct execution risk. **Fix:** reject (or loudly warn + require `--force`) when `scope.check_target(run["target"], mission_allowed)` fails; add a test.

**M3 — documented `\\wsl$` deployment path fails for the read-only connection** (`intected/pentestcore.py:50`, `cli.py:248`)
The CLI help advertises `INTECTED_PENTEST_CORE_DB="\\wsl$\...\pentest.db"` — the realistic Windows→WSL path for the production DB. Verified live:
- `file:\\wsl$\...?mode=ro` → `OperationalError: unable to open database file`
- `file://wsl$/...` (correct authority form) → `OperationalError: invalid uri authority: wsl$`

Meanwhile `connect_rw` (plain path, no URI) opens UNC paths fine — so `pc stats`/`pc sync` fail while `pc write` would work on the same path. Failure is loud (PentestCoreError), with workarounds (copy DB, mapped drive), but the flagship integration path is broken as documented. **Fix:** normalize the path before URI-encoding (forward slashes + percent-encode, or `file:///` form), or fall back to plain `sqlite3.connect` + `PRAGMA query_only=ON` when URI mode fails.

### LOW

**L1 — `pc` CLI surfaces raw tracebacks on missing args / DB errors** (`cli.py:240-293`, `cli.py:391-395`)
`main()` catches only `ScopeViolation`; `PentestCoreError` (e.g. `pc sync` without `--run`/`--mission` → "mission not found: None"), `ValueError`, and `sqlite3.Error` propagate as full tracebacks. Loud, not silent — but a `pc`-level try/except with a clean stderr message would match the polish of the rest of the CLI.

**L2 — `connect_rw` never enables `PRAGMA foreign_keys`** (`pentestcore.py:64-81`)
Writable connection runs with FK enforcement off. Today harmless (run row is inserted before the finding, so the FK is satisfied; `INSERT OR IGNORE` covers collisions), but any schema drift or caller-supplied `run_id` pointing at a missing run would silently create an orphan finding instead of failing. Enable `PRAGMA foreign_keys = ON` after connect.

**L3 — `_fact_value` crashes on NULL `detail`** (`pentestcore.py:155`)
`f["detail"][:500]` raises `TypeError` if the live pentest-core schema ever yields NULL (fixture declares `NOT NULL DEFAULT ''`). A `(f["detail"] or "")[:500]` would be drift-proof. Same class: `get_run`/`_fact_value` assume non-NULL columns.

**L4 — Test gaps** (`tests/test_pentestcore.py`, `tests/test_scope.py`)
18 tests pass and cover the main flows well. Missing: ro-connection write rejection (docstring promise at pentestcore.py:222-223 is untested), write idempotency when the run already exists, `run_id` override param, `pc sync`/`write` missing-required-arg error paths, `depends_on` non-list type, `=`-bypass regression cases, and the `_is_pass_rule` filter (no direct test in `test_reasoning.py`).

---

## 3. Overall verdict: **NEEDS-FIX**

The P4 integration is well-constructed — deny-by-default write gating, parameterized SQL, verified read-only enforcement, idempotent sync, no LLM-reachable write path (no-simulation rule intact), and the hardening fixes (temperature 0.0, timeout/max_tokens, PASS-filter, FK-id guard) are sound and tested (18/18 targeted pass; full suite per parent 126). However, **H1 is a demonstrated, trivially reproducible bypass of MissionScope** — the product's core safety boundary — introduced by the same P4 change that intended to strengthen it, and **M1** is an unhandled-exception crash in the newly hardened model-input path. Both have one-line fixes and clear regression-test targets. M2/M3 are defense-in-depth and deployment-path defects worth fixing in the same pass.

**Blocking items:** H1 (scope bypass). **Should-fix this pass:** M1, M2, M3. **Nice-to-have:** L1–L4.
