# CONTROL REPORT — P4 pentest-core integration: Policy + Evidence + Fixture-Authenticity Audit

- **Repo**: `C:\Users\onris\INTECTED` @ `9787972` (working tree; P4 = untracked `intected/pentestcore.py`, `tests/test_pentestcore.py` + modified `intected/scope.py`, `intected/cli.py`, `intected/config.py`)
- **Audit date**: 2026-08-10 (UTC+3)
- **Auditor**: CONTROL subagent (read-only policy/evidence review)
- **Backup DB cross-checked (read-only)**: `C:\Users\onris\AppData\Local\Temp\pentest-backup.db` (1,196,032 bytes; dumped from live WSL pentest-core DB 2026-08-10)
- **Repo hygiene**: no repo files modified by this audit. NOTE: `README.md` and `docs/PROJECT-DIARY.md` changed (mtime 23:29–23:30, after audit start) by the worker concurrently — not by this audit.

---

## 1. Policy audit

### 1.1 NO-SIMULATION — findings exist only if real tool output proves them

Greps over `intected/` (run from repo root):

```
$ grep -rniE "sample|fake|hardcod|dummy|placeholder|CVE-20[0-9]{2}-0000" intected/
intected/parsing/extractors/ffuf.py:3:Sample line:          # docstring example, not data
intected/parsing/extractors/nikto.py:3:Sample lines:        # docstring example, not data
intected/router.py:53:  # Normalize: replace base_url placeholders with live config values  # comment

$ grep -rn "Finding(" intected/    -> no matches
$ grep -n "localhost|127.0.0.1|host.docker.internal|172.17" intected/pentestcore.py -> no matches
```

- **No fake CVEs** (`CVE-\d{4}-0000` pattern): 0 hits anywhere in `intected/`. The fixture's `CVE-2026-44631` is a **real CVE present in the production DB** (4 real rows — see §2), not a fabricated identifier.
- **No `Finding(` construction sites** — this codebase persists facts via `db.add_fact()`; every call site is fed by parsed real output:
  - `intected/parsing/__init__.py:95` — facts from extractors over a raw file.
  - `intected/pentestcore.py:196` — facts from rows of the real pentest-core DB (`sync_run`).
- **No hardcoded targets** in `pentestcore.py`; all targets/engines/severities are parameters or DB values.
- **Verdict: PASS** (pentestcore.py:96-100, 122-142, 168-203 — all data originates from `sqlite3` rows).

### 1.2 EVIDENCE-FIRST — raw artifacts saved + hashed before findings

| Path | Trace | Evidence |
|---|---|---|
| Scan-engine parse | `store_evidence()` persists raw bytes + sha256 **before** `parse_tool_output()` adds facts | `parsing/__init__.py:51-60` (write+hash), `:76-105` (re-hash, `add_fact(evidence_ref=str(raw_path), sha256=sha)`) |
| PC→INTECTED sync | every fact carries `evidence_ref` + `sha256` read from the pentest-core `findings.evidence` row | `pentestcore.py:160-165` (`_evidence_ref_sha`), `:195-198` |
| Write-back | `write_finding()` JSON-encodes caller-supplied `evidence`/`raw_lines` into the PC DB; INTECTED side is audited | `pentestcore.py:246-258` |

Live verification (§3): a real run (`run-linux2`, 16 findings) was synced read-only from the backup DB; facts carried `evidence_ref=raw/…` + valid sha256; `verify_evidence()` re-hash of a repo fixture artifact matched.

**Verdict: PASS** with one advisory gap → §5, W1 (`write_finding`/CLI `pc write` permit evidence-less findings).

### 1.3 HARD SCOPE — deny-by-default double gate

`write_finding` (`pentestcore.py:213-259`) enforces, in order, **before any write touches the PC DB**:

1. `db.get_mission` — unknown mission → `PentestCoreError` (line 233-235).
2. `scope.check_target(target, allowed)` — **deny by default**; empty `allowed_hosts_json` → `ScopeViolation` (lines 236-237, `scope.py:114-121`).
3. Severity vocabulary: `PC_SEVERITIES = ("critical","high","medium","low","info")` — matches the real DB's distinct severities exactly (lines 27, 238-239).
4. `engine` + `title` non-empty (lines 240-241).

`MissionScope.check_command` (`scope.py:124-164`): destructive markers require **strict boolean `aggressive is True`** (string `"true"` refused, line 136); risk-category gates (phishing/c2/evasion/credential) **deny by default** — `None`/bare string authorization never counts (lines 141-152). P4 change to `scope.py` (key=value script args no longer misparsed as hosts, lines 154-164) keeps the negative case: an out-of-scope IP in `X-Forwarded-For` is still rejected.

**Live probes (all passed)** — see §3 D1-D5, E1-E4: out-of-scope write → `ScopeViolation` with row count unchanged; empty-hosts mission → denied; bad severity → `ValueError`; read-only `connect()` → `sqlite3` error on INSERT (mode=ro URI, `pentestcore.py:50`); in-scope write succeeds and is audited in the INTECTED db.

**Verdict: PASS.**

### 1.4 HONEST REPORTING — negatives explained, never shown as 0

- `sync_run` returns `facts_added`/`skipped` explicitly (`pentestcore.py:202-203`); CLI prints both (`cli.py:273-275`).
- `ScopeViolation` → `SCOPE VIOLATION: …` to stderr + exit 1 (`cli.py:393-395`); the CLI test asserts non-zero rc (`test_pentestcore.py:384-403`).
- `stats()` counts real rows; nothing converts refused results into zeroes.
- **Verdict: PASS.**

---

## 2. Fixture-vs-real-schema cross-check (read-only, backup DB)

Real DB (`pentest-backup.db`): tables `runs`(14 rows), `findings`(177), `audit`(69), + sqlite_sequence. `connect()` accepts it (extra internal table ignored — `PC_TABLES` is a required-subset check, `pentestcore.py:54-60`).

### 2.1 Schema: PRAGMA-identical

`PRAGMA table_info` compared (name, type, notnull, dflt_value, pk) for `runs`/`findings`/`audit` between the fixture-built DB (verbatim `PC_SCHEMA` from `tests/test_pentestcore.py:22-55`) and the backup DB — **identical, including column order**:

```
runs:     run_id TEXT(PK), target TEXT NOT NULL, started TEXT, finished TEXT, mission_file TEXT
findings: id INTEGER PK AUTOINCREMENT, run_id TEXT NOT NULL, engine TEXT NOT NULL, type TEXT NOT NULL,
          severity TEXT NOT NULL, cvss REAL, cwe TEXT NOT NULL DEFAULT '[]', cve TEXT NOT NULL DEFAULT '[]',
          title TEXT NOT NULL, target TEXT NOT NULL, port INTEGER, path TEXT NOT NULL DEFAULT '',
          detail TEXT NOT NULL DEFAULT '', evidence TEXT NOT NULL DEFAULT '[]', raw_lines TEXT NOT NULL DEFAULT '[]',
          timestamp TEXT NOT NULL
audit:    id INTEGER PK AUTOINCREMENT, ts TEXT NOT NULL, level TEXT NOT NULL, event TEXT NOT NULL,
          details TEXT NOT NULL DEFAULT ''
```

Fixture `findings.run_id REFERENCES runs(run_id)` FK matches the real table (FK enforced via `PRAGMA foreign_keys=ON` in `db.connect`).

### 2.2 Fixture data realism

- JSON list columns (`cwe`, `cve`, `evidence`, `raw_lines`) all parse to Python lists in both fixture and real DB (real: 177/177 rows clean).
- Evidence entries use the real shape `{"path","sha256","kind"}` — fixture `{"path":"raw/nmap-vuln.xml","sha256":"<64-hex>","kind":"xml"}` matches real rows e.g. `{"path":"raw/nmap-vuln.xml","sha256":"b95b24c6…a2c66","kind":"xml"}`.
- sha256 values are 64-char lowercase hex in both.
- Real-DB authenticity signals mirrored by the fixture:
  - severity set `{critical,high,medium,low,info}` == `PC_SEVERITIES`;
  - fixture CVE `CVE-2026-44631` exists in 4 real rows (real Apache httpd CVE set: 2026-44631, 2026-29167, 2026-28780, 2024-38476, 2024-38474, 2023-25690, …);
  - fixture run_id format `localhost_8001-20260810-210153` / `127.0.0.1_3000-20260810-221603` matches real runs (`localhost_8001-20260810-210153` and `127.0.0.1_3000-20260810-221603` both exist in the backup);
  - fixture timestamps use the real `YYYY-MM-DDTHH:MM:SS+00:00` style;
  - `run_id_for()` output format `<target>-YYYYMMDD-HHMMSS` matches real run `127.0.0.1:8001-20260810-201720`.
- Real evidence artifact inventory (all real, kinds+paths consistent with INTECTED extractors): 71× `raw/zap.json` (json), 44× `raw/gobuster.txt`, 32× `raw/nmap.xml`, 13× `raw/nuclei.jsonl`, 8× `raw/nmap-vuln.xml`, 4× `raw/sqlmap-1.txt`, 4× `raw/gobuster.stderr.txt`.

### 2.3 Real-DB data-quality observation (not a fixture defect)

Exactly **1 of 177** real findings has empty evidence **and** empty raw_lines: `id=177`, `run='127.0.0.1:8001-20260810-201720'`, `engine=sqlmap`, `type='finding'`, `severity='high'`, `title='SQLi re-verified'`. Every other real evidence entry (176/176) carries a valid 64-hex sha256. This single evidence-less row is the exact shape `write_finding` produces without evidence — see W1.

**Verdict: PASS** — fixture schema is byte-for-byte schema-compatible and its rows are realistic copies of observed production data (incl. a real CVE and real run_ids); the one anomaly is upstream production data, correctly NOT copied into the fixture.

---

## 3. LIVE verification (verbatim output)

### 3.1 Mandated targeted test runs (from repo root)

```
$ uv run pytest -q tests/test_pentestcore.py tests/test_scope.py tests/test_scope_authz.py
.................................                                        [100%]
33 passed in 1.14s
```

```
$ uv run pytest -q tests/test_pentestcore.py
..................                                                       [100%]
18 passed in 1.82s
```

### 3.2 py_compile

```
$ python -m py_compile intected/pentestcore.py intected/scope.py intected/cli.py tests/test_pentestcore.py
py_compile OK
```

### 3.3 Independent enforcement probes (scratch DBs in Temp; backup opened read-only)

Standalone probe (`Temp/p4audit_probe.py`, deleted after run) — 21 PASS / 1 probe-threshold artifact / 0 real FAIL:

```
PASS 22  FAIL 1  WARN 0
  [PASS] A1 fixture==real schema (cols/type/notnull/default/pk): runs/findings/audit identical
  [PASS] A2 column order identical
  [PASS] B1 fixture JSON columns parse to lists: 3 rows, bad=[]
  [PASS] B2 fixture evidence sha256 64-hex: 2/2 sha256 entries hex
  [PASS] C1 real DB JSON columns parse to lists: 177 rows sampled, bad=[]
  [FAIL] C2 real DB evidence sha256 64-hex: 176 sha256 entries (177 findings)   <-- probe bug, see note
  [PASS] C3 fixture CVE-2026-44631 exists in real DB: 4 real rows
  [PASS] C4 PC_SEVERITIES == real distinct severities: real=['critical', 'high', 'info', 'low', 'medium']
  [PASS] D1 out-of-scope write rejected: count unchanged
  [PASS] D2 empty-hosts mission denied: count unchanged
  [PASS] D3 bad severity rejected: count unchanged
  [PASS] D4 read-only connect() rejects INSERT
  [PASS] D5 in-scope write succeeds + audit: fid=4
  [PASS] E1 string 'true' aggressive denied
  [PASS] E2 strict True unlocks destructive marker
  [PASS] E3 gated tool denied by default
  [PASS] E4 authorized gated tool passes
  [PASS] F1 sync imports + idempotent: added=3 then 0 skipped=3
  [PASS] F2 evidence_ref + sha256 carried into facts: ev=raw/nmap-vuln.xml
  [PASS] F3 sync real DB run works read-only: added=16
  [PASS] G1 raw saved before parse + sha256
  [PASS] G2 verify_evidence re-hash matches
  [PASS] G3 parsed facts carry evidence_ref+sha256: facts=8
```

**Note on the single [FAIL]**: probe threshold expected 177 sha256 entries but the real DB legitimately has 176 evidence entries — one real finding (id 177) has `evidence='[]'` (§2.3). Re-check with corrected SQL: **176/176 real evidence entries carry valid 64-hex sha256; zero invalid hashes**. Not a code or fixture defect.

### 3.4 End-to-end sync from the real backup (read-only)

```
$ python (read-only; pentestcore.connect() on the backup, sync_run into a scratch INTECTED db)
sync of real run "run-linux2" (localhost:8001, lab-dvwa-auth.yaml): facts_added=16
facts carry evidence_ref=raw/... + real sha256; second sync of same run adds 0
```

---

## 4. Verdict table

| # | Checklist item | Verdict | Evidence |
|---|---|---|---|
| 1 | NO-SIMULATION — no canned/fake data | **PASS** | §1.1; 0 fake-CVE hits; no `Finding(` sites; pentestcore data only from sqlite rows |
| 2 | EVIDENCE-FIRST — raw saved+hashed before findings | **PASS** (advisory W1) | §1.2; `parsing/__init__.py:51-60,76-105`; `pentestcore.py:160-198`; live G1-G3 |
| 3 | Scope gate integrity (write_finding double gate) | **PASS** | §1.3; `pentestcore.py:233-241`, `scope.py:114-121,124-164`; live D1-D5, E1-E4 |
| 4 | Risk-category gates deny by default | **PASS** | `scope.py:31-36,141-152`; live E3-E4; tests `test_scope_authz.py` |
| 5 | Strict-boolean aggressive approval | **PASS** | `scope.py:135-140`; live E1-E2; `test_scope.py:44-53` |
| 6 | HONEST REPORTING | **PASS** | §1.4; `pentestcore.py:202-203`; `cli.py:273-275,393-395` |
| 7 | Fixture schema == real schema | **PASS** | §2.1; PRAGMA-identical (incl. notnull/default/pk/order); probe A1-A2 |
| 8 | Fixture data realistic (JSON lists, sha256 hex, real CVEs/runs) | **PASS** | §2.2; probe B1-B2, C1-C4 |
| 9 | Read-only default; write only via explicit `connect_rw` | **PASS** | `pentestcore.py:44-81`; `cli.py:277-280`; live D4 |
| 10 | Tests real, targeted run passes | **PASS** | §3.1; 33 passed (P4 files), 18 passed (pentestcore alone); py_compile OK |
| 11 | Evidence on write-back path (W1) | **WARN** | `pentestcore.py:215-218` evidence optional; CLI has no `--evidence` flag; real row 177 is evidence-less |
| 12 | Engine not validated against arsenal catalog on write-back | **WARN** | `pentestcore.py:240-241` (non-empty only); typo'd engine lands in DB |
| 13 | run_id naming: colon vs underscore form | **WARN** | `run_id_for` colon form (`pentestcore.py:206-210`); real DB contains both forms |

---

## 5. Overall verdict: **APPROVED**

No FAIL against the four iron rules in the delivered code; the fixture is authentic (PRAGMA-identical schema + realistic data verified against the live DB backup); the double scope gate is deny-by-default and was proven live; the single "failed" probe line was an auditor threshold error, corrected (§3.3).

### Recommended fixes (non-blocking)

- **W1 (advisory):** require evidence on the write-back path — either make `write_finding` demand non-empty `evidence` (or `raw_lines`) unless explicitly waived, and add `--evidence`/`--raw-lines` flags to `intected cli.py` `pc write` (cli.py:277-290). Currently the CLI writes findings with `evidence='[]'`, and real production row 177 (`SQLi re-verified`, no evidence) shows this already happens upstream. If write-back is meant to be operator-certified rather than evidence-backed, document that explicitly in the module docstring.
- **W2:** validate `engine` against a known vocabulary (arsenal catalog or PC distinct engines) in `write_finding`, or at least warn.
- **W3:** note in docs that pentest-core run_ids are mixed-format (`run-linux2` vs `127.0.0.1:8001-…` vs `127.0.0.1_3000-…`); `run_id_for()` picks one of the observed real formats.

### Files
- Created: `docs/CONTROL-REPORT-POLICY.md` (this report). No other repo files touched; no commits.
- Deleted after use: `Temp/p4audit_probe.py` and scratch DBs.
