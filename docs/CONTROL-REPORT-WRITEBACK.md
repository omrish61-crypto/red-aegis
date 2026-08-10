# CONTROL-REPORT-WRITEBACK — Supervision of Worker C's Live Write-Back

**Control agent:** independent supervision, read-only on all DBs (no writes to pentest.db or intected.db)
**Date:** 2026-08-11
**Subject:** Worker C's operator-authorized live write-back into production pentest-core DB
**Report audited:** `docs/WRITEBACK-LIVE.md` (Worker C, 2026-08-10 23:55)
**Method:** every claim re-measured independently by the control agent — no reliance on the worker's transcript.

---

## 1. Poll / readiness

| Condition | Required | Observed | Status |
|---|---|---|---|
| `docs/WRITEBACK-LIVE.md` present | yes | Present, 6,385 bytes, mtime 2026-08-10 23:55 | PASS |
| WB-LIVE-* mission in `~/.intected/intected.db` | task spec | **Not present** — that DB holds ENG-LAB + ENG-OVERNIGHT-* missions only | WARN (see §5) |
| WB-LIVE-* mission in actual session state DB (`/tmp/intected-live/intected.db`, the documented `INTECTED_STATE` redirect) | yes | `id=2 name='WB-LIVE-20260810-235455'` allowed_hosts=`["127.0.0.1","localhost","host.docker.internal"]` auth_ref=`AUTH-OVERNIGHT-20260811` status=active created=`2026-08-10 20:54:55` | PASS |

---

## 2. Verdict table

| Check | Verdict | Evidence (control agent's own measurements) |
|---|---|---|
| Pre-flight DB state | PASS | pentest.db exists (2,199,552 B) with WAL+SHM; `PRAGMA journal_mode`=`wal`; `PRAGMA integrity_check`=`ok`; tables `runs/findings/audit/sqlite_sequence`; counts runs=36 findings=413 audit=163 |
| Write (finding row present) | PASS | Finding **id=413** physically read from production DB read-only — full row in §3 |
| Run row present | PASS | `runs` row `127.0.0.1:8001-20260810-205514` exists: target=`127.0.0.1:8001`, started=`2026-08-10T20:55:14+00:00` |
| No orphan FKs | PASS | `SELECT ... FROM findings WHERE run_id NOT IN (SELECT run_id FROM runs)` → **0 rows** |
| Integrity | PASS | `PRAGMA integrity_check` → `ok`; `journal_mode` → `wal` (unchanged); WAL 0 bytes / SHM present = clean checkpoint state |
| Counts consistency | PASS | findings=413 (= sqlite_sequence findings=413), runs=36, audit=163 (= sqlite_sequence audit=163); severity buckets info=234, medium=85, **low=50**, high=27, critical=17 → low 49→50 delta as claimed; run row has exactly 1 finding (low=1) |
| Evidence authenticity | PASS | Control agent independently re-ran `nmap -sV -Pn -p 8001 127.0.0.1` from kali-linux: `8001/tcp open  http    Apache httpd 2.4.25 ((Debian))` — byte-identical banner to the finding's detail. Not fabricated. |
| Daemon health (Windows) | PASS | `netstat -ano | grep 9292` → `TCP 127.0.0.1:9292 LISTENING` pid **18620**; `tasklist` → **wslrelay.exe** (matches worker claim) |
| Daemon health (WSL) | PASS | `wsl -d kali-linux -u root -e bash -lc "ss -tlnp | grep 9292"` → `LISTEN 0 100 127.0.0.1:9292` |
| INTECTED audit trail | PASS | `/tmp/intected-live/intected.db` audit id=31: `2026-08-10 20:55:14 cli pentestcore.write_finding run=127.0.0.1:8001-20260810-205514 target=127.0.0.1:8001 engine=nmap severity=low title='Apache httpd 2.4.25 (Debian) on 127.0.0.1:8001' finding=413` — matches report §5e verbatim; mission.create (id=30) also present |
| pentest-core audit untouched | PASS | pentest-core `audit` table count=163, latest events (`mission_end`, `engine_done`) predate the write-back — write path correctly did not touch it |

---

## 3. Actual finding row read from production DB (read-only, `file:...?mode=ro`)

```sql
SELECT id, run_id, engine, type, severity, cvss, cwe, cve, title, target, port, path, detail, evidence, raw_lines, timestamp
FROM findings WHERE id=413;
```

| Field | Value (as read by control agent) |
|---|---|
| id | **413** |
| run_id | `127.0.0.1:8001-20260810-205514` |
| engine | `nmap` |
| type | `finding` |
| severity | `low` |
| cvss / cwe / cve | `NULL` / `[]` / `[]` |
| title | `Apache httpd 2.4.25 (Debian) on 127.0.0.1:8001` |
| target | `127.0.0.1:8001` |
| port | `NULL` (port only in target string; `--port` not passed — as documented) |
| path | `''` |
| detail | `8001/tcp open  http    Apache httpd 2.4.25 ((Debian)) (nmap -sV -Pn -p 8001 127.0.0.1, 2026-08-10)` |
| evidence / raw_lines | `[]` / `[]` |
| timestamp | `2026-08-10T20:55:14+00:00` |

Run row (read-only): `run_id='127.0.0.1:8001-20260810-205514'`, `target='127.0.0.1:8001'`, `started='2026-08-10T20:55:14+00:00'`, `finished=NULL`, `mission_file=NULL`.

---

## 4. Discrepancy table vs Worker C's report (`docs/WRITEBACK-LIVE.md`)

| # | Claim in report | Control measurement | Verdict |
|---|---|---|---|
| 1 | Mission WB-LIVE-20260810-235455 (id 2) created in state DB | Found in `/tmp/intected-live/intected.db` (INTECTED_STATE redirect), **not** in `~/.intected/intected.db` | CONSISTENT — worker disclosed the redirect in caveat 3; mission exists, active, scope-correct |
| 2 | Pre-write counts runs=35, findings=412, audit=163 → post 36/413/163 | Post-write measured 36/413/163; deltas exactly as claimed; audit unchanged at 163 | CONSISTENT |
| 3 | Finding 413 content (engine/title/severity/target/timestamp/port=NULL/detail) | Byte-identical read-back (§3) | CONSISTENT |
| 4 | low severity bucket 49→50 | Measured low=50 post-write; run carries exactly 1 low finding | CONSISTENT |
| 5 | Daemon pid 18620 `wslrelay.exe` on :9292, WSL-side listener up | Both re-verified: pid 18620 = wslrelay.exe LISTENING; WSL `ss` LISTEN | CONSISTENT |
| 6 | App-level WS ping inconclusive (daemon silent to unknown protocol) | Not re-tested (write path is DB-file direct, socket irrelevant); report's honest caveat accepted | CONSISTENT (no contradiction) |
| 7 | Audit event `pentestcore.write_finding ... finding=413` | Found verbatim in session state DB audit id=31 | CONSISTENT |
| 8 | Evidence line `8001/tcp open  http  Apache httpd 2.4.25 ((Debian))` | Control re-scan returned the identical banner | CONSISTENT (real evidence) |
| 9 | **Task-spec poll path** `~/.intected/intected.db` contains WB-LIVE mission | **FALSE in that DB** — it holds ENG-LAB, ENG-OVERNIGHT-20260810-235301, ENG-OVERNIGHT-20260810-235627 instead | WARN — spec/location mismatch, fully explained by the worker's documented `INTECTED_STATE` override; no impact on write correctness (scope gate used same state dir) |

**No factual discrepancies found in any claim the worker made.** The single WARN is a difference between the task's assumed state-DB location and the environment override the worker used and documented.

---

## 5. Notes / observations

- `~/.intected/intected.db` and `engagement-log.jsonl` have mtime 2026-08-11 00:06 — later than the write-back (23:55). Likely parallel-session activity (ENG-OVERNIGHT missions in that DB are contemporaneous with WB-LIVE). Does not affect the verified production row.
- WAL file is 0 bytes with SHM present — clean post-checkpoint state; journal_mode still `wal` as required.
- No git operations performed by either worker or control agent; only file written by control agent: this report.

---

## 6. Overall verdict

# ✅ APPROVED

- The finding row (id=413) **physically exists** in the production pentest-core DB with content matching the real nmap evidence; verified read-only by the control agent independently.
- DB integrity `ok`, journal mode `wal`, zero orphan FKs, counts and severity buckets consistent, sqlite_sequence coherent.
- Daemon healthy on both sides (`wslrelay.exe` pid 18620 on Windows; `ss` LISTEN inside kali-linux).
- Worker's report is accurate: 0 factual discrepancies; the only WARN is the documented state-DB redirect vs the task's poll spec, which does not affect write correctness.

**Control agent confirms:** the write-back happened, is real, is fully verified, and the worker's documentation is trustworthy. No corrective action required.
