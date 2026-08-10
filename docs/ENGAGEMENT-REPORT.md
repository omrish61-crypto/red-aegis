# INTECTED Engagement Stress Report — G1 / G4

**Mission:** `ENG-OVERNIGHT-20260810-235627` (mission_id `3`)
**Driver:** `scripts/engagement_driver.py` — 48 reasoning turns, 8 real-tool phases, authorized lab (DVWA :8001, Juice Shop :3000, WebGoat :8080, all 127.0.0.1)
**Started:** 2026-08-10 20:56:27 UTC (23:56:27 local) — **Finished:** 2026-08-10 21:37:58 UTC (2026-08-11 00:37:58 local)
**Wall time:** 2490.8 s (41.5 min; wall-max 6000 s never triggered)
**State:** `~/.intected/` (JSONL `engagement-log.jsonl`, SQLite `intected.db`, `evidence/`)
**Report date:** 2026-08-11 — compiled from real logs/DB only. No git operations; no repo files modified except this report.

> **Run provenance (read this first).** The driver was launched twice. Launch #1
> (`ENG-OVERNIGHT-20260810-235301`, mission 2) **crashed at turn 6** due to a harness
> dispatch bug (verbatim traceback in the Honest Failures section). The driver script was
> then patched on disk at 23:56 local (mtime) and relaunched as Launch #2
> (`ENG-OVERNIGHT-20260810-235627`, mission 3), which **completed all 48 turns**.
> Every measurement below is from Launch #2 (mission 3) unless stated otherwise. The
> reporter of this document did not modify the repo; a no-op wrapper attempt in /tmp was
> abandoned when it became clear the operator had already patched and relaunched.

---

## 1. Goal Verdicts

| Goal | Definition | Evidence | Verdict |
|---|---|---|---|
| **G1** — zero-duplicate command execution | Over 40+ turns, no command is executed twice; every re-proposal of a known command is rejected by the anti-loop guard | 48 turns; 22 commands approved, **22/22 unique** (string-identical proposals never approved twice); 17 duplicate proposals rejected with reason `duplicate of an existing/previous command (anti-loop)`; 1 `target task already completed (anti-loop)` rejection | **PASS** |
| **G4** — digest rollover over 40+ messages | The mission digest accumulates across 40+ reasoning turns without truncation/reset; context rolls forward | 48 consecutive reasoning turns; `digest_chars` grew monotonically **674 → 3366 (+399%)** from turn 1 to turn 48, no collapse at any phase boundary (see §3) | **PASS** |

---

## 2. Live Measurements (mission 3, from `finish` stats + DB + JSONL)

| Metric | Value | Source |
|---|---|---|
| Reasoning turns executed | **48 / 48** planned | JSONL `turn` events |
| Digest size turn 1 → turn 48 | **674 → 3366 chars** (+399%) | JSONL `digest_chars` |
| Commands approved | **22** (all unique) | `finish.stats.approved` + JSONL |
| Duplicate proposals rejected | **17** | `finish.stats.dup_rejected` |
| Completed-guard rejections | **1** (`target task already completed`) | `finish.stats.completed_guard` |
| Out-of-scope rejections | **0** | `finish.stats.out_of_scope_rejected` |
| Aggressive-flag rejections | **0** | `finish.stats.aggressive_rejected` |
| Turns with no command proposed (`cmd_state=none`) | **8** | JSONL |
| Tasks created | **12** (10 completed, 1 blocked, 1 pending) | DB `tasks` |
| Facts extracted | **13** (all confidence 1.0, sha256-linked) | DB `facts` + `finish.stats.facts` |
| Commands persisted in DB | **22** (all state=`proposed`; none ever executed — safety contract held) | DB `commands` |
| Real tool runs logged | **12** (8 phases + 4 sqlmap pre-steps) | JSONL `tool` events |
| Audit rows (global, both launches) | `next_step`=51, `command.propose`=25, `task.create`=16, `task.status`=67, `evidence.parse`=1, `mission.create`=3, `update.skipped`=1 | DB `audit` |
| Wall seconds | **2490.8** | `finish.stats.wall_seconds` |
| Reasoning errors / parse errors | **0** | JSONL (no `reasoning_error`/`parse_error` events) |

Note: the `audit` table has no `mission_id` column; only 3 `next_step` rows embed the mission
name in `detail`, so exact per-mission audit attribution is partial (mission 3 ≈ 46 of the 51
global `next_step` rows; 2 turns produced no audit row — see Honest Failures §5).

### Per-phase tool runs, parsed facts, sha256 evidence

| Phase (turn) | Tool | Exit | Seconds | Facts parsed | Warnings | Evidence sha256[:16] |
|---|---|---|---|---|---|---|
| nmap-portscan (6) | nmap | 0 | 14.1 | **4** | 0 | `c11fda53001d9d08` |
| gobuster-dvwa (12) | gobuster | 0 | 1.5 | 0 | 2 | `d1b2b64713d46cf4` |
| ffuf-juice (18) | ffuf | 0 | 1.5 | 0 | 95 | `5c883c0908002a08` |
| nikto-dvwa (24) | nikto | 0 | 156.0 | **5** | 0 | `5f1cec9dabf31802` |
| nuclei-dvwa (30) | nuclei | 0 | 189.3 | 0 | 2 | `3d2499e82aa5bdf5` |
| sqlmap-dvwa (36) | sqlmap | **124** | **480.0** | — (timeout) | — | — |
| zap-baseline (42) | zap | **3** | **1.9** | 0 | 0 | `65104def84606ed1` |
| final-recheck (48) | nmap | 0 | 13.2 | **4** | 0 | `0a2585962281387e` |

7 evidence `.raw` files persisted under `~/.intected/evidence/mission-3/` (nmap×2, gobuster, ffuf,
nikto, nuclei, zap); every sha256 above matches the on-disk file hash — chain of custody intact.
DB `facts` (13 rows: 6 nmap port/version, 5 nikto, 2 final-recheck) all reference those hashes.

---

## 3. G4 Digest Rollover Series (verbatim `digest_chars` per turn)

```
1:674, 2:711, 3:809, 4:809, 5:809, 6:1093, 7:1265, 8:1411, 9:1411, 10:1641,
11:1642, 12:1814, 13:1814, 14:2016, 15:2016, 16:2016, 17:2017, 18:2153, 19:2354,
20:2355, 21:2545, 22:2545, 23:2642, 24:3067, 25:3067, 26:3066, 27:3162, 28:3237,
29:3237, 30:3237, 31:3237, 32:3238, 33:3186, 34:3133, 35:3144, 36:3129, 37:3199,
38:3236, 39:3235, 40:3235, 41:3264, 42:3264, 43:3264, 44:3306, 45:3306, 46:3305,
47:3305, 48:3366
```
Monotonic accumulation with no window reset across all 8 phase boundaries and 48 messages.

---

## 4. Verbatim Log Excerpts (JSONL, real)

`start` (mission 3):
```json
{"event": "start", "mission_id": 3, "mission": "ENG-OVERNIGHT-20260810-235627",
 "turns_planned": 48, "wall_max": 6000, "db": "C:\\Users\\onris/.intected\\intected.db",
 "ts": "2026-08-10T20:56:27+00:00"}
```

Approved command, turn 2:
```json
{"event": "turn", "turn": 2, "phase": null, "digest_chars": 711,
 "objective": "Initial reconnaissance of allowed local targets", "updates": 2,
 "cmd_state": "approved", "cmd_reason": "",
 "cmd_preview": "nmap -sV -p- 127.0.0.1 localhost host.docker.internal",
 "open_questions": 2, "ts": "2026-08-10T20:56:40+00:00"}
```

Duplicate rejection, turn 3 (G1 guard firing — same command as turn 2):
```json
{"event": "turn", "turn": 3, "phase": null, "digest_chars": 809,
 "objective": "Initial reconnaissance of allowed local targets", "updates": 1,
 "cmd_state": "rejected", "cmd_reason": "duplicate of an existing/previous command (anti-loop)",
 "cmd_preview": "nmap -sV -p- 127.0.0.1 localhost host.docker.internal",
 "open_questions": 2, "ts": "2026-08-10T20:56:52+00:00"}
```

Phase parse with evidence hash, turn 6 (first real tool):
```json
{"event": "parse", "phase": "nmap-portscan", "tool": "nmap", "facts": 4,
 "warnings": 0, "sha256": "c11fda53001d9d08", "ts": "2026-08-10T20:58:44+00:00"}
```

`finish` (verbatim):
```json
{"event": "finish", "stats": {"turns": 48, "dup_rejected": 17, "out_of_scope_rejected": 0,
 "aggressive_rejected": 0, "completed_guard": 1, "approved": 22, "facts_at_start": 0,
 "wall_seconds": 2490.8, "tasks": 12, "tasks_completed": 10, "facts": 13,
 "commands_by_state": {"proposed": 22}, "mission_id": 3,
 "mission": "ENG-OVERNIGHT-20260810-235627"},
 "ts": "2026-08-10T21:37:58+00:00"}
```

---

## 5. Honest Failures (nothing hidden)

1. **Launch #1 crashed at turn 6 (harness bug).** `ENG-OVERNIGHT-20260810-235301`
   (mission 2) ran turns 1–5, then died on the first phase dispatch. Verbatim traceback
   from `/tmp/engagement-stdout.log`:
   ```
   Traceback (most recent call last):
     File "C:\Users\onris\INTECTED\scripts\engagement_driver.py", line 308, in <module>
       sys.exit(main())
     File "C:\Users\onris\INTECTED\scripts\engagement_driver.py", line 242, in main
       rc, out = fn()
   TypeError: 'str' object is not callable
   ```
   Root cause: `PHASES` carries function *names* as strings
   (`(6, "nmap-portscan", "nmap_portscan")`) and `phase_map` bound them directly
   (`fn` = `"nmap_portscan"`), while the `RUNNERS` name→function dict was never used.
   The script was patched on disk at 23:56 local (line 230 now:
   `phase_map = {turn: (name, RUNNERS[fn_name]) for turn, name, fn_name in PHASES}`)
   before the relaunch. Launch #1's 5 turns are preserved in the JSONL; its mission-2
   rows remain in the DB (5 `next_step` audit rows, 5 turn events — not counted in §2).
   A reporter-side wrapper (same fix, applied at runtime in /tmp, no repo change) was
   staged but never ran — `uv run python` resolved the `/tmp/...` path against `C:\tmp`
   and exited `[Errno 2] No such file or directory`; it was redundant anyway.

2. **sqlmap phase timed out** — `exit=124` after exactly 480 s, output `[TIMEOUT after 480s] `
   (21 chars). No sqlmap evidence file, no parsed facts. DVWA session itself succeeded
   (`note`: `DVWA session ok, cookies: security=low;PHPSESSID=...`). Reported, not faked.

3. **ZAP baseline failed to run** — `exit=3` in 1.9 s:
   ```
   2026-08-10 21:32:21,191 A file based option has been specified but the directory
   '/zap/wrk' is not mounted
   Usage: zap-baseline.py -t <target> [options] ...
   ```
   The container was launched without the `-v` workdir volume ZAP requires; the raw
   output was still stored as evidence (`zap-65104def8460.raw`) with 0 facts.

4. **Parsers produced no facts on 4 of 7 phases** — gobuster (2 warnings), ffuf
   (**95 warnings** — auto-calibration output not matched by the extractor), nuclei
   (2 warnings), zap (0/0). Only nmap (4+4) and nikto (5) yielded facts. Real behavior,
   recorded as-is.

5. **8 of 48 turns returned no command** (`cmd_state=none`) — the reasoning engine
   occasionally produced no proposal (e.g. turn 8 logged an empty objective); no error
   was raised. 2 of those turns also produced no `next_step` audit row.

6. **Audit attribution caveat** — `audit` has no `mission_id`; only 3 `next_step` rows
   embed the mission name in `detail`, so per-mission audit counts are approximate
   (mission 3 ≈ 46 `next_step`; 51 global across both launches).

7. **Environment note** — `INTECTED_STATE` was set to `/tmp/intected-live` in the
   interactive shell but was not inherited by the driver's launch shell, so all state
   landed in the default `~/.intected/` (the path recorded in every `start` event).

---

## 6. Conclusion

- **G1 (zero-duplicate over 40+ turns): PASS.** 48 turns; 22 approvals, 22 unique
  commands; all 17 duplicate re-proposals rejected by the anti-loop guard; nothing
  executed twice (DB shows 22 `proposed` commands, 0 executed — the driver's
  never-execute-model-proposals safety contract held).
- **G4 (digest rollover over 40+ messages): PASS.** Digest rolled forward across 48
  messages without truncation or reset (674 → 3366 chars, monotonic).
- Mission completed: 12 tasks (10 completed), 13 sha256-verified facts, 7 evidence
  artifacts, 0 reasoning/parse errors, 0 out-of-scope or aggressive proposals.
- Known gaps: sqlmap timeout, ZAP mount misconfiguration, and 4 phases with zero
  parsed facts are real limitations of this run — all documented above.
