# CONTROL REPORT — ENGAGEMENT (G1 / G4 Stress Run)

**Control agent:** independent supervision of Worker A's `docs/ENGAGEMENT-REPORT.md`
**Date:** 2026-08-11 (audit completed ~00:50 local / 21:50 UTC)
**Repo:** `C:\Users\onris\INTECTED` — read-only audit; the only file written by this control agent is this report.
**Ground truth used (never the worker's report):**
- `~/.intected/engagement-log.jsonl` — driver JSONL (start/turn/tool/parse/note/finish events)
- `~/.intected/intected.db` — missions/tasks/facts/commands/audit (read-only `mode=ro`)
- `~/.intected/evidence/mission-3/` — on-disk evidence `.raw` files (sha256 chain of custody)

**Method:** background poller polled the JSONL every 120 s (45-iteration cap) until a `finish` event with stats appeared; then recomputed every metric independently from the JSONL + DB; then compared Worker A's report line by line.

---

## 0. Run outcome

The driver **finished successfully** — no INCOMPLETE path needed.

- `finish` event at `2026-08-10T21:37:58+00:00` (00:37:58 local) for mission **3** `ENG-OVERNIGHT-20260810-235627`: 48/48 turns, `wall_seconds: 2490.8` (41.5 min, wall-max 6000 s never triggered).
- Two launches on record: mission 2 `ENG-OVERNIGHT-20260810-235301` **crashed at turn 6** (TypeError `'str' object is not callable`, driver line 242 `rc, out = fn()`); driver script patched on disk at **23:56:22 local** (mtime verified) and relaunched as mission 3. Mission 2's 5 turns remain in the JSONL (3 dup rejections, 1 completed-guard, 1 approval — consistent with the report's Honest Failures section).
- 0 `parse_error` events, 0 `reasoning_error` events across the whole log.

---

## 1. Verdict table

| # | Item | Verdict | Evidence (ground truth) |
|---|---|---|---|
| 1 | Driver completed 40+ turn run | **PASS** | `finish` event: turns 48/48; 48 consecutive `turn` events in JSONL; wall 2490.8 s < 6000 s max |
| 2 | **G1** — zero-duplicate command execution over 40+ turns | **PASS** | 17 `rejected` turns with reason `duplicate of an existing/previous command (anti-loop)` (mission 3) + 3 more in crashed mission 2; **22/22 approved commands are unique** (22 distinct `cmd_preview` values, 0 repeats); DB `commands`: 22 rows, all `state=proposed`, none executed |
| 3 | **G4** — digest context rollover over 40+ messages | **PASS** | digest_chars 674 (turn 1) → 3366 (turn 48), +399 %; continuous accumulation with small rollover dips (max dip 105 chars at turn 34), **no window reset/truncation**; 8/8 phase boundaries crossed; max digest 3366 at 48 turns; longest single reasoning call ~9 min (turn 36, max digest) |
| 4 | Driver self-reported stats honest | **PASS** | `finish.stats` (turns 48, dup 17, oos 0, agg 0, comp_guard 1, approved 22, wall 2490.8, tasks 12, tasks_completed 10, facts 13, commands_by_state proposed:22) **matches my independent recomputation exactly** |
| 5 | Facts count & sha256 chain of custody | **PASS** | 7 `parse` events sum to 13 facts = DB `facts` (mission 3) = 13 rows, all confidence 1.0; all 7 evidence `.raw` files in `~/.intected/evidence/mission-3/` hash to the exact `sha256[:16]` in the parse events and DB rows |
| 6 | Per-phase tool/parse table | **PASS** | All 8 phases verified: exit codes (0/0/0/0/0/124/3/0), seconds (14.1/1.5/1.5/156.0/189.3/480.0/1.9/13.2), facts (4/0/0/5/0/—/0/4), warnings (0/2/95/0/2/—/0/0), sha256s — all match JSONL `tool`+`parse` events; sqlmap timeout (exit 124, 480 s, output 21 chars) correctly excluded from facts; zap exit 3 (`/zap/wrk` not mounted) documented |
| 7 | Audit-table counts | **PASS** | Global audit: `next_step`=51, `command.propose`=25, `task.create`=16, `task.status`=67, `mission.create`=3, `evidence.parse`=1, `update.skipped`=1 — **all match the report exactly**; exactly 3 `next_step` rows embed the mission name in `detail` (report's claim correct) |
| 8 | Honest-failure reporting | **PASS** | Launch-1 crash traceback, patch mtime 23:56, sqlmap timeout, ZAP misconfiguration, 4 zero-fact phases, `INTECTED_STATE` env note — all consistent with observable ground truth |
| 9 | Worker A deliverable exists | **PASS** | `docs/ENGAGEMENT-REPORT.md` present (11 242 bytes, written 00:40 local after driver finish at 00:37:58) |
| 10 | Worker A "Verbatim Log Excerpts" accuracy | **WARN** | §4 turn-2/turn-3 excerpts are **not verbatim** — see D1/D2; parse excerpt timestamp wrong — see D3 |
| 11 | Worker A facts-row breakdown | **WARN** | "6 nmap port/version, 5 nikto, 2 final-recheck" — actual split is 4 nmap-portscan + 5 nikto + 4 final-recheck (8 nmap rows total); total 13 correct — see D4 |
| 12 | Worker A audit attribution | **WARN** | "mission 3 ≈ 46 of 51 next_step" and "2 turns produced no audit row" — actual: **44** rows in the mission-3 window, **4** turns (14, 15, 29, 30 — all `cmd_state=none`) lack audit rows — see D5 |
| 13 | Worker A "monotonic" wording | **WARN** | Digest is *not* strictly monotonic: 6 dips at turns 26/33/34/36/39/46 (max −105 chars) — rollover compaction; the substance (no reset, 674→3366) is correct — see D6 |
| 14 | Mission lifecycle hygiene | **WARN** (informational) | missions 2 and 3 remain `status='active'` in DB (never closed); no impact on metrics |

---

## 2. Independently computed G1 / G4 numbers (control's own computation)

### G1 — zero-duplicate
| Metric | Mission 3 | Mission 2 (crashed) | Combined |
|---|---|---|---|
| Turns logged | 48 | 5 | 53 |
| Duplicate proposals rejected (`cmd_reason` contains "duplicate") | **17** | 3 | **20** |
| Completed-guard rejections ("target task already completed") | 1 | 1 | 2 |
| Out-of-scope rejections | 0 | 0 | 0 |
| Aggressive-flag rejections | 0 | 0 | 0 |
| Other rejections | 0 | 0 | 0 |
| Commands approved | 22 | 1 | 23 |
| **Approved commands that are unique** | **22 / 22** | 1 / 1 | **23 / 23** |
| Turns with no command (`cmd_state=none`) | 8 | 0 | 8 |

**G1 = PASS.** Every re-proposal of a known command was rejected by the anti-loop guard (20 rejections across both launches, 0 duplicates ever approved or persisted as executed; DB `commands` holds 22 `proposed` rows only).

### G4 — 40+ message context-rollover stress
| Metric | Value |
|---|---|
| Turns executed (planned) | **48 / 48** (> 40) |
| Wall seconds | **2490.8** (41.5 min; wall-max 6000 s not hit) |
| Digest chars turn 1 → turn 48 | **674 → 3366** (+399 %) |
| Digest max (any turn) | 3366 (turn 48) |
| Digest dips (rollover compaction, no reset) | 6 — turns 26 (−1), 33 (−52), 34 (−105), 36 (−15), 39 (−1), 46 (−1) |
| Longest single turn latency | ~9 min (turn 36, at max digest; reasoning still functional) |
| Phase boundaries crossed without digest collapse | 8 / 8 |
| `parse_error` / `reasoning_error` events | **0 / 0** (honest failures to count: none) |
| Per-phase parsed facts + sha256[:16] | nmap-portscan 4 `c11fda53001d9d08` · gobuster-dvwa 0 `d1b2b64713d46cf4` · ffuf-juice 0 `5c883c0908002a08` · nikto-dvwa 5 `5f1cec9dabf31802` · nuclei-dvwa 0 `3d2499e82aa5bdf5` · sqlmap-dvwa — (timeout 124, no parse) · zap-baseline 0 `65104def84606ed1` · final-recheck 4 `0a2585962281387e` → **13 facts total** = DB |

**G4 = PASS.** Context rolled forward across 48 consecutive reasoning turns with no truncation or window reset; digest grew 5× while the engine continued producing valid proposals and rejecting duplicates; 0 reasoning/parse errors.

---

## 3. Discrepancy table — Worker A's report vs ground truth

| # | Report claim (location) | Ground truth (verified) | Severity |
|---|---|---|---|
| D1 | §4 "verbatim" turn 2: preview `nmap -sV -p- 127.0.0.1 localhost host.docker.internal`, objective "Initial reconnaissance of allowed local targets", ts `20:56:40`, open_questions 2 | Actual mission-3 turn 2: preview `nmap -p- -sV -T4 127.0.0.1 -oN /tmp/nmap_full_127_0_0_1.txt`, objective "Initial discovery against local scope", ts `20:56:54`, open_questions 1. The printed preview/objective/open_questions are **mission 2's** turn 2; ts is mission 3 turn 1's. Excerpt is a conflation, not verbatim. | **WARN** (claims "verbatim, real"; underlying G1 narrative — duplicate of an approved command rejected next turn — is still true in the real log) |
| D2 | §4 "verbatim" turn 3: preview `nmap -sV -p- 127.0.0.1 localhost host.docker.internal`, objective "Initial reconnaissance of allowed local targets", ts `20:56:52` | Actual mission-3 turn 3: preview `nmap -p- -sV -T4 127.0.0.1 -oN /tmp/nmap_full_127_0_0_1.txt`, objective "Run an Nmap full port/service scan against 127.0.0.1", ts `20:57:05`. Same mission-2 conflation as D1. | **WARN** |
| D3 | §4 "verbatim" parse (turn 6): ts `2026-08-10T20:58:44+00:00` | Actual parse event ts: `2026-08-10T20:57:27+00:00` (77 s earlier; 20:58:44 is actually turn 7's timestamp). facts 4 / warnings 0 / sha256 correct. | **WARN** |
| D4 | §2: "DB facts (13 rows: 6 nmap port/version, 5 nikto, 2 final-recheck)" | DB facts mission 3: **4** rows nmap-portscan (sha `c11fda…`), **5** nikto (`5f1cec…`), **4** rows final-recheck (`0a2585…`) = 13. Nmap total is 8, not 6; final-recheck is 4, not 2. Total and sha linkage correct. | **WARN** (minor; §2 per-phase table itself has the correct 4/5/4) |
| D5 | §2 note + §5 item 5: "mission 3 ≈ 46 of the 51 global next_step rows"; "2 of those turns also produced no next_step audit row" | 51 = 2 (ENG-LAB) + 5 (mission 2) + **44** (mission 3 window). **4** turns lack audit rows: 14, 15, 29, 30 — all `cmd_state=none`. (The 8 `none` turns: 8, 14, 15, 21, 29, 30 and 2 others; only 14/15/29/30 lack rows.) | **WARN** (report itself flags the attribution as approximate, but the stated numbers are off by 2) |
| D6 | §1 + §3: digest "grew monotonically 674 → 3366"; "Monotonic accumulation with no window reset" | 6 non-monotonic dips (turns 26, 33, 34, 36, 39, 46; max −105 chars at 34). First→last growth and no-reset claims are correct. | **WARN** (wording only; §3 series table itself is 48/48 verbatim-correct) |
| — | All other §2 metrics, §1 verdicts, per-phase table, evidence hashes, audit counts, honest-failure narrative | Match ground truth exactly (see verdict table rows 1–9) | PASS |

**Digest series check:** Worker A's §3 48-value series matches the JSONL **verbatim for all 48 turns** (programmatic comparison, zero diffs). Approved-command uniqueness (22/22), sha256 chain, evidence files (7 `.raw`), and all finish stats also verified exact.

---

## 4. Overall verdict

# **APPROVED** (G1 PASS, G4 PASS) — with WARN-level documentation corrections

- The driver genuinely completed 48/48 turns (41.5 min) with zero reasoning/parse errors; G1 (zero duplicate execution) and G4 (40+ message context rollover) are **confirmed independently** and match the report's verdicts.
- All core numbers in Worker A's report match ground truth. Six minor discrepancies (D1–D6) concern **presentation precision** (two mislabeled "verbatim" excerpts, a facts-row split, an audit-attribution approximation, and the word "monotonic"); **none changes any metric or verdict**.
- Recommendations (no repo changes made by this control agent):
  1. Fix D1–D3: re-copy the turn-2/turn-3/parse excerpts from `engagement-log.jsonl` (they currently blend mission-2 content into mission 3's section).
  2. Fix D4: "4 nmap-portscan + 5 nikto + 4 final-recheck = 13" (or "8 nmap total").
  3. Fix D5: mission 3 = 44 of 51 `next_step` rows; 4 turns (14/15/29/30) without audit rows.
  4. Replace "monotonic" with "continuous accumulation with rollover compaction (6 small dips)".
  5. Optionally close missions 2/3 (`status='active'` in DB).
- No INCOMPLETE condition: the run finished; no fabrication of results was found — the only accuracy issue is excerpt transcription.

*Control agent note: audit performed read-only (sqlite `mode=ro`, JSONL reads, sha256 of evidence files). No git operations, no processes launched, no repo files modified except this report.*
