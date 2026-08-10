# CONTROL REPORT — Evidence Chain Verification (Dashboard: fact #14 / nikto, mission 3)

**Date:** 2026-08-11
**Scope:** Independent verification of the dashboard's evidence chain for fact #14 (nikto, mission 3 = `ENG-OVERNIGHT-20260810-235627`, mission_id 3), plus 2 spot-checked chains (nmap final-recheck facts 18–21; zap evidence file).
**Method:** Read-only only. SQLite opened via `sqlite3.connect("file:...?mode=ro", uri=True)` against `C:\Users\onris\.intected\intected.db`; file hashes computed with `sha256sum`/`hashlib`; no writes to the DB or evidence tree; no pytest; no git. `PRAGMA integrity_check` → `ok`.
**Verifier:** independent subagent (second opinion), no access to the dashboard's own code path for these rows.

## Verdict summary

| # | Item | Verdict | Evidence |
|---|------|---------|----------|
| 1 | DB row for fact id=14 exists in mission 3 | **PASS** | `tool=nikto`, `fact_type=note`, `confidence=1.0`, `value_json={"nikto_target": "127.0.0.1"}`, `evidence_ref=...\evidence\mission-3\nikto-5f1cec9dabf3.raw`, `sha256=5f1cec9dabf31802a82ecbf5dbee928f29af95f12ff88d62458555378aadc4a0` |
| 2 | On-disk file sha256 == DB sha256 == modal sha256 | **PASS** | `sha256sum nikto-5f1cec9dabf3.raw` = `5f1cec9dabf31802a82ecbf5dbee928f29af95f12ff88d62458555378aadc4a0` (exact match, all three sources identical) |
| 3 | Evidence file exists and `evidence_ref` resolves to it | **PASS** | `C:\Users\onris\.intected\evidence\mission-3\nikto-5f1cec9dabf3.raw` present (2,314 bytes, modified 2026-08-11 00:09 local = fact `created_at` 21:09:26 UTC, timezone-consistent) |
| 4 | Raw content matches the modal's raw-content description | **PASS** | See chain detail below — banner, Target IP, Server, all 5 OSVDB ids, 120 s ERROR, Start Time all present verbatim |
| 5 | Parsed-facts cross-check: sibling nikto facts (same sha256) reflect the raw | **PASS** (1 note) | Facts 13–17 all carry `sha256=5f1cec9dabf3...` and every value string appears verbatim in the raw; no OSVDB-typed fact rows exist (see Finding A) |
| 6 | Spot-check: nmap final-recheck facts 18–21 (sha256 `0a258596...`) | **PASS** | File hash matches DB sha256; all 4 fact values (port 3000, 8001 Apache banner, port 8080, Tomcat banner) appear verbatim in the raw |
| 7 | Spot-check: zap evidence file `zap-65104def8460.raw` | **WARN** | File hashes to `65104def84606ed1...f85a0` but **no DB fact or command references it**; content shows the scan never ran (usage/help output, `/zap/wrk` not mounted) — orphan artifact, not a broken chain |
| 8 | DB integrity | **PASS** | `PRAGMA integrity_check` → `ok` |

**Overall: APPROVED** — the fact #14 evidence chain (DB row ↔ file sha256 ↔ modal content ↔ parsed facts) is fully consistent. Spot-checked nmap chain also consistent. Caveats (A–D) are completeness/format notes, none of which break the fact-14 chain.

---

## 1. Fact #14 chain (nikto, mission 3)

**DB row (facts id=14, mission_id=3):**

| column | value |
|---|---|
| tool | `nikto` |
| fact_type | `note` |
| value_json | `{"nikto_target": "127.0.0.1"}` |
| confidence | `1.0` |
| evidence_ref | `C:\Users\onris/.intected\evidence\mission-3\nikto-5f1cec9dabf3.raw` (mixed separators — resolves correctly on Windows; see Finding C) |
| sha256 | `5f1cec9dabf31802a82ecbf5dbee928f29af95f12ff88d62458555378aadc4a0` |
| created_at | `2026-08-10 21:09:26` (UTC) = `2026-08-11 00:09` local (GMT+3) — matches file mtime |

**Hash:** `sha256sum` of `nikto-5f1cec9dabf3.raw` → `5f1cec9dabf31802a82ecbf5dbee928f29af95f12ff88d62458555378aadc4a0` — **identical** to the DB row and to the dashboard modal's displayed sha256. The modal's "✓ verified on disk" is corroborated independently.

**Raw content vs modal description** (all verbatim, confirmed by substring match):
- `- Nikto v2.6.0` banner ✓
- `+ Target IP:          127.0.0.1` ✓ (matches fact 14 `nikto_target`)
- `+ Server: Apache/2.4.25 (Debian)` ✓
- OSVDB findings all present: `[95]` (cookies w/o httponly), `[600050]` (Apache outdated, "current is at least 2.4.66"), `[013587]` (missing security headers), `[750500]` (directory indexing), `[006333] /login.php: Admin login page/section found.` ✓
- `+ ERROR: Host maximum execution time of 120 seconds reached` ✓
- `+ Start Time:         2026-08-11 00:06:53 (GMT3)` ✓
- File is genuine nikto output: ends with `+ 1 host(s) tested` plus real WSL wrapper noise (`wsl: Failed to start the systemd user session for 'root'`) — consistent with a real `nikto -h http://127.0.0.1:3000` run (command id 14, proposed).

**Chain integrity: DB sha256 == file sha256 == modal sha256, and value_json ↔ raw line pair confirmed. PASS.**

## 2. Parsed-facts cross-check (sibling nikto facts, same sha256 prefix `5f1cec9dabf3`)

All facts 13–17 trace to the same evidence file (same sha256, same evidence_ref) and each value appears verbatim in the raw:

| fact id | type | value_json | matches raw line |
|---|---|---|---|
| 13 | version | `{"product": "http-server", "banner": "Apache/2.4.25 (Debian)"}` | `+ Server: Apache/2.4.25 (Debian)` |
| 14 | note | `{"nikto_target": "127.0.0.1"}` | `+ Target IP:          127.0.0.1` |
| 15 | note | `{"nikto": "Platform: Linux/Unix"}` | `+ Platform:           Linux/Unix` |
| 16 | note | `{"nikto": "ERROR: Failed to check for updates: 403"}` | `+ ERROR: Failed to check for updates: 403` |
| 17 | note | `{"nikto": "ERROR: Host maximum execution time of 120 seconds reached"}` | `+ ERROR: Host maximum execution time of 120 seconds reached` |

Requirement "at least one parsed fact matches the raw" → satisfied (all five match).

## 3. Spot-check A — nmap final-recheck (facts 18–21)

- File `nmap-0a2585962281.raw` sha256 = `0a2585962281387eb20a7783a3f27d5435c6d0debb6e583ad7c7431dad965f67` — **matches DB sha256 on facts 18–21** (the expected value from the user's spot-check list).
- Raw content is a genuine `nmap -sT -sV -Pn -p 8001` run (command id 20/23 lineage) against `localhost (127.0.0.1)` at `2026-08-11 00:36 +0300` (= fact `created_at` 21:36:50 UTC — consistent).
- Fact 18 `{"port": 3000, "protocol": "tcp"}` ↔ `3000/tcp open  ppp?` ✓
- Fact 19 `{"port": 3000, "banner": "8001/tcp open  http    Apache httpd 2.4.25 ((Debian))"}` ↔ verbatim line in raw ✓ (see Finding D for the port/banner pairing quirk)
- Fact 20 `{"port": 8080, "protocol": "tcp"}` ↔ `8080/tcp open  http ...` ✓
- Fact 21 `{"port": 8080, "banner": "Apache Tomcat (language: en)"}` ↔ verbatim line ✓
- **PASS.**

## 4. Spot-check B — zap evidence file

- `zap-65104def8460.raw` exists and sha256 = `65104def84606ed191488acf258ea7d343ec57e7c6bea0fbce29863ad95f85a0` (stable, matches filename prefix).
- **No DB fact references it** (0 facts with `tool='zap'`, `evidence_ref LIKE '%zap%'`, or that sha256 — checked across ALL missions), and **no command row** (0 `commands` with `tool='zap'` in mission 3).
- Content: `zap-baseline.py` usage/help output with `A file based option has been specified but the directory '/zap/wrk' is not mounted` — the ZAP container scan never actually ran.
- **WARN**: the file is an orphaned artifact. Because no fact claims this evidence, there is no chain to break — but a dashboard entry pointing at it would be unverifiable, and the content itself records a failed scan.

## Findings (non-blocking)

- **A. No OSVDB-typed facts.** The raw contains 13 nikto items (OSVDB [95]/[600050]/[013587]/[750500]/[006333] etc.) but the parser only emitted 5 note/version facts and **no** fact encodes the OSVDB findings (0 facts in the whole DB contain `osvdb`, `login.php`, `600050`, or `006333`). The dashboard modal's raw-content display is accurate; the *structured* fact layer under-represents the scan findings. Completeness gap, not an integrity failure.
- **B. ZAP evidence orphaned** (see §4) — recommend either wiring it to a fact/command or removing it.
- **C. `evidence_ref` separator mixing** — stored as `C:\Users\onris/.intected\evidence\...` (mixed `\` and `/`). Resolves correctly on Windows; cosmetic only.
- **D. Fact 19 port/banner pairing** — banner text is the `8001/tcp` line but the fact's `port` field is `3000` (port 3000 itself shows only `ppp?`). Text is verbatim-correct; the semantic pairing is a parser choice (same pattern in facts 9–12 from the earlier nmap chain).
- **E. Timestamps** — DB `created_at` is UTC; evidence file mtimes are local (GMT+3). Offsets are consistent (21:09:26 UTC ↔ 00:09 local, etc.), so no discrepancy.
- **F. Commands table** — all mission-3 commands are `proposed` with no exit codes (execution tracked elsewhere, e.g. engagement log); not part of the evidence-chain contract under review.

## Method note

Read-only verification only: DB opened `mode=ro` (URI), no transactions; evidence files only read; `PRAGMA integrity_check` → `ok`. No pytest was run (per instructions — parent runs the suite; concurrent pytest would hang WSL probes). No git operations.
