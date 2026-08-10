# CONTROL REPORT — FIXTURES (Worker B supervision: ffuf/nikto real captures + tests + provenance)

- **Reviewer:** CONTROL agent (independent supervision of Worker B's fixture work; read-only on the repo except this report)
- **Date:** 2026-08-11 (local, supervision window 00:02–01:06)
- **Scope:** new lab captures for the ffuf/nikto extractors in `tests/fixtures/` (expected `real-ffuf-dvwa-20260811.jsonl` / `real-nikto-dvwa-20260811.txt`), extractor tests in `tests/test_parsing.py`, provenance in `tests/fixtures/README.md`, honest burp note
- **Method:** 40-iteration poll loop (sleep 90 s, 00:02→01:06, ~67 min) watching `tests/fixtures/` for `real-ffuf-*`/`real-nikto-*` files with mtime ≥ 2026-08-11; authenticity + sha256 + content sampling; verbatim test run; burp-honesty sweep of the whole repo.

---

## 1. Verdict table

| # | Item | Verdict | Evidence |
|---|------|---------|----------|
| 1 | New today-dated ffuf capture `real-ffuf-dvwa-20260811.jsonl` (or equivalent) appeared | **FAIL — not delivered** | Poll loop 40/40 iterations, `count_today_ffuf_nikto=0` every iteration (00:02→01:06). Repo-wide `find -newermt '2026-08-11' -iname 'real-ffuf*'` → 0 files. No fixture file has an mtime on 2026-08-11. |
| 2 | New today-dated nikto capture `real-nikto-dvwa-20260811.txt` (or equivalent) appeared | **FAIL — not delivered** | Same poll record. `find -newermt '2026-08-11' -iname 'real-nikto*'` → 0 files. |
| 3 | ffuf fixture that IS exercised is authentic | **PASS** | `real-ffuf-dvwa-20260810.jsonl` (mtime Aug 10 23:56): genuine ffuf 2.1.0-dev `-json` output — per-line `{"input":{"FFUFHASH":"…","FUZZ":"<base64>"},"position":N,"status":N,"length":N,"words":N,"lines":N,"content-type":"…","redirectlocation":"…","url":"http://127.0.0.1:8001/…","duration":N,…,"host":"127.0.0.1:8001"}`; 9 entries, real DVWA paths (redirects to `login.php`, `/config` 301→`/config/`, `/docs`, `/robots.txt`, `/php.ini`). Base64 FUZZ values + FFUFHASH + per-request duration = tool-generated, not synthetic. |
| 4 | nikto fixture that IS exercised is authentic | **PASS** | `real-nikto-dvwa-20260810.txt` (mtime Aug 10 23:56): genuine nikto v2.6.0 — `- Nikto v2.6.0`, `+ Target IP: 127.0.0.1`, `+ Server: Apache/2.4.25 (Debian)`, OSVDB-prefixed findings `+ [006333] /login.php: Admin login page/section found.`, `+ [600050] Apache/2.4.25 appears to be outdated (current is at least 2.4.66).`, `+ ERROR: Failed to check for updates: 403`, `+ Scan terminated: 5 errors and 13 items reported on the remote host`. |
| 5 | sha256 of each exercised fixture matches README provenance | **PASS (3/3)** | Computed now vs README-listed: `real-ffuf-dvwa-20260810.jsonl` `011f09544361837b10ac4c9d8cbb5410237bd266f04770db9473c60542f1a8e5` = `011f0954…` ✓; `real-ffuf-juiceshop-20260810.jsonl` `e19cdb5f9c082c8d459c90caaabbb3e2754a47a131c47f03f8340b960ef527ea` ✓; `real-nikto-dvwa-20260810.txt` `1dddc35684c37d33999abebb9dbf0151b080504b3847ab83da3c2dc014f2fc1a` ✓. |
| 6 | "Modified today (2026-08-11 local)" criterion | **FAIL (no fixture qualifies)** | All fixture files have mtime Aug 10 23:56 or earlier. The only 2026-08-11 changes in the repo are `intected/parsing/extractors/nikto.py` (00:43), `tests/test_parsing.py` (00:43), `tests/fixtures/README.md` (00:44) — no fixture files. |
| 7 | Extractor tests exercise the real fixtures and pass | **PASS** | Verbatim: `uv run pytest tests/test_parsing.py -q` → **34 passed in 0.49s** (baseline before Worker B: 33 passed; `.pytest_cache/v/cache/lastfailed` = `{}`). `FfufRealFixtureTest.test_dvwa_paths` / `test_juiceshop_spa_capture` and `NiktoRealFixtureTest.test_apache_banner` / `test_target_captured` / `test_osvdb_findings_parsed` call `EXTRACTORS["ffuf"/"nikto"]` on the real files; `ParsePipelineTest.test_pipeline_ffuf_real` / `test_pipeline_nikto_real` run them end-to-end through the DB with evidence_ref+sha256 structural checks. |
| 8 | Worker B's nikto extractor fix (README: gap CLOSED) is real, not cosmetic | **PASS** | `nikto.py` (00:43) adds `_OSVDB_RE` (`^\+ \[(\d+)\] …`) and `_ERROR_RE` (`^[+-] ERROR: …`), lifting `[OSVDB-id]` findings into path/note facts with `nikto_osvdb` and both ERROR signs into warnings. New test `test_osvdb_findings_parsed` asserts fact `nikto_osvdb=006333` path `/login.php`, note `600050` containing "outdated", and the time-limit warning — all green against the real 20260810 capture. README's claim is accurate. |
| 9 | README provenance honest and current | **PASS** | `tests/fixtures/README.md` (00:44): per-fixture provenance incl. exact scan commands, sha256 column matching computed hashes, "Known gaps" nikto item struck through with correct test references, burp note unchanged. |
| 10 | Burp note honest — no fabricated burp fixture | **PASS** | Repo-wide sweep: zero burp fixture files anywhere (`find -iname '*burp*'` → only `intected/parsing/extractors/burp.py` + pyc). Burp coverage is the documented-format inline sample `FormatSampleTest.test_burp_sitemap` only. README states: "No burp CLI exists in this environment … This is not faked — a real burp fixture will replace the sample when one is obtainable." Honest. |

---

## 2. What Worker B actually delivered (2026-08-11)

- `intected/parsing/extractors/nikto.py` (00:43) — OSVDB + `+ ERROR:` parsing fix (verified real, tests green).
- `tests/test_parsing.py` (00:43) — `test_osvdb_findings_parsed` added (34 total), regression coverage for the fix on the **real** 20260810 nikto capture.
- `tests/fixtures/README.md` (00:44) — provenance table intact (sha256 verified 3/3), nikto gap marked CLOSED with correct references, honest burp note preserved.

**Not delivered:** any new lab capture dated 2026-08-11 (`real-ffuf-dvwa-20260811.jsonl`, `real-nikto-dvwa-20260811.txt`, or equivalent). All exercised ffuf/nikto fixtures remain the **2026-08-10 batch** — authentic and sha256-consistent, but not created in this supervision window and therefore failing the "modified today" acceptance criterion.

## 3. Tests run verbatim

```
$ uv run pytest tests/test_parsing.py -q
..................................                                       [100%]
34 passed in 0.49s
```

(Baseline before Worker B's changes, same command: `33 passed in 0.43s`.)

## 4. Sampled real lines (authenticity evidence)

ffuf (`real-ffuf-dvwa-20260810.jsonl`, line 1):
```json
{"input":{"FFUFHASH":"MWEwNTQx","FUZZ":""},"position":1,"status":302,"length":0,"words":1,"lines":1,"content-type":"text/html; charset=UTF-8","redirectlocation":"login.php","url":"http://127.0.0.1:8001/","duration":5126812,"scraper":{},"resultfile":"","host":"127.0.0.1:8001"}
```

nikto (`real-nikto-dvwa-20260810.txt`):
```
- Nikto v2.6.0
+ Target IP:          127.0.0.1
+ Server: Apache/2.4.25 (Debian)
+ [600050] Apache/2.4.25 appears to be outdated (current is at least 2.4.66).
+ [006333] /login.php: Admin login page/section found.
+ Scan terminated: 5 errors and 13 items reported on the remote host
```

---

## Overall verdict: **NEEDS-FIX**

The primary deliverable — fresh, today-dated ffuf/nikto lab captures — **did not appear** within the 67-minute supervision window (40 polls × 90 s). The work that WAS done (nikto extractor OSVDB fix, regression tests, README provenance + honest burp note) is authentic, accurate, and fully green: 34/34 tests pass against real captures whose sha256 match the documented provenance, and no fabricated burp fixture exists. But per the acceptance criteria ("fixture modified today 2026-08-11", "new real-ffuf-* / real-nikto-* files"), the fixture deliverable itself is **missing** — Worker B reused the existing 2026-08-10 captures rather than producing new ones.

**Fix required:** Worker B must re-run `ffuf -u http://127.0.0.1:8001/FUZZ … -json` and `nikto -h http://127.0.0.1:8001 …` against the live lab (127.0.0.1:8001), save the verbatim output as `real-ffuf-dvwa-20260811.jsonl` / `real-nikto-dvwa-20260811.txt` (or equivalent 20260811 names), point the ffuf/nikto real-fixture tests at them, and update the README provenance table + sha256. No code defects were found in what was delivered.
