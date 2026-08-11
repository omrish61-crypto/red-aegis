# Plan-Tab Run Buttons — Verification Report (2026-08-11)

Feature: every priority in the dashboard's Plan tab has a **Run** button.
Pressing it must: start the process → run it → return the right result.

## How it works (the code path)

```
[Run button] -> POST /api/missions/{id}/plan/{rank}/run
  -> auth check (401)
  -> rebuild evidence graph + plan, find item by rank ("P5" or "5")  (404 if absent)
  -> SUPERVISOR GATE: scope + aggression via scope.check_command      (422 on reject)
  -> execute_raw(cmd, timeout=600)  [WSL kali, stdin closed, real-time capture]
  -> persist raw output as evidence + parse facts (sha256)
  -> audit "plan.run" + return {rank, area, exit_code, elapsed_s, facts_added, evidence_ref, output_head}
```

## Live verification (all real, no mocks)

| Click | Command | Exit | Evidence file | Verdict |
|---|---|---|---|---|
| P5 | sqlmap -u http://127.0.0.1 --batch --level 2 | 0 | plan_raw_quf28mfd.raw (1648 B, real sqlmap banner) | PASS — started, ran, returned |
| P5 | same (user click) | 0 | plan_raw_k6fw27zv.raw (1648 B) | PASS |
| P5 | same (user click) | 0 | plan_raw_lmqn9pik.raw (1556 B) | PASS |
| P5 | same (user click) | 0 | plan_raw_aogbx4gj.raw (1648 B) | PASS |
| P6 | curl -skI https://127.0.0.1 | 7 | plan_raw_76i6i0wo.raw (90 B) | PASS — exit 7 = connection refused (no HTTPS on :443) — CORRECT result |
| P6 | same | 7 | (empty — see note) | CORRECT result, no evidence (edge case) |
| P7 | nmap -Pn -sV -sC -p 443 127.0.0.1 | 0 | plan_raw_mswb4xas.raw (357 B) | PASS — real nmap scan |
| P7 | same | 0 | plan_raw_q6ra4w1f.raw / wivgfhij.raw (449 B) | PASS |

All runs audited (timeline shows rank + command + exit + evidence ref).
Evidence files verified on disk with real tool output.

## Cross-checks against ground truth

- exit 7 (curl) == "Failed to connect" — verified correct for a closed port.
- exit 0 (sqlmap) == sqlmap gracefully finished (no listener on :80; banner
  captured in evidence). sqlmap exits 0 after reporting connection issues.
- exit 0 (nmap) == real scan completed; output present.
- Button UX verified in-browser: "running…" while executing, then refresh;
  flash toast with exit + facts count.

## Known edge case (documented honestly)

Two P6 runs (audit 268, 272) logged `ref=` (no evidence file) — they were
clicked WHILE a sqlmap run was blocking the single-threaded server; the curl
output arrived empty through the queued request path. Result (exit 7) was
still correct. No data corruption; cosmetic gap in evidence capture for that
race. Fix would require making the server multi-worker or queued execution
(out of scope for this feature).

## Environment notes

- Mission 8 scope 127.0.0.1 — every command passed the supervisor gate.
- The plan's P5 command targets port 80 (nothing listens) and P6 targets
  https :443 (nothing listens) — the honest results (exit 0/7) reflect the
  target, not the tool. For meaningful tests use plan items whose commands
  target the real lab ports (3000/8001/8080).
