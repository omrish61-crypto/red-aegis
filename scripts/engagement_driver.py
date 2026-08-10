"""ENGAGEMENT DRIVER — automated 2h lab engagement through INTECTED (G1/G4 stress).

Runs REAL tools against the local authorized lab (DVWA :8001, Juice Shop :3000,
WebGoat :8080) and drives INTECTED's full pipeline: parse -> facts -> digest ->
reasoning turn (deepseek-v4-flash) -> PTM updates + command validation. Every
turn logs digest size, objective, command state (approved/rejected + reason),
task/fact counts — the raw material for the G1 (zero-duplicate) and G4
(40+ message context rollover) stress report.

Safety contract (non-negotiable):
- The driver NEVER executes model-proposed commands; it only runs its OWN
  whitelisted tool commands (real scans, no aggressive flags anywhere).
- Targets: 127.0.0.1 / localhost / host.docker.internal ONLY (mission scope).
- No faking: every tool runs for real; output is parsed by INTECTED's real
  extractors; evidence is hashed. Failures/timeouts are logged honestly.
- Budget: reasoning turns capped (default 48); cloud LLM cost is tiny.

Usage:  python scripts/engagement_driver.py [--turns 48] [--wall-max 5400]
State:  INTECTED_STATE env or default (~/.intected); mission ENG-OVERNIGHT-<ts>
Log:    <state>/engagement-log.jsonl (JSONL, one dict per line)
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intected import db, config, ptm
from intected.parsing import parse_tool_output, store_evidence
from intected.reasoning import ReasoningEngine, build_digest
from intected.scope import ScopeViolation

LAB_TARGETS = ("127.0.0.1", "localhost", "host.docker.internal")
ALLOWED = list(LAB_TARGETS)
WSL = ["wsl", "-d", "kali-linux", "-u", "root", "-e", "bash", "-lc"]
DVWA = "http://127.0.0.1:8001"
JUICE = "http://127.0.0.1:3000"
WORDLIST = "/usr/share/wordlists/dirb/common.txt"

# Phase schedule: (turn_index, phase_name, run_fn). Reasoning turns fill the gaps.
PHASES = [
    (6,  "nmap-portscan",  "nmap_portscan"),
    (12, "gobuster-dvwa",  "gobuster_dvwa"),
    (18, "ffuf-juice",     "ffuf_juice"),
    (24, "nikto-dvwa",     "nikto_dvwa"),
    (30, "nuclei-dvwa",    "nuclei_dvwa"),
    (36, "sqlmap-dvwa",    "sqlmap_dvwa"),
    (42, "zap-baseline",   "zap_baseline"),
    (48, "final-recheck",  "final_recheck"),
]

# Tester inputs per reasoning turn — varied, keeps the LLM honest (no canned
# single prompt). Rolled by turn index.
TESTER_INPUTS = [
    "What is the current objective?",
    "Summarize what we know so far. Is anything missing?",
    "Assess the findings: what is the highest-value lead?",
    "What should we do next?",
    "Is there any task we already covered that should be closed?",
    "Any risks in the current plan?",
    "Reassess the mission state and propose next step.",
    "What would you verify before concluding?",
]


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log(entry: dict):
    entry.setdefault("ts", now())
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def run_wsl(cmd: str, timeout: int, label: str) -> tuple[int, str]:
    """Run a real command in kali WSL; returns (exit_code, output)."""
    t0 = time.time()
    try:
        p = subprocess.run(WSL + [cmd], capture_output=True, text=True,
                           timeout=timeout)
        out = (p.stdout or "") + (p.stderr or "")
        rc = p.returncode
    except subprocess.TimeoutExpired as e:
        out = f"[TIMEOUT after {timeout}s] " + ((e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else str(e.stdout or ""))
        rc = 124
    dt = round(time.time() - t0, 1)
    log({"event": "tool", "phase": label, "exit": rc, "seconds": dt,
         "output_chars": len(out), "output_head": out[:300]})
    return rc, out


def run_docker_zap(timeout: int = 600) -> tuple[int, str]:
    """ZAP baseline via Docker Desktop (container -> lab via host.docker.internal)."""
    t0 = time.time()
    cmd = ["docker", "run", "--rm", "-t",
           "zaproxy/zap-stable",
           "zap-baseline.py", "-t", "http://host.docker.internal:8001",
           "-r", "/zap/zap-baseline-report.html"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "") + (p.stderr or "")
        rc = p.returncode
    except subprocess.TimeoutExpired as e:
        out = f"[TIMEOUT after {timeout}s] " + str(e)
        rc = 124
    log({"event": "tool", "phase": "zap-baseline", "exit": rc,
         "seconds": round(time.time() - t0, 1), "output_chars": len(out),
         "output_head": out[:300]})
    return rc, out


# --- phase tool runners -----------------------------------------------------

def nmap_portscan():
    return run_wsl(
        "nmap -sV -Pn -p 8001,3000,8080 --host-timeout 60s 127.0.0.1",
        120, "nmap-portscan")


def gobuster_dvwa():
    return run_wsl(
        f"gobuster dir -u {DVWA} -w {WORDLIST} -t 20 -q 2>&1 | head -120",
        300, "gobuster-dvwa")


def ffuf_juice():
    # SPA -> auto-calibrate (-ac) so wildcard 200s are filtered (real behavior)
    return run_wsl(
        f"ffuf -u {JUICE}/FUZZ -w {WORDLIST} -ac -t 20 -mc 200,204,301,302,307,401,403,500 -o - 2>&1 | head -120",
        300, "ffuf-juice")


def nikto_dvwa():
    return run_wsl(
        f"nikto -h {DVWA} -maxtime 120s -nointeractive 2>&1 | head -150",
        240, "nikto-dvwa")


def nuclei_dvwa():
    return run_wsl(
        f"nuclei -u {DVWA} -severity low,medium,high,critical -t 25 -timeout 5 "
        f"-silent -jsonl 2>&1 | head -100",
        300, "nuclei-dvwa")


def _dvwa_session() -> str | None:
    """Real DVWA login; returns cookie header or None (sqlmap needs a session)."""
    jar = "/tmp/dvwa-cookies.txt"
    run_wsl(f"rm -f {jar} && curl -s -c {jar} -m 10 {DVWA}/login.php -o /dev/null", 30, "dvwa-login-get")
    rc, out = run_wsl(
        f"curl -s -b {jar} -c {jar} -m 10 -d 'username=admin&password=password&Login=Login' "
        f"-L {DVWA}/login.php -o /dev/null -w '%{{http_code}}'", 40, "dvwa-login-post")
    if rc != 0 or out.strip() != "200":
        log({"event": "note", "phase": "sqlmap-dvwa", "detail": "DVWA login failed — sqlmap phase skipped honestly"})
        return None
    run_wsl(f"curl -s -b {jar} -c {jar} -m 10 '{DVWA}/security.php?security=low&seclev_submit=Submit' -o /dev/null", 30, "dvwa-seclev")
    rc, out = run_wsl(f"awk '{{print $6\"=\"$7}}' {jar} | grep -E 'PHPSESSID|security' | tr '\\n' '; '", 15, "dvwa-cookie")
    cookies = " ".join(out.split()).strip("; ")
    log({"event": "note", "phase": "sqlmap-dvwa", "detail": f"DVWA session ok, cookies: {cookies}"})
    return cookies or None


def sqlmap_dvwa():
    cookies = _dvwa_session()
    if not cookies:
        return 1, "DVWA session unavailable — skipped (honest)"
    target = f"{DVWA}/vulnerabilities/sqli/?id=1&Submit=Submit"
    return run_wsl(
        f"sqlmap -u '{target}' --cookie='{cookies}' --batch --level 1 --risk 1 "
        f"--flush-session --timeout 10 --retries 1 -o 2>&1 | tail -60",
        480, "sqlmap-dvwa")


def zap_baseline():
    return run_docker_zap()


def final_recheck():
    return run_wsl(
        "nmap -sV -Pn -p 8001,3000,8080 --host-timeout 45s 127.0.0.1",
        120, "final-recheck")


RUNNERS = {
    "nmap_portscan": nmap_portscan, "gobuster_dvwa": gobuster_dvwa,
    "ffuf_juice": ffuf_juice, "nikto_dvwa": nikto_dvwa,
    "nuclei_dvwa": nuclei_dvwa, "sqlmap_dvwa": sqlmap_dvwa,
    "zap_baseline": zap_baseline, "final_recheck": final_recheck,
}

TOOL_NAMES = {  # phase -> extractor tool name for `paste`
    "nmap-portscan": "nmap", "gobuster-dvwa": "gobuster", "ffuf-juice": "ffuf",
    "nikto-dvwa": "nikto", "nuclei-dvwa": "nuclei", "sqlmap-dvwa": "sqlmap",
    "zap-baseline": "zap", "final-recheck": "nmap",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--turns", type=int, default=48)
    ap.add_argument("--wall-max", type=int, default=5400, help="wall-clock cap (s)")
    args = ap.parse_args()

    global LOG_PATH
    LOG_PATH = os.path.join(config.STATE_DIR, "engagement-log.jsonl")

    conn = db.connect(config.DB_PATH)
    db.init_db(conn)

    mission_name = f"ENG-OVERNIGHT-{datetime.now():%Y%m%d-%H%M%S}"
    mission_id = db.create_mission(conn, mission_name, list(ALLOWED),
                                   auth_ref="AUTH-OVERNIGHT-20260811",
                                   authorizations=[])
    log({"event": "start", "mission_id": mission_id, "mission": mission_name,
         "turns_planned": args.turns, "wall_max": args.wall_max,
         "db": config.DB_PATH})

    engine = ReasoningEngine()
    t_start = time.time()
    stats = {"turns": 0, "dup_rejected": 0, "out_of_scope_rejected": 0,
             "aggressive_rejected": 0, "completed_guard": 0, "approved": 0,
             "facts_at_start": len(db.get_facts(conn, mission_id))}

    phase_map = {turn: (name, RUNNERS[fn_name])
                 for turn, name, fn_name in PHASES}

    for turn in range(1, args.turns + 1):
        if time.time() - t_start > args.wall_max:
            log({"event": "stop", "reason": "wall-max", "turns": turn})
            break
        stats["turns"] = turn

        # 1) run the scheduled phase (real tool) when due
        phase_out = None
        if turn in phase_map:
            name, fn = phase_map[turn]
            rc, out = fn()
            phase_out = name
            # store real output as evidence + parse into facts
            if rc != 124 and out.strip() and len(out) > 40:
                tool = TOOL_NAMES[name]
                ev_path, sha = store_evidence(mission_id, tool,
                                              out.encode("utf-8", errors="replace"),
                                              config.EVIDENCE_DIR)
                try:
                    res = parse_tool_output(conn, mission_id, tool, ev_path)
                    log({"event": "parse", "phase": name, "tool": tool,
                         "facts": len(res["facts"]), "warnings": len(res["warnings"]),
                         "sha256": sha[:16]})
                except Exception as exc:  # honest parse failure
                    log({"event": "parse_error", "phase": name, "err": str(exc)})

        # 2) reasoning turn (context rollover + guards)
        digest = build_digest(conn, mission_id)
        inp = TESTER_INPUTS[(turn - 1) % len(TESTER_INPUTS)]
        if phase_out:
            inp = f"Phase '{phase_out}' finished. {inp}"
        try:
            res = engine.next_step(conn, mission_id, user_input=inp)
        except Exception as exc:
            log({"event": "reasoning_error", "turn": turn, "err": str(exc)})
            continue
        cmd = res.get("command") or {}
        state = cmd.get("state", "none")
        reason = cmd.get("reason", "")
        if state == "rejected":
            if "duplicate" in reason:
                stats["dup_rejected"] += 1
            elif "outside allowed scope" in reason:
                stats["out_of_scope_rejected"] += 1
            elif "aggressive" in reason:
                stats["aggressive_rejected"] += 1
            elif "completed" in reason:
                stats["completed_guard"] += 1
        elif state == "approved":
            stats["approved"] += 1
        log({"event": "turn", "turn": turn, "phase": phase_out,
             "digest_chars": len(digest), "objective": (res.get("objective") or "")[:80],
             "updates": len(res.get("task_updates_applied", [])),
             "cmd_state": state, "cmd_reason": reason[:60],
             "cmd_preview": (cmd.get("cmd") or "")[:90],
             "open_questions": len(res.get("open_questions", []))})

    # 3) final state
    tasks = db.get_tasks(conn, mission_id)
    facts = db.get_facts(conn, mission_id)
    cmds = conn.execute(
        "SELECT state, COUNT(*) n FROM commands WHERE mission_id=? GROUP BY state",
        (mission_id,)).fetchall()
    wall = round(time.time() - t_start, 1)
    stats.update({
        "wall_seconds": wall, "tasks": len(tasks),
        "tasks_completed": sum(1 for t in tasks if t["status"] == "completed"),
        "facts": len(facts), "commands_by_state": {r["state"]: r["n"] for r in cmds},
        "mission_id": mission_id, "mission": mission_name,
    })
    log({"event": "finish", "stats": stats})
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
