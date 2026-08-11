#!/usr/bin/env python
"""RedAegis 6h auto-recon launcher — MSYS-path-aware for cron."""

import subprocess, sys, os, re
from datetime import datetime

LOG_DIR = os.path.expandvars(r"%LOCALAPPDATA%\hermes\logs")
os.makedirs(LOG_DIR, exist_ok=True)
ts = datetime.now().strftime("%Y%m%d-%H%M%S")
log_path = os.path.join(LOG_DIR, f"auto-recon-{ts}.log")

# Paths — use raw Windows paths and convert to MSYS form for bash subprocess
WIN_SCRIPT = r"C:\Users\onris\INTECTED\scripts\auto-recon.sh"
WIN_CWD    = r"C:\Users\onris\INTECTED"


def _to_msys_path(win_path: str) -> str:
    """Convert Windows path to MSYS/git-bash path (C:\... -> /c/...)."""
    win_path = win_path.replace("\\", "/")
    m = re.match(r"^([a-zA-Z]):(.*)", win_path)
    if m:
        return f"/{m.group(1).lower()}{m.group(2)}"
    return win_path  # already Unix-style or UNC — pass through


MSYS_SCRIPT = _to_msys_path(WIN_SCRIPT)

rc = 0
with open(log_path, "w", encoding="utf-8") as log:
    log.write(f"=== auto-recon launcher starting at {ts} ===\n")
    log.write(f"script : {MSYS_SCRIPT}\n")
    log.write(f"cwd    : {WIN_CWD}\n")
    log.flush()

    try:
        proc = subprocess.run(
            ["bash", MSYS_SCRIPT],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            cwd=WIN_CWD, timeout=1800,
        )
        log.write(proc.stdout)
        print(proc.stdout)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        msg = "[auto-recon timed out after 30m]\n"
        log.write(msg); print(msg)
        rc = 124
    except Exception as exc:
        msg = f"[auto-recon error: {exc}]\n"
        log.write(msg); print(msg)
        rc = 1

sys.exit(rc)
