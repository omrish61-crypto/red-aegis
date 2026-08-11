"""Tool registry — predefined Python scan functions (the ONLY execution path).

Implements the spec's core: the LLM/planner NEVER generates raw bash strings
executed via os.system(). It references tools by name + typed params
(e.g. run_nmap(target, ports, rate)); the Supervisor validates the call
(supervisor.validate_tool_call) and only then does the registry execute it
with bounded rate/timing — stealth-first (no SYN floods, no unrate-limited
dir busting, no availability impact).

Every tool returns structured output; raw output is saved as evidence by the
caller. Tools run through the kali WSL host (pentest toolchain).
"""

import json
import shlex
import subprocess
import time

# --- registry --------------------------------------------------------------

RATE_CAP = 300          # packets/s hard cap for any scanner
DEFAULT_TIMEOUT = 120   # s
NMAP_BASELINE_RATE = 150

_TOOLS: dict[str, dict] = {
    "nmap_ports": {
        "summary": "port scan (bounded rate)",
        "params": {"target": str, "ports": str, "rate": int},
        "defaults": {"ports": "top1000", "rate": NMAP_BASELINE_RATE},
    },
    "nmap_services": {
        "summary": "service/version detection on given ports (bounded)",
        "params": {"target": str, "ports": str, "rate": int},
        "defaults": {"rate": NMAP_BASELINE_RATE},
    },
    "http_headers": {
        "summary": "fetch HTTP response headers (single request)",
        "params": {"target": str, "port": int},
        "defaults": {"port": 80},
    },
    "nikto": {
        "summary": "web server vuln scan (bounded maxtime)",
        "params": {"target": str, "maxtime": int},
        "defaults": {"maxtime": 90},
    },
    "ffuf_content": {
        "summary": "content discovery (rate-limited)",
        "params": {"target": str, "wordlist": str, "rate": int},
        "defaults": {"wordlist": "/usr/share/dirb/wordlists/common.txt",
                     "rate": 50},
    },
    "nuclei": {
        "summary": "template-based vuln scan (bounded)",
        "params": {"target": str, "severity": str},
        "defaults": {"severity": "low,medium,high,critical"},
    },
}

# tool -> whitelisted parameter keys (anything else is rejected outright)
_PARAM_WHITELIST = {name: set(spec["params"]) for name, spec in _TOOLS.items()}

# parameters that MUST NOT be operator-overridable to unsafe values
_SAFE_BOUNDS = {
    "rate": (1, RATE_CAP),
    "maxtime": (10, 300),
    "port": (1, 65535),
}


class ToolError(RuntimeError):
    pass


def list_tools() -> dict:
    """Tool catalogue (names, params, defaults) — what the planner may call."""
    return {name: {"summary": spec["summary"], "params": spec["params"],
                   "defaults": spec["defaults"]}
            for name, spec in _TOOLS.items()}


def validate_params(tool: str, params: dict) -> dict:
    """Type/whitelist/bounds validation WITHOUT executing anything."""
    if tool not in _TOOLS:
        raise ToolError(f"unknown tool {tool!r}")
    spec = _TOOLS[tool]
    merged = dict(spec["defaults"])
    for key, value in (params or {}).items():
        if key not in _PARAM_WHITELIST[tool]:
            raise ToolError(f"parameter {key!r} not allowed for {tool}")
        merged[key] = value
    # type checks
    for key, expected in spec["params"].items():
        value = merged[key]
        if not isinstance(value, expected):
            # ints may arrive as strings from the planner
            if expected is int and isinstance(value, str) and value.isdigit():
                merged[key] = int(value)
            else:
                raise ToolError(f"{tool}.{key} must be {expected.__name__}, "
                                f"got {type(value).__name__}")
    # safety bounds
    for key, (lo, hi) in _SAFE_BOUNDS.items():
        if key in merged:
            if not (lo <= merged[key] <= hi):
                raise ToolError(f"{tool}.{key} out of safe bounds "
                                f"({lo}..{hi}): {merged[key]}")
    return merged


def _run(cmd: list[str], timeout: int) -> tuple[str, int]:
    """Run through kali WSL; returns (stdout, exit_code). Bounded by timeout."""
    try:
        proc = subprocess.run(
            ["wsl", "-d", "kali-linux", "-u", "root", "-e", "bash", "-lc",
             " ".join(shlex.quote(c) for c in cmd)],
            capture_output=True, text=True, timeout=timeout,
            errors="replace")
        return proc.stdout + proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        raise ToolError(f"{cmd[0]} exceeded {timeout}s timeout")


def _run_nmap_ports(target: str, ports: str, rate: int) -> dict:
    if ports == "top1000":
        p = "--top-ports 1000"
    elif ports == "all":
        p = "-p-"  # allowed ONLY via operator-explicit approval (supervisor)
    else:
        p = f"-p {ports}"
    out, rc = _run(["nmap", "-Pn", p, "--max-rate", str(rate), "--open",
                    "-oN", f"/tmp/intected_{target}.nmap", target], 180)
    return {"exit": rc, "output": out}


def _run_nmap_services(target: str, ports: str, rate: int) -> dict:
    out, rc = _run(["nmap", "-Pn", "-sV", "-sC", "-p", ports, "--max-rate",
                    str(rate), target], 240)
    return {"exit": rc, "output": out}


def _run_http_headers(target: str, port: int) -> dict:
    out, rc = _run(["curl", "-skI", f"http://{target}:{port}"], 30)
    return {"exit": rc, "output": out}


def _run_nikto(target: str, maxtime: int) -> dict:
    out, rc = _run(["nikto", "-h", f"http://{target}", "-maxtime",
                    f"{maxtime}s", "-nointeractive"], maxtime + 15)
    return {"exit": rc, "output": out}


def _run_ffuf_content(target: str, wordlist: str, rate: int) -> dict:
    out, rc = _run(["ffuf", "-u", f"http://{target}/FUZZ", "-w", wordlist,
                    "-rate", str(rate), "-ac", "-mc", "200,204,301,302,307,401,403",
                    "-t", "10"], 120)
    return {"exit": rc, "output": out}


def _run_nuclei(target: str, severity: str) -> dict:
    out, rc = _run(["nuclei", "-u", f"http://{target}", "-severity", severity],
                   150)
    return {"exit": rc, "output": out}


_EXECUTORS = {
    "nmap_ports": _run_nmap_ports,
    "nmap_services": _run_nmap_services,
    "http_headers": _run_http_headers,
    "nikto": _run_nikto,
    "ffuf_content": _run_ffuf_content,
    "nuclei": _run_nuclei,
}


# --- ToolConfigurator (addendum section 7): stealth safe-defaults ----------
# The Supervisor enforces these; the planner builds calls THROUGH this config.
SAFE_DEFAULTS: dict[str, dict] = {
    "nmap_ports": {"rate": 50, "data_length": 32, "timing": "T3"},
    "nmap_services": {"rate": 50, "data_length": 32, "timing": "T3"},
    "http_headers": {"port": 80},
    "nikto": {"maxtime": 90},
    "ffuf_content": {"rate": 50, "threads": 5, "delay": 1,
                     "wordlist": "/usr/share/dirb/wordlists/common.txt"},
    "nuclei": {"rate_limit": 10, "concurrency": 5,  # -rl 10 -c 5
               "severity": "low,medium,high,critical"},
}

# --- ToolVersionValidator (addendum section 8A): pre-flight knowledge -------
# Before the planner builds a command for a tool, the backend runs
# `<tool> --version` / `--help`, parses the output and caches it — the LLM
# gets REAL flags from THIS Kali image, not memory (kills hallucinated flags
# like sqlmap --bypass-cloudflare).
_help_cache: dict[str, str] = {}
_HELP_TIMEOUT = 20


def probe_tool(tool: str, force: bool = False) -> str:
    """Run <tool> --version/--help in the kali image; returns parsed head."""
    import re as _re
    if tool in _help_cache and not force:
        return _help_cache[tool]
    version = ""
    for flag in ("--version", "-V", "-Version", "-v"):
        try:
            out, _ = _run([tool, flag], _HELP_TIMEOUT)
            if out.strip():
                version = out.strip().splitlines()[0][:160]
                break
        except Exception:
            continue
    help_text = ""
    try:
        out, _ = _run([tool, "--help"], _HELP_TIMEOUT)
        # keep flag-relevant lines only (e.g. tamper, rate, threads)
        lines = [ln.strip() for ln in out.splitlines()
                 if _re.search(r"(--\w+|tamper|rate|threads|delay)", ln)]
        help_text = " | ".join(lines[:8])[:600]
    except Exception:
        pass
    _help_cache[tool] = f"{tool}: {version}\nflags: {help_text}"
    return _help_cache[tool]


def probe_all_tools() -> dict[str, str]:
    """Pre-flight all registered tools (used to seed planner context)."""
    return {name: probe_tool(name) for name in _TOOLS}


# --- Real-time log capture (addendum: the AI can't analyze unseen logs) -----
def execute_raw(cmd: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Execute a raw shell command via the kali image (real-time capture).

    Used for OPERATOR-GATED runs from the dashboard queue: the command must
    have passed supervisor.check_command already (scope + aggression gate).
    stdin is closed (nuclei-style TTY hangs) and output streams line-by-line.
    """
    import time as _time
    started = _time.time()
    lines: list[str] = []
    try:
        proc = subprocess.Popen(
            ["wsl", "-d", "kali-linux", "-u", "root", "-e", "bash", "-lc", cmd],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            stdin=subprocess.DEVNULL, errors="replace")
        try:
            for raw in proc.stdout:
                lines.append(raw.rstrip("\n"))
        finally:
            try:
                proc.wait(timeout=max(1, timeout - (_time.time() - started)))
            except subprocess.TimeoutExpired:
                proc.kill()
                lines.append("[timeout exceeded — process killed]")
        return {"exit": proc.returncode, "log": "\n".join(lines),
                "log_lines": lines,
                "elapsed_s": round(_time.time() - started, 2)}
    except Exception as exc:
        return {"exit": -1, "log": f"execution error: {exc}",
                "log_lines": [f"execution error: {exc}"],
                "elapsed_s": round(_time.time() - started, 2)}


def execute_streaming(tool: str, params: dict,
                      timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Execute with REAL-TIME stdout capture: each line is appended to
    'log_lines' as it is produced, so progress/failures feed back to the AI
    even for long scans (no wait-until-exit black box)."""
    import time as _time
    merged = validate_params(tool, params)
    started = _time.time()
    cmd = _build_command(tool, merged)
    lines: list[str] = []
    try:
        proc = subprocess.Popen(
            ["wsl", "-d", "kali-linux", "-u", "root", "-e", "bash", "-lc",
             " ".join(shlex.quote(c) for c in cmd)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            stdin=subprocess.DEVNULL,  # nuclei blocks on TTY stdin — close it
            errors="replace")
        try:
            for raw in proc.stdout:  # streams line-by-line
                lines.append(raw.rstrip("\n"))
        finally:
            proc.wait(timeout=timeout)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        raise ToolError(f"{tool} exceeded {timeout}s timeout")
    return {"tool": tool, "params": merged, "exit": rc,
            "log_lines": lines, "log": "\n".join(lines),
            "elapsed_s": round(_time.time() - started, 1)}


def _build_command(tool: str, merged: dict) -> list[str]:
    """Map validated params to the actual tool argv (single source of truth)."""
    if tool == "nmap_ports":
        p = ("--top-ports 1000" if merged["ports"] == "top1000"
             else "-p- " if merged["ports"] == "all" else f"-p {merged['ports']}")
        return ["nmap", "-Pn", *p.split(), "--max-rate", str(merged["rate"]),
                "-T3", "--data-length", "32", "--open", merged["target"]]
    if tool == "nmap_services":
        return ["nmap", "-Pn", "-sV", "-sC", "-p", merged["ports"],
                "--max-rate", str(merged["rate"]), "-T3", "--data-length", "32",
                merged["target"]]
    if tool == "http_headers":
        return ["curl", "-skI", f"http://{merged['target']}:{merged['port']}"]
    if tool == "nikto":
        return ["nikto", "-h", f"http://{merged['target']}",
                "-maxtime", f"{merged['maxtime']}s", "-nointeractive"]
    if tool == "ffuf_content":
        return ["ffuf", "-u", f"http://{merged['target']}/FUZZ",
                "-w", merged["wordlist"], "-rate", str(merged["rate"]),
                "-t", "5", "-ac", "-mc",
                "200,204,301,302,307,401,403", "-json"]
    if tool == "nuclei":
        return ["nuclei", "-u", f"http://{merged['target']}",
                "-severity", merged["severity"], "-rl", "10", "-c", "5"]
    raise ToolError(f"unknown tool {tool!r}")


def execute(tool: str, params: dict, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Validate + execute a tool call. Returns structured result dict."""
    merged = validate_params(tool, params)
    started = time.time()
    result = _EXECUTORS[tool](**merged)
    result["tool"] = tool
    result["params"] = merged
    result["elapsed_s"] = round(time.time() - started, 1)
    return result
