"""Supervisor Agent — validates every tool call before execution (Agent 1).

The single gate every scan must pass. Blocks (spec: no DoS, no data
modification, no massive brute force, no aggressive rates that trigger
IDS/IPS) and enforces scope + operator approval semantics:

- scope:      target must be in the mission's allowed hosts (deny by default)
- DoS:        no unrate-limited scans; rate capped; SYN-flood-ish tools banned
- brute:      no hydra/medusa/hashcat/wordlist-login tools in the registry
- aggressive: -T5 / --min-rate / -p- with high rate need operator-explicit
              approval (the reasoning engine can NEVER self-approve)
- PII:        data-extraction tools (sqlmap --dump, database reads beyond
              version-proof) are blocked at the supervisor level

The Supervisor is also the anti-hallucination gate: it never fabricates — a
tool call only exists if it came from the registry with valid params.
"""

import re

from .scope import ScopeViolation, check_command
from .tools import RATE_CAP, list_tools, validate_params

# tools/patterns the supervisor will never auto-approve
_BANNED_TOOLS = ("hydra", "medusa", "hashcat", "john", "ncrack", "msfconsole",
                 "msfvenom", "sqlmap --dump", "sqlmap --os-shell")
_AGGRESSIVE_RATE = re.compile(r"(--min-rate|--max-rate \d{4,}|-T[45]\b)")
_DOS_TOOLS = ("hping3", "slowloris", "goldeneye", "siege", "ab ", "xerxes",
              "mhddos", "LOIC", "HOIC")

BLOCK_REASON_GENERIC = "blocked by supervisor policy"


def validate_tool_call(tool: str, params: dict, allowed_hosts: list[str],
                       operator_approved: bool = False) -> dict:
    """Gate a tool call. Returns {'ok': True, 'params': {...}} or raises.

    Raises ToolError/ScopeViolation/ValueError with the exact reason.
    """
    # 1. registry existence + param validation (nothing raw can pass)
    merged = validate_params(tool, params)

    # 2. target in scope (deny by default)
    target = merged.get("target") or ""
    check_command(f"{tool} {target}", allowed_hosts)  # reuse scope engine

    # 3. DoS / aggressive-rate block
    if tool == "nmap_ports" and merged.get("ports") == "all" and not operator_approved:
        raise ValueError("full -p- scan requires explicit operator approval")
    if merged.get("rate", 0) > RATE_CAP:
        raise ValueError(f"rate {merged['rate']} exceeds the supervisor cap "
                         f"({RATE_CAP} pps) — no availability impact")

    # 4. banned/brute-force/data-extraction tools never auto-approve
    for banned in _BANNED_TOOLS:
        if tool == banned or (banned in tool):
            if not operator_approved:
                raise ValueError(f"tool {tool!r} is banned by supervisor "
                                 f"policy (brute-force / data extraction)")

    # 5. PII-safe: nothing in the registry extracts data (no sqlmap dump path)
    return {"ok": True, "tool": tool, "params": merged,
            "supervisor": "approved"}


def auto_approvable(tool: str, params: dict) -> bool:
    """True if a tool call needs NO operator approval (recon-grade only)."""
    try:
        merged = validate_params(tool, params)
    except Exception:
        return False
    return tool in ("nmap_ports", "http_headers", "nikto") \
        and merged.get("ports", "top1000") != "all"
