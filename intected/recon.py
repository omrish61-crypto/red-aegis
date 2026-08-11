"""Phase 1 — Gradual, Supervised Reconnaissance (Agent 2).

Runs recon as an ordered sequence of STAGES, each one:
  - supervisor-gated (validate_tool_call: scope, rate, whitelist)
  - stealth-configured (ToolConfigurator defaults: -T3, --max-rate 50, delays)
  - evidence-aware (a stage whose evidence already exists is SKIPPED — no
    duplicate facts; --force re-runs)
  - streamed in real time (execute_streaming: the AI sees the logs)
  - parsed into facts + sha256 evidence before the next stage starts

Gradual by design: rates start at the safe floor and never escalate without
an explicit operator flag. Phase 2 (planning) consumes the resulting
evidence graph — recon never jumps straight to exploitation.

Stage order (each depends on the previous):
  1. ports    — top-1000 port discovery (nmap, stealth)
  2. services — service/version detection on the ports found (nmap -sV -sC)
  3. headers  — web fingerprint on http ports (single request, curl -skI)
  4. content  — rate-limited content discovery (ffuf, delay 1s)
"""

import json
import os
import tempfile

from . import db
from .scope import ScopeViolation
from .supervisor import validate_tool_call
from .tools import ToolError, execute_streaming

STAGES = [
    {"name": "ports", "tool": "nmap_ports",
     "desc": "top-1000 port discovery (stealth)"},
    {"name": "services", "tool": "nmap_services",
     "desc": "service/version detection on discovered ports"},
    {"name": "headers", "tool": "http_headers",
     "desc": "web fingerprint (single request)"},
    {"name": "content", "tool": "ffuf_content",
     "desc": "rate-limited content discovery (delay 1s)"},
]

# stage -> fact-type evidence used to decide "already covered"
_EVIDENCE_TYPES = {"ports": "port", "services": "service",
                   "headers": "note", "content": "path"}

# stage -> execution timeout (s) — content discovery at rate 50 needs headroom
_STAGE_TIMEOUT = {"ports": 200, "services": 260, "headers": 30, "content": 220}


def stage_covered(conn, mission_id: int, stage: str, target: str) -> bool:
    """True when the stage's evidence already exists for this mission.

    Facts don't carry a target column and extractors store the raw tool name
    (e.g. 'nmap', not 'nmap_ports'), so coverage is matched by FACT TYPE:
    if the stage's evidence type exists for the mission, re-running would only
    create duplicates (the gradual principle: don't re-scan what we know)."""
    ftype = _EVIDENCE_TYPES[stage]
    row = conn.execute(
        "SELECT COUNT(*) FROM facts WHERE mission_id=? AND fact_type=?",
        (mission_id, ftype)).fetchone()
    return bool(row and row[0] > 0)


def discovered_ports(conn, mission_id: int, target: str) -> str:
    """Comma-joined open ports found for the target (from port facts)."""
    ports = []
    for (value_json,) in conn.execute(
            "SELECT value_json FROM facts WHERE mission_id=? AND fact_type='port'",
            (mission_id,)):
        try:
            v = json.loads(value_json) if isinstance(value_json, str) else value_json
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(v, dict) and v.get("port"):
            ports.append(int(v["port"]))
    return ",".join(str(p) for p in sorted(set(ports)))


def run_recon(conn, mission_id: int, target: str,
              stage: str | None = None, force: bool = False,
              operator_approved: bool = False) -> dict:
    """Execute the gradual supervised recon sequence (or a single stage).

    Returns {stages: [{name, tool, gate, action, facts, output_head}]}.
    Raises ScopeViolation/ToolError/ValueError on the first blocked stage.
    """
    mission = db.get_mission(conn, mission_id)
    if mission is None:
        raise ValueError(f"no such mission {mission_id}")
    hosts = json.loads(mission["allowed_hosts_json"] or "[]")
    results = []
    selected = [s for s in STAGES if stage is None or s["name"] == stage]
    for st in selected:
        tool = st["tool"]
        # stage params adapt to earlier evidence
        params = {"target": target}
        if tool == "nmap_services":
            ports = discovered_ports(conn, mission_id, target)
            params["ports"] = ports or "top1000"
        if tool == "http_headers":
            ports = discovered_ports(conn, mission_id, target)
            web_port = next((p for p in ports.split(",") if p in
                             ("80", "443", "3000", "8001", "8080", "8081")), "80")
            params["port"] = int(web_port)
        if tool == "ffuf_content":
            ports = discovered_ports(conn, mission_id, target)
            web_port = next((p for p in ports.split(",") if p in
                             ("80", "443", "3000", "8001", "8080", "8081")), "")
            if web_port:
                params["target"] = f"{target}:{web_port}"
        # supervisor gate (Agent 1)
        try:
            validated = validate_tool_call(tool, params, hosts,
                                           operator_approved=operator_approved)
        except (ScopeViolation, ToolError, ValueError) as exc:
            results.append({"name": st["name"], "tool": tool,
                            "gate": "BLOCKED", "reason": str(exc)})
            raise
        # evidence-aware skip (gradual: don't re-scan what we know)
        if not force and stage_covered(conn, mission_id, st["name"], target):
            results.append({"name": st["name"], "tool": tool,
                            "gate": "skipped",
                            "reason": "evidence already present"})
            continue
        # execute with real-time capture (stage-appropriate timeout)
        result = execute_streaming(tool, validated["params"],
                                   timeout=_STAGE_TIMEOUT.get(st["name"], 120))
        output = result.get("log", "")
        # persist raw + parse into facts
        fact_count = 0
        if output.strip():
            fact_count = _ingest(conn, mission_id, tool, target, output)
        results.append({"name": st["name"], "tool": tool, "gate": "approved",
                        "facts": fact_count,
                        "exit": result.get("exit"),
                        "output_head": output[:300]})
    return {"target": target, "stages": results}


def _ingest(conn, mission_id: int, tool: str, target: str, output: str) -> int:
    """Save raw evidence + parse into facts; returns fact count."""
    from . import config
    from .parsing import parse_tool_output
    # registry tool name -> parser name (extractors know 'nmap', not 'nmap_ports')
    parser_tool = {"nmap_ports": "nmap", "nmap_services": "nmap"}.get(tool, tool)
    state = os.path.join(config.state_dir(), "evidence", f"mission-{mission_id}")
    os.makedirs(state, exist_ok=True)
    fd, raw_path = tempfile.mkstemp(
        prefix=f"{tool}_{target.replace('/', '_')}_", suffix=".raw",
        dir=state)
    with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as f:
        f.write(output)
    from .parsing import EXTRACTORS, parse_tool_output
    if parser_tool not in EXTRACTORS:
        return 0  # no extractor (e.g. curl headers) — raw evidence is the record
    res = parse_tool_output(conn, mission_id, parser_tool, raw_path)
    return len(res.get("facts", []))
