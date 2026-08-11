"""
SMB Security Grade Engine — converts red-team evidence into a business-readable
letter grade (A–F) with weighted risk deduction.

The model is calibrated for SMB risk: open RDP/SMB/Telnet ports, known CVEs,
missing security headers, exposed admin panels, and unpatched services are
weighted more heavily than exotic attack chains.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from collections import Counter

from . import db
from .evidence import build_evidence_graph, EvidenceGraph

# ── risk weights (points deducted from a 100-point baseline) ─────────────

HIGH_RISK_PORTS = {3389, 445, 23, 21, 22, 3306, 5432, 6379, 27017}
PORT_DEDUCTION = 15          # each open high-risk port

CVE_WEIGHTS = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
}

MISSING_HEADERS = {
    "Content-Security-Policy": 8,
    "Strict-Transport-Security": 8,
    "X-Frame-Options": 5,
    "X-Content-Type-Options": 3,
}

EXPOSED_PANELS = {
    "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config", "/backup",
    "/.git", "/console", "/jenkins", "/solr",
}
PANEL_DEDUCTION = 10

UNPATCHED_DEDUCTION = 10     # each service with a known-vulnerable version
CORS_WILDCARD_DEDUCTION = 8
CREDENTIAL_DEDUCTION = 25    # default/weak creds found — huge SMB risk


@dataclass
class GradeReport:
    """Result of compute_grade()."""
    score: int                  # 0-100
    letter: str                 # A, B, C, D, F
    deductions: list[dict]      # [{reason, points, detail}, ...]
    positives: list[str]        # things they did right
    fact_count: int


def compute_grade(conn, mission_id: int, target: str | None = None) -> GradeReport:
    """Score a mission's target on a 100-point scale and return an A-F grade.

    ``target`` scopes the assessment to one host (v3 per-target evidence);
    when None, all mission facts are assessed.
    """
    graph = build_evidence_graph(conn, mission_id, target)
    # also pull raw facts for CVE / credential / header detail
    facts = _load_facts(conn, mission_id, target)

    score = 100
    deductions: list[dict] = []
    positives: list[str] = []

    # 1. high-risk open ports
    for svc in graph.services:
        port = svc.get("port") or (int(svc["port"]) if isinstance(svc.get("port"), (int, str)) else 0)
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        if port in HIGH_RISK_PORTS:
            deductions.append({
                "reason": f"Port {port}/tcp open",
                "points": PORT_DEDUCTION,
                "detail": f"TCP port {port} is reachable — common ransomware / RDP exploit vector",
            })
            score -= PORT_DEDUCTION

    # 2. CVEs
    for f in facts.get("cve", []):
        sev = (f.get("value", {}).get("severity") or "").lower()
        pts = CVE_WEIGHTS.get(sev, 0)
        if pts:
            cid = f.get("value", {}).get("cve_id", "?")
            deductions.append({
                "reason": f"CVE {cid} ({sev})",
                "points": pts,
                "detail": f.get("value", {}).get("summary", "")[:120],
            })
            score -= pts

    # 3. CORS wildcard
    cors_found = any(
        "access-control-allow-origin: *" in (f.get("value") or {}).get("header", "").lower()
        or "access-control-allow-origin" in str(f.get("value", {}))
        for f in facts.get("note", [])
    )
    if cors_found:
        deductions.append({
            "reason": "CORS wildcard (*)",
            "points": CORS_WILDCARD_DEDUCTION,
            "detail": "Your web server allows any website to make requests on behalf of your users",
        })
        score -= CORS_WILDCARD_DEDUCTION

    # 4. exposed admin panels / sensitive paths
    for path in graph.attack_surface:
        clean = path.rstrip("/")
        if clean in EXPOSED_PANELS or any(ep in clean for ep in EXPOSED_PANELS):
            deductions.append({
                "reason": f"Exposed admin path {path}",
                "points": PANEL_DEDUCTION,
                "detail": f"Path {path} is publicly reachable — attackers probe these for weak logins",
            })
            score -= PANEL_DEDUCTION

    # 5. unpatched / EOL service versions
    for t in graph.technologies:
        tech = t.get("name", "") if isinstance(t, dict) else t
        if any(v in tech for v in ("2.4.7", "2.4.25", "9.0.0-M1", "1.0", "1.1")):
            deductions.append({
                "reason": f"Outdated software: {tech}",
                "points": UNPATCHED_DEDUCTION,
                "detail": f"{tech} has known vulnerabilities — update to the latest version",
            })
            score -= UNPATCHED_DEDUCTION

    # 6. default credentials
    if facts.get("credential"):
        deductions.append({
            "reason": "Default/weak credentials found",
            "points": CREDENTIAL_DEDUCTION,
            "detail": "One or more services accept default or easily-guessed passwords — "
                      "this is the #1 SMB ransomware entry point",
        })
        score -= CREDENTIAL_DEDUCTION

    # 7. positives — things they did RIGHT
    if not any(svc.get("port") == 3389 for svc in graph.services):
        positives.append("Port 3389 (RDP) is not open to the internet")
    if graph.technologies:
        positives.append(f"Identified {len(graph.technologies)} running technologies")

    # 8. letter grade
    score = max(0, min(100, score))
    if score >= 90:
        letter = "A"
    elif score >= 80:
        letter = "B"
    elif score >= 70:
        letter = "C"
    elif score >= 60:
        letter = "D"
    else:
        letter = "F"

    return GradeReport(
        score=score,
        letter=letter,
        deductions=deductions,
        positives=positives,
        fact_count=sum(len(v) for v in facts.values()),
    )


def _load_facts(conn, mission_id: int, target: str | None) -> dict[str, list]:
    """Pull raw-fact rows grouped by fact_type, optionally filtered by target."""
    rows: list[dict] = []
    if target:
        sql = ("SELECT id, tool, fact_type, value_json, confidence "
               "FROM facts WHERE mission_id=? AND (target=? OR target='') ORDER BY id")
        for r in conn.execute(sql, (mission_id, target)):
            rows.append(dict(r))
    else:
        sql = ("SELECT id, tool, fact_type, value_json, confidence "
               "FROM facts WHERE mission_id=? ORDER BY id")
        for r in conn.execute(sql, (mission_id,)):
            rows.append(dict(r))
    grouped: dict[str, list] = {}
    for r in rows:
        try:
            r["value"] = json.loads(r["value_json"]) if isinstance(r["value_json"], str) else r.pop("value_json")
        except (json.JSONDecodeError, TypeError):
            continue
        grouped.setdefault(r["fact_type"], []).append(r)
    return grouped
