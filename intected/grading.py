"""
SMB Security Grade Engine — converts red-team evidence into a business-readable
letter grade (A–F) with weighted risk deduction.

The model is calibrated for SMB risk: open RDP/SMB/Telnet ports, known CVEs,
missing security headers, exposed admin panels, and unpatched services are
weighted more heavily than exotic attack chains.
"""
from __future__ import annotations

import json
import re
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

# ── security headers to check ─────────────────────────────────────────────
SECURITY_HEADERS = {
    "Content-Security-Policy": ("Content-Security-Policy", 8,
        "Missing CSP — your site can be injected with malicious scripts"),
    "Strict-Transport-Security": ("Strict-Transport-Security", 8,
        "Missing HSTS — browsers may connect over insecure HTTP"),
    "X-Frame-Options": ("X-Frame-Options", 5,
        "Missing X-Frame-Options — your site can be embedded in attack pages"),
    "X-Content-Type-Options": ("X-Content-Type-Options", 3,
        "Missing X-Content-Type-Options — MIME-sniffing attacks possible"),
    "Referrer-Policy": ("Referrer-Policy", 3,
        "Missing Referrer-Policy — URLs may leak to external sites via Referer header"),
    "Permissions-Policy": ("Permissions-Policy", 3,
        "Missing Permissions-Policy — browser features unrestricted (camera, mic, etc.)"),
}

EXPOSED_PANELS = {
    "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config", "/backup",
    "/.git", "/console", "/jenkins", "/solr",
}
PANEL_DEDUCTION = 10

UNPATCHED_DEDUCTION = 10     # each service with a known-vulnerable version
CORS_WILDCARD_DEDUCTION = 8
CREDENTIAL_DEDUCTION = 25    # default/weak creds found — huge SMB risk

# ── version fingerprint patterns mapping version fragments → risk detail ──
#
# Each entry is (regex_pattern, risk_description).
# The regex is checked case-insensitively against any technology name or
# service banner found in the evidence graph.
_VERSION_PATTERNS: list[tuple[str, str, str]] = [
    # Generic / legacy
    (r"\b1\.\d(?!\d)", "1.x", "Version 1.x is long EOL — update immediately"),
    (r"\b2\.4\.7", "Apache 2.4.7", "Apache 2.4.7 (2013) has known CVEs — upgrade now"),
    (r"\b2\.4\.25", "Apache 2.4.25", "Apache 2.4.25 (2016) has known CVEs — upgrade now"),
    (r"\b9\.0\.0-M1", "Tomcat 9.0.0-M1", "Tomcat 9.0.0-M1 is a pre-release milestone — upgrade now"),

    # WordPress
    (r"(?i)wordpress\s*(?:version\s*)?[34]\.\d", "WordPress 3.x/4.x",
     "WordPress 3.x/4.x is EOL — update to 6.x now"),
    (r"(?i)wordpress\s*(?:version\s*)?5\.([0-8])\b", "WordPress 5.x < 5.9",
     "WordPress < 5.9 has known vulnerabilities — update to 6.x"),
    (r"(?i)wp-content", "WordPress detected",
     "WordPress sites need regular core/plugin updates — run `wp core update`"),

    # Drupal
    (r"(?i)drupal\s*(?:version\s*)?7\.", "Drupal 7.x",
     "Drupal 7.x is EOL (Jan 2025) — migrate to Drupal 10+ immediately"),
    (r"(?i)drupal\s*(?:version\s*)?8\.", "Drupal 8.x",
     "Drupal 8.x is EOL — upgrade to Drupal 10+"),
    (r"(?i)drupal/sites", "Drupal detected",
     "Drupal detected — ensure core + modules are patched regularly"),

    # PHP
    (r"(?i)php\s*/?\s*5\.", "PHP 5.x",
     "PHP 5.x is EOL since 2019 — migrate to PHP 8.x"),
    (r"(?i)php\s*/?\s*7\.[0-3]\b", "PHP 7.x < 7.4",
     "PHP 7.0-7.3 is EOL — upgrade to PHP 8.x"),
    (r"(?i)php\s*/?\s*7\.4", "PHP 7.4",
     "PHP 7.4 reached EOL in Nov 2022 — upgrade to PHP 8.x"),

    # OpenSSL
    (r"(?i)openssl\s*/?\s*1\.0\.", "OpenSSL 1.0.x",
     "OpenSSL 1.0.x is EOL (Heartbleed era) — upgrade to 3.x"),
    (r"(?i)openssl\s*/?\s*1\.1\.[01]", "OpenSSL 1.1.0/1.1.1",
     "OpenSSL 1.1.x reached EOL in 2023 — upgrade to 3.x"),

    # nginx
    (r"(?i)nginx\s*/?\s*0\.", "nginx 0.x",
     "nginx 0.x is EOL — upgrade to 1.24+"),
    (r"(?i)nginx\s*/?\s*1\.([0-9]|1[0-7])\b", "nginx < 1.18",
     "nginx < 1.18 has known vulnerabilities — upgrade to 1.24+"),
    (r"(?i)nginx\s*/?\s*1\.1[89]\.", "nginx 1.18/1.19",
     "nginx 1.18/1.19 — consider upgrading to latest stable"),
    (r"(?i)nginx\s*/?\s*1\.2[0-3]\.", "nginx 1.20-1.23",
     "nginx 1.20-1.23 — consider upgrading to 1.24+"),

    # IIS
    (r"(?i)microsoft-iis\s*/?\s*[5-6]\.", "IIS 5.x/6.x",
     "IIS 5/6 is Windows Server 2003 era — migrate to a supported version"),
    (r"(?i)microsoft-iis\s*/?\s*7\.", "IIS 7.x",
     "IIS 7.x is EOL — upgrade to IIS 10 on Server 2019+"),
    (r"(?i)iis", "IIS detected",
     "IIS detected — ensure patch management (Windows Update) is current"),

    # Exchange
    (r"(?i)exchange\s*(?:server\s*)?201[0-6]", "Exchange 2010-2016",
     "Exchange 2010-2016 is EOL or approaching — upgrade to 2019+"),
    (r"(?i)owa|outlook\s*web\s*access", "Exchange OWA",
     "Exchange OWA exposed — ensure you've patched ProxyLogon/ProxyShell"),

    # Synology DSM
    (r"(?i)synology\s*(?:dsm\s*)?[4-6]\.", "Synology DSM 4.x-6.x",
     "Synology DSM < 7.x is EOL — upgrade to DSM 7.2+"),
    (r"(?i)synology.*diskstation", "Synology DiskStation",
     "Synology NAS detected — ensure DSM is updated; close default ports"),
    (r"(?i)dsm\s*(?:version\s*)?[4-6]\.", "Synology DSM 4-6",
     "Synology DSM < 7.0 — upgrade immediately; many CVEs"),

    # Ubiquiti UniFi
    (r"(?i)unifi\s*(?:network\s*)?[5-6]\.", "UniFi 5.x/6.x",
     "UniFi Network < 7.x has CVEs — upgrade controller to 7.5+"),
    (r"(?i)unifi", "UniFi detected",
     "Ubiquiti UniFi detected — update controller & change default creds"),
    (r"(?i)ubiquiti", "Ubiquiti device",
     "Ubiquiti device — ensure firmware is current; change default creds"),

    # Jenkins
    (r"(?i)jenkins\s*/?\s*[12]\.\d+\.", "Jenkins < 2.400",
     "Jenkins < 2.400 has known vulnerabilities — upgrade to latest LTS"),
    (r"(?i)jenkins", "Jenkins detected",
     "Jenkins detected — restrict access; update plugins regularly"),

    # Docker API
    (r"(?i)docker.*api.*(?:version\s*1\.|2375|2376)", "Docker API exposed",
     "Docker API exposed without auth — attackers can deploy containers"),
    (r"(?i)docker.*engine\s*1[89]\.", "Docker Engine < 20",
     "Docker Engine < 20 is EOL — upgrade to 24+"),

    # MongoDB exposed
    (r"(?i)mongodb.*(?:2\.[0-5]|3\.[0-3])\b", "MongoDB < 3.4",
     "MongoDB < 3.4 is ancient — upgrade to 7.x"),
    (r"(?i)mongodb", "MongoDB detected",
     "MongoDB detected — ensure auth is enabled and port is firewalled"),

    # Redis exposed
    (r"(?i)redis.*(?:2\.[0-7]|3\.[0-1])\b", "Redis < 3.2",
     "Redis < 3.2 has CVEs (unauthenticated access) — upgrade to 7.x"),
    (r"(?i)redis", "Redis detected",
     "Redis detected — set requirepass and bind to localhost"),

    # phpMyAdmin
    (r"(?i)phpmyadmin\s*/?\s*[34]\.", "phpMyAdmin 3.x/4.x",
     "phpMyAdmin 3/4 is EOL — upgrade to 5.x+"),
    (r"(?i)phpmyadmin", "phpMyAdmin detected",
     "phpMyAdmin exposed — restrict access or remove if not needed"),

    # Solaris
    (r"(?i)solarwinds", "SolarWinds detected",
     "SolarWinds detected — ensure you've patched SUNBURST vulnerability"),
]


@dataclass
class GradeReport:
    """Result of compute_grade()."""
    score: int                  # 0-100
    letter: str                 # A, B, C, D, F
    deductions: list[dict]      # [{reason, points, detail}, ...]
    positives: list[str]        # things they did right
    fact_count: int


def _scan_notes_for_headers(facts: dict[str, list]) -> list[dict]:
    """Scan note facts for security header presence/absence info.

    Looks for HTTP response headers in note fact values — if we find
    a header note that lists response headers, check which security
    headers are present.
    """
    deductions: list[dict] = []
    present_headers: set[str] = set()

    # Gather all note text — headers might be in various formats
    all_notes: list[str] = []
    for f in facts.get("note", []):
        val = f.get("value", {})
        if isinstance(val, dict):
            for v in val.values():
                if isinstance(v, str):
                    all_notes.append(v)
        elif isinstance(val, str):
            all_notes.append(val)

    note_text = "\n".join(all_notes).lower()

    for header_name, (canonical, pts, detail) in SECURITY_HEADERS.items():
        # Check if the header is present in notes
        if canonical.lower() in note_text:
            present_headers.add(header_name)

    # We only flag missing headers if we found SOME headers (meaning we
    # have an HTTP response to check). If we found no headers at all,
    # we don't know the state — don't deduct.
    if not present_headers:
        return []

    for header_name, (canonical, pts, detail) in SECURITY_HEADERS.items():
        if header_name not in present_headers:
            deductions.append({
                "reason": f"Missing security header: {header_name}",
                "points": pts,
                "detail": detail,
            })

    return deductions


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

    # 5. unpatched / EOL service versions (expanded pattern library)
    seen_patterns: set[str] = set()

    # Helper to scan a string for version patterns
    def _scan_version(text: str) -> None:
        nonlocal score
        for pattern, label, detail in _VERSION_PATTERNS:
            if re.search(pattern, text):
                key = f"{label}:{detail[:40]}"
                if key not in seen_patterns:
                    seen_patterns.add(key)
                    deductions.append({
                        "reason": f"Outdated software: {label}",
                        "points": UNPATCHED_DEDUCTION,
                        "detail": detail,
                    })
                    score -= UNPATCHED_DEDUCTION

    # Check technology names from the evidence graph
    for t in graph.technologies:
        tech_name = t.get("name", "") if isinstance(t, dict) else str(t)
        _scan_version(tech_name)

    # Check service banners directly
    for svc in graph.services:
        banner = svc.get("banner", "") or ""
        if banner:
            _scan_version(banner)

    # Check raw fact values (notes, etc.) for version strings the graph
    # may have simplified (e.g. note "WordPress 4.9.1" → graph tech "WordPress")
    for ftype, flist in facts.items():
        for f in flist:
            val = f.get("value", {})
            # Convert to a string representation to scan
            if isinstance(val, dict):
                text = json.dumps(val)
            elif isinstance(val, str):
                text = val
            else:
                text = str(val)
            _scan_version(text)

    # 6. missing security headers (from note facts)
    header_deductions = _scan_notes_for_headers(facts)
    for hd in header_deductions:
        deductions.append(hd)
        score -= hd["points"]

    # 7. default credentials
    if facts.get("credential"):
        deductions.append({
            "reason": "Default/weak credentials found",
            "points": CREDENTIAL_DEDUCTION,
            "detail": "One or more services accept default or easily-guessed passwords — "
                      "this is the #1 SMB ransomware entry point",
        })
        score -= CREDENTIAL_DEDUCTION

    # 8. positives — things they did RIGHT
    if not any(svc.get("port") == 3389 for svc in graph.services):
        positives.append("Port 3389 (RDP) is not open to the internet")
    if not any(svc.get("port") == 445 for svc in graph.services):
        positives.append("Port 445 (SMB) is not exposed")

    # Check which security headers ARE present (from header deductions scan)
    present_headers_set: set[str] = set()
    for hd in header_deductions:
        pass  # we counted the missing ones
    # Find present headers by checking notes
    all_notes_text = ""
    for f in facts.get("note", []):
        val = f.get("value", {})
        if isinstance(val, dict):
            for v in val.values():
                if isinstance(v, str):
                    all_notes_text += v + "\n"
    for header_name, (canonical, pts, detail) in SECURITY_HEADERS.items():
        if canonical.lower() in all_notes_text.lower():
            positives.append(f"Security header present: {header_name}")

    if graph.technologies:
        positives.append(f"Identified {len(graph.technologies)} running technologies")

    # 9. letter grade
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
