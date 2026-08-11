"""Evidence Graph — structured per-target model built from the fact store.

Implements the methodology: the AI receives structured EVIDENCE (services,
technologies, WAF indicators, attack surface) with confidence scores, not raw
tool text. Every element traces back to facts (and through them to sha256
evidence files). Also provides the finding scoring model
(confidence / impact / exploitability / priority).

Rule of the system: every finding must lead to a test hypothesis, every test
must be based on a previous finding (see planner.py for the engine).
"""

import json
import re

SERVICE_TYPES = ("port", "service", "version")
PATH_TYPES = ("path", "dir", "url", "endpoint")
TECH_MARKERS = (
    ("Apache", "apache"), ("nginx", "nginx"), ("Tomcat", "tomcat"),
    ("IIS", "iis"), ("Node.js", "node"), ("Express", "express"),
    ("PHP", "php"), ("nginx", "nginx"), ("Jetty", "jetty"),
    ("Werkzeug", "werkzeug"), ("Flask", "flask"), ("Django", "django"),
    ("Ruby", "ruby"), ("Rails", "rails"), ("Java", "java"), ("Go", "go"),
)
WAF_MARKERS = (
    "mod_security", "modsecurity", "cloudflare", "akamai", "sucuri",
    "imperva", "incapsula", "f5 ", "barracuda", "aws waf", "waf",
)
API_MARKERS = ("/api", "/rest", "/graphql", "/swagger", "/openapi", "/v1", "/v2")


class EvidenceGraph:
    """Per-target structured evidence model (methodology section 12)."""

    def __init__(self, asset: str):
        self.asset = asset
        self.ip = None
        self.services: list[dict] = []
        self.technologies: list[dict] = []
        self.waf: dict = {"detected": False, "confidence": 0.0, "evidence": []}
        self.attack_surface: list[str] = []
        self.facts: list[int] = []

    def to_dict(self) -> dict:
        return {
            "asset": self.asset,
            "ip": self.ip,
            "services": sorted(self.services, key=lambda s: s["port"]),
            "technologies": sorted(self.technologies,
                                   key=lambda t: t["confidence"], reverse=True),
            "waf": self.waf,
            "attack_surface": sorted(set(self.attack_surface)),
            "fact_ids": sorted(self.facts),
        }

    # -- aggregation helpers ------------------------------------------------

    def add_service(self, port: int, protocol: str, banner: str | None,
                    confidence: float, fact_id: int) -> None:
        for svc in self.services:
            if svc["port"] == port:
                if banner and not svc.get("banner"):
                    svc["banner"] = banner
                svc["confidence"] = max(svc["confidence"], confidence)
                return
        self.services.append({
            "port": port, "protocol": protocol,
            "banner": banner or "", "confidence": confidence,
        })
        self.facts.append(fact_id)

    def add_technology(self, name: str, confidence: float, fact_id: int) -> None:
        for tech in self.technologies:
            if tech["name"].lower() == name.lower():
                tech["confidence"] = max(tech["confidence"], confidence)
                return
        self.technologies.append({"name": name, "confidence": confidence})
        self.facts.append(fact_id)

    def add_waf_indicator(self, indicator: str, confidence: float) -> None:
        self.waf["detected"] = True
        self.waf["confidence"] = max(self.waf["confidence"], confidence)
        if indicator not in self.waf["evidence"]:
            self.waf["evidence"].append(indicator)

    def add_surface(self, path: str) -> None:
        if path and path not in self.attack_surface:
            self.attack_surface.append(path)


def _value(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return default


def _infer_technologies(text: str) -> list[str]:
    found = []
    low = text.lower()
    for name, marker in TECH_MARKERS:
        if marker in low and name not in found:
            found.append(name)
    return found


def build_evidence_graph(conn, mission_id: int, target: str | None = None) -> EvidenceGraph:
    """Compose the fact store into a per-target EvidenceGraph (methodology 12).
    When ``target`` is given, facts are filtered to that host only (v3 per-target
    scoping); when None, all mission facts are included (backwards-compat)."""
    if target:
        rows = conn.execute(
            "SELECT id, tool, fact_type, value_json, confidence FROM facts "
            "WHERE mission_id=? AND (target=? OR target='') ORDER BY id",
            (mission_id, target)).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, tool, fact_type, value_json, confidence FROM facts "
            "WHERE mission_id=? ORDER BY id", (mission_id,)).fetchall()
    asset = target or f"mission-{mission_id}"
    graph = EvidenceGraph(asset)
    for fact_id, tool, ftype, value_json, confidence in rows:
        try:
            value = json.loads(value_json) if isinstance(value_json, str) else value_json
        except (json.JSONDecodeError, TypeError):
            continue
        conf = float(confidence or 0.0)
        # services: port facts + version/service banners
        if ftype in SERVICE_TYPES:
            port = _value(value, "port")
            if port is None and ftype == "port":
                continue
            if port is None:
                # banner-only facts: infer port from the banner text if present
                banner = _value(value, "banner") or _value(value, "product") or ""
                m = re.search(r"(\d+)/tcp", banner)
                port = int(m.group(1)) if m else None
            banner = (_value(value, "banner") or _value(value, "product")
                      or _value(value, "server") or "")
            protocol = _value(value, "protocol") or "tcp"
            if port is not None:
                graph.add_service(int(port), protocol, banner or None, conf,
                                  fact_id)
                for tech in _infer_technologies(f"{banner} {tool}"):
                    graph.add_technology(tech, conf, fact_id)
        # attack surface: path-ish facts
        if ftype in PATH_TYPES:
            path = _value(value, "path") or _value(value, "url") or _value(value, "dir")
            if path:
                graph.add_surface(str(path))
        # string notes may carry technology/waf indicators (e.g. banners)
        if ftype == "note" and isinstance(value, dict):
            blob = json.dumps(value).lower()
            for tech in _infer_technologies(blob):
                graph.add_technology(tech, max(conf, 0.5), fact_id)
            for marker in WAF_MARKERS:
                if marker in blob:
                    graph.add_waf_indicator(f"note:{marker.strip()}", 0.4)
            # note values often carry path findings (e.g. legacy nikto
            # "/login.php: Admin login page") — lift them into the surface
            for m in re.finditer(r'"(/\.?[A-Za-z0-9_./-]{2,})', json.dumps(value)):
                path = m.group(1).rstrip("/")
                if len(path) > 3:
                    graph.add_surface(path)
    _enrich_surface_from_api(graph)
    return graph


def _default_target(conn, mission_id: int) -> str | None:
    """First scope host of a mission (used as the plan/graph asset)."""
    import json as _json
    row = conn.execute("SELECT allowed_hosts_json FROM missions WHERE id=?",
                       (mission_id,)).fetchone()
    if row is None:
        return None
    try:
        hosts = _json.loads(row[0] or "[]")
    except ValueError:
        return None
    return hosts[0] if hosts else None


def _enrich_surface_from_api(graph: EvidenceGraph) -> None:
    """Methodology 8: modern apps expose API surfaces — flag them explicitly."""
    for path in list(graph.attack_surface):
        for marker in API_MARKERS:
            if path.startswith(marker):
                graph.add_surface(path)
                break


# --- Scoring (methodology 13) ----------------------------------------------

SEVERITY_IMPACT = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3,
                   "info": 0.1}
SEVERITY_PRIORITY = {"critical": "P0", "high": "P1", "medium": "P2",
                     "low": "P3", "info": "-"}


def score_finding(confidence: float, severity: str,
                  exploitability: float = 0.5, exposure: float = 0.5,
                  waf: bool = False) -> dict:
    """Methodology 13 scoring: confidence x impact x exploitability x exposure.

    WAF-aware: when a WAF fronts the target, exposure is REDUCED
    automatically (the WAF is a mitigation layer) — a port being reachable
    is not the same as being exposed."""
    impact = SEVERITY_IMPACT.get((severity or "info").lower(), 0.1)
    if waf:
        exposure = exposure * 0.6  # mitigation layer discount
    overall = round(confidence * impact * exploitability * exposure, 3)
    return {
        "confidence": round(confidence, 2),
        "impact": impact,
        "exploitability": round(exploitability, 2),
        "exposure": round(exposure, 2),
        "severity": (severity or "info").lower(),
        "priority": SEVERITY_PRIORITY.get((severity or "info").lower(), "-"),
        "score": overall,
        "waf_discounted": bool(waf),
    }


def stack_profile(graph: EvidenceGraph) -> dict:
    """Methodology 11: characterize the target stack to pick the test branch."""
    WEB_PORTS = {80, 443, 3000, 8001, 8080, 8443, 8081, 5000}
    web_ports = [s["port"] for s in graph.services
                 if s["protocol"] in ("http", "https") or s["port"] in WEB_PORTS]
    techs = " ".join(t["name"] for t in graph.technologies).lower()
    surface = " ".join(graph.attack_surface).lower()
    profile = {
        "web": len(web_ports) > 0,
        "network": any(s["port"] in (21, 22, 445, 139, 3389, 1433, 3306, 5432, 6379)
                       for s in graph.services),
        "api": any(m in surface for m in ("/api", "/rest", "/graphql", "/swagger", "/openapi")),
        "graphql": "/graphql" in surface,
        "jwt": "jwt" in surface or "token" in surface,
        "auth_surface": any(m in surface for m in ("/login", "/register", "/admin", "/profile")),
        "server": next((t["name"] for t in graph.technologies
                        if t["name"].lower() in ("nginx", "apache", "iis", "tomcat", "jetty")), None),
        "language": next((t["name"] for t in graph.technologies
                          if t["name"].lower() in ("node.js", "php", "java", "ruby", "python", "go")), None),
    }
    return profile
