"""Canonical tests: Evidence Graph + Attack-Plan Engine (methodology 11-13).

Verifies: services/technologies/WAF/surface aggregation with confidence,
scoring model, web-api vs network branch selection, and the core rule
(every plan item is based_on evidence facts).
"""

import json
import tempfile
import unittest

from intected import db
from intected.evidence import (build_evidence_graph, score_finding,
                               stack_profile)
from intected.planner import build_plan, plan_for_mission


def _mission_with_facts(facts, targets=("127.0.0.1",)):
    fd, path = tempfile.mkstemp(suffix=".db")
    import os
    os.close(fd)
    conn = db.connect(path)
    db.init_db(conn)
    mid = db.create_mission(conn, "ev", list(targets), auth_ref="A")
    for tool, ftype, value, conf in facts:
        db.add_fact(conn, mid, tool, ftype, value,
                    evidence_ref=f"{tool}.raw",
                    sha256="ab" * 32, confidence=conf)
    return conn, mid, path


def _web_facts():
    return [
        ("nmap", "port", {"port": 3000, "protocol": "http"}, 1.0),
        ("nmap", "port", {"port": 8001, "protocol": "http"}, 1.0),
        ("nmap", "version", {"port": 8001,
                             "banner": "Apache httpd 2.4.25"}, 1.0),
        ("nmap", "version", {"port": 3000, "banner": "Node.js/Express"}, 0.9),
        ("nikto", "path", {"path": "/login.php"}, 1.0),
        ("nikto", "path", {"path": "/api/v1"}, 1.0),
        ("ffuf", "path", {"path": "/graphql"}, 1.0),
    ]


class EvidenceGraphTest(unittest.TestCase):
    def test_web_graph_aggregation(self):
        conn, mid, path = _mission_with_facts(_web_facts())
        try:
            g = build_evidence_graph(conn, mid)
            d = g.to_dict()
            ports = {s["port"] for s in d["services"]}
            self.assertEqual(ports, {3000, 8001})
            techs = {t["name"].lower() for t in d["technologies"]}
            self.assertTrue(techs & {"apache", "node.js", "express"})
            self.assertIn("/graphql", d["attack_surface"])
            self.assertIn("/api/v1", d["attack_surface"])
            self.assertTrue(d["fact_ids"])
        finally:
            conn.close()
            import os
            os.unlink(path)

    def test_waf_indicator(self):
        conn, mid, path = _mission_with_facts(
            [("note", "note", {"nikto": "Server: cloudflare-nginx"}, 0.5)])
        try:
            g = build_evidence_graph(conn, mid)
            self.assertTrue(g.waf["detected"])
            self.assertGreater(g.waf["confidence"], 0)
            self.assertTrue(g.waf["evidence"])
        finally:
            conn.close()
            import os
            os.unlink(path)

    def test_paths_lifted_from_notes(self):
        """Legacy nikto notes carry '/path: message' — lifted into surface."""
        conn, mid, path = _mission_with_facts(
            [("nikto", "note", {"nikto": "/login.php: Admin login page"}, 1.0),
             ("nikto", "note", {"nikto": "/config/: Directory indexing"}, 1.0)])
        try:
            g = build_evidence_graph(conn, mid)
            self.assertIn("/login.php", g.attack_surface)
            self.assertIn("/config", g.attack_surface)
        finally:
            conn.close()
            import os
            os.unlink(path)

    def test_scoring_priority(self):
        s = score_finding(confidence=0.9, severity="high",
                          exploitability=0.8, exposure=1.0)
        self.assertEqual(s["priority"], "P1")
        self.assertAlmostEqual(s["score"], 0.9 * 0.8 * 0.8 * 1.0)
        self.assertEqual(score_finding(1.0, "critical")["priority"], "P0")
        self.assertEqual(score_finding(1.0, "info")["priority"], "-")


class PlannerTest(unittest.TestCase):
    def test_web_branch_priorities(self):
        conn, mid, path = _mission_with_facts(_web_facts())
        try:
            graph = build_evidence_graph(conn, mid)
            prof = stack_profile(graph)
            self.assertTrue(prof["web"])
            self.assertTrue(prof["api"])
            self.assertTrue(prof["graphql"])
            plan = build_plan(graph)["plan"]
            areas = [p["area"] for p in plan]
            # auth first, infra last — the methodology's priority ordering
            self.assertTrue(areas[0].startswith("Authentication"))
            self.assertTrue(areas[-1].startswith("Infrastructure"))
            for item in plan:
                self.assertTrue(item["based_on"])  # every test is evidence-based
        finally:
            conn.close()
            import os
            os.unlink(path)

    def test_network_branch(self):
        facts = [
            ("nmap", "port", {"port": 22, "protocol": "tcp"}, 1.0),
            ("nmap", "port", {"port": 445, "protocol": "tcp"}, 1.0),
            ("nmap", "version", {"port": 22, "banner": "OpenSSH 8.9p1"}, 1.0),
        ]
        conn, mid, path = _mission_with_facts(facts)
        try:
            graph = build_evidence_graph(conn, mid)
            result = build_plan(graph)
            self.assertEqual(result["branch"], "network")
            self.assertEqual(result["plan"][0]["area"], "Service enumeration")
            self.assertTrue(any("OpenSSH" in c or "22" in c
                                for c in result["plan"][0]["commands"]))
        finally:
            conn.close()
            import os
            os.unlink(path)

    def test_empty_mission_plan(self):
        conn, mid, path = _mission_with_facts([])
        try:
            data = plan_for_mission(conn, mid)
            self.assertEqual(data["graph"]["services"], [])
            self.assertTrue(data["plan"]["plan"])
        finally:
            conn.close()
            import os
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
