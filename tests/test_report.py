"""Integration tests for the SMB report pipeline: grading edge cases (A/F/empty),
report HTML structure, checklist dedup + priority ordering, and auto-recon
script existence.  All tests use isolated temp-DB fixtures."""

import os
import tempfile
import unittest

from intected import db
from intected.grading import compute_grade, GradeReport
from intected.checklist import generate_checklist
from intected.dashboard import _render_report_html


class GradeTest(unittest.TestCase):
    """Grading edge cases: A (clean), F (multiple issues), empty, positives-only."""

    def test_grade_A(self):
        """Clean target (no high-risk ports, no CVEs, no exposed paths) → A (90+)."""
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        path = tmp.name; tmp.close()
        conn = db.connect(path)
        try:
            db.init_db(conn)
            mid = db.create_mission(conn, "clean-test", ["clean.example.com"])
            # low-risk port only — port 80/tcp is NOT in HIGH_RISK_PORTS
            db.add_fact(conn, mid, "nmap", "port",
                        {"port": 80, "protocol": "tcp"}, target="clean.example.com")
            db.add_fact(conn, mid, "nmap", "version",
                        {"port": 80, "banner": "nginx/1.24.0"}, target="clean.example.com")

            grade = compute_grade(conn, mid, "clean.example.com")

            self.assertEqual(grade.letter, "A",
                             f"Expected A, got {grade.letter}")
            self.assertGreaterEqual(grade.score, 90,
                                    f"Score {grade.score} should be ≥ 90")
            self.assertEqual(len(grade.deductions), 0,
                             "Clean target should have zero deductions")
            self.assertTrue(grade.positives,
                            "Should have at least one positive (RDP not open)")
            self.assertIn("3389", grade.positives[0].lower(),
                          "First positive should mention RDP port not open")
        finally:
            conn.close()
            os.unlink(path)

    def test_grade_F(self):
        """Multiple critical issues (RDP 3389, critical CVE, default creds,
        exposed /wp-admin) → F (<60)."""
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        path = tmp.name; tmp.close()
        conn = db.connect(path)
        try:
            db.init_db(conn)
            mid = db.create_mission(conn, "bad-test", ["bad.example.com"])
            # High-risk port
            db.add_fact(conn, mid, "nmap", "port",
                        {"port": 3389, "protocol": "tcp"}, target="bad.example.com")
            # Critical CVE
            db.add_fact(conn, mid, "nmap", "cve",
                        {"cve_id": "CVE-2024-0001", "severity": "critical",
                         "summary": "Remote code execution in Widget"}, target="bad.example.com")
            # Default credentials
            db.add_fact(conn, mid, "hydra", "credential",
                        {"service": "ssh", "username": "admin", "password": "admin"},
                        target="bad.example.com")
            # Exposed admin panel
            db.add_fact(conn, mid, "ffuf", "path",
                        {"path": "/wp-admin"}, target="bad.example.com")

            grade = compute_grade(conn, mid, "bad.example.com")

            self.assertEqual(grade.letter, "F",
                             f"Expected F, got {grade.letter}")
            self.assertLess(grade.score, 60,
                            f"Score {grade.score} should be < 60")
            # Verify all four deductions present (ordered by evaluation)
            reasons = [d["reason"] for d in grade.deductions]
            self.assertTrue(any("3389" in r for r in reasons),
                            "Should have RDP port 3389 deduction")
            self.assertTrue(any("CVE" in r for r in reasons),
                            "Should have CVE deduction")
            self.assertTrue(any("credentials" in r.lower() for r in reasons),
                            "Should have default credentials deduction")
            self.assertTrue(any("/wp-admin" in r for r in reasons),
                            "Should have exposed /wp-admin deduction")
        finally:
            conn.close()
            os.unlink(path)

    def test_grade_edge_cases(self):
        """No facts → still returns A (100).  Only positives → A."""
        # Edge case 1: no facts at all
        tmp1 = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        path1 = tmp1.name; tmp1.close()
        conn1 = db.connect(path1)
        try:
            db.init_db(conn1)
            mid1 = db.create_mission(conn1, "empty", ["no-facts.example.com"])
            grade1 = compute_grade(conn1, mid1, "no-facts.example.com")

            self.assertEqual(grade1.letter, "A",
                             f"Empty DB should return A, got {grade1.letter}")
            self.assertEqual(grade1.score, 100,
                             f"Empty DB should score 100, got {grade1.score}")
            self.assertEqual(len(grade1.deductions), 0,
                             "Empty DB should have zero deductions")
            self.assertEqual(grade1.fact_count, 0,
                             "Empty DB should have zero facts")
        finally:
            conn1.close()
            os.unlink(path1)

        # Edge case 2: only positive facts (low-risk port + version, no CVEs)
        tmp2 = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        path2 = tmp2.name; tmp2.close()
        conn2 = db.connect(path2)
        try:
            db.init_db(conn2)
            mid2 = db.create_mission(conn2, "positive", ["safe.example.com"])
            db.add_fact(conn2, mid2, "nmap", "port",
                        {"port": 443, "protocol": "tcp"}, target="safe.example.com")
            db.add_fact(conn2, mid2, "nmap", "version",
                        {"port": 443, "banner": "Apache/2.4.57"}, target="safe.example.com")

            grade2 = compute_grade(conn2, mid2, "safe.example.com")

            self.assertEqual(grade2.letter, "A",
                             f"Safe target should be A, got {grade2.letter}")
            self.assertGreaterEqual(grade2.score, 95,
                                    f"Safe target scored {grade2.score}, expected ≥95")
            self.assertEqual(len(grade2.deductions), 0,
                             "Safe target should have zero deductions")
            self.assertTrue(grade2.positives,
                            "Should have positives about RDP not open")
            self.assertGreater(grade2.fact_count, 0,
                               "Should have facts counted")
        finally:
            conn2.close()
            os.unlink(path2)


class ReportHtmlTest(unittest.TestCase):
    """Report HTML structure: grade card, executive summary, checklist, footer."""

    def test_report_html_structure(self):
        """Generate report HTML and assert all key structural elements present."""
        # Build a minimal GradeReport for rendering
        grade = GradeReport(
            score=85,
            letter="B",
            deductions=[
                {"reason": "Port 22/tcp open", "points": 15,
                 "detail": "SSH exposed"},
            ],
            positives=["Firewall properly configured for ports 80/443"],
            fact_count=5,
        )
        checklist = generate_checklist(
            grade, {"port": [{"value": {"port": 22}}]})

        html = _render_report_html("test.example.com", grade,
                                   "Executive summary paragraph.", checklist,
                                   {"port": [], "cve": []})

        # Core structural elements
        self.assertIn('<div class="grade-letter">', html,
                      "Report must contain grade-letter div")
        self.assertIn('B</div>', html,
                      "Grade letter 'B' must appear in the grade card")

        self.assertIn('<h2>Executive Summary</h2>', html,
                      "Report must have Executive Summary section")
        self.assertIn('<h2>Checklist for Your IT Team</h2>', html,
                      "Report must have Checklist section with full title")
        self.assertIn('<h2>Risk Breakdown</h2>', html,
                      "Report must have Risk Breakdown section")

        # Footer
        self.assertIn("RedAegis", html,
                      "Report footer must mention RedAegis")
        self.assertIn("redaegis.io", html,
                      "Report footer must include redaegis.io domain")

        # Document structure
        self.assertTrue(html.strip().startswith("<!DOCTYPE html>"),
                        "Report must be valid HTML5 doctype")
        self.assertIn("</html>", html,
                      "Report must have closing </html> tag")


class ChecklistTest(unittest.TestCase):
    """Checklist deduplication and priority ordering."""

    def test_checklist_dedup(self):
        """Two identical deductions → produce ONE checklist item (dedup by title)."""
        grade = GradeReport(
            score=70,
            letter="C",
            deductions=[
                {"reason": "Port 3389/tcp open", "points": 15,
                 "detail": "RDP port is reachable"},
                {"reason": "Port 3389/tcp open", "points": 15,
                 "detail": "RDP port is reachable (duplicate detection)"},
            ],
            positives=[],
            fact_count=2,
        )
        facts = {"port": [{"value": {"port": 3389}}]}

        checklist = generate_checklist(grade, facts)

        # Dedup should collapse identical titles to one
        titles = [c["title"] for c in checklist]
        self.assertEqual(len(titles), len(set(titles)),
                         f"Checklist titles should be unique, got: {titles}")

        # Specifically, only ONE RDP item
        rdp_items = [c for c in checklist
                     if "RDP" in c["title"] or "Remote Desktop" in c["title"]]
        self.assertEqual(len(rdp_items), 1,
                         f"Should have exactly one RDP item, got {len(rdp_items)}: {[c['title'] for c in rdp_items]}")

        self.assertEqual(len(checklist), 1,
                         f"Checklist should have 1 unique item from 2 identical deductions, got {len(checklist)}")

    def test_checklist_priority_order(self):
        """Critical items come before high before medium before low."""
        grade = GradeReport(
            score=50,
            letter="F",
            deductions=[
                # Order in the deductions list should NOT matter —
                # the checklist must sort by priority
                {"reason": "CORS wildcard (*)", "points": 8,
                 "detail": "CORS misconfiguration"},
                {"reason": "Port 3389/tcp open", "points": 15,
                 "detail": "RDP reachable"},
                {"reason": "Exposed admin path /config", "points": 10,
                 "detail": "Config file exposed"},
                {"reason": "Port 23/tcp open", "points": 15,
                 "detail": "Telnet exposed"},
            ],
            positives=[],
            fact_count=4,
        )
        facts = {"port": [{"value": {"port": 3389}}, {"value": {"port": 23}}]}

        checklist = generate_checklist(grade, facts)

        priorities = [c["priority"] for c in checklist]
        # Expected: critical (3389, 23) before high (/config) before medium (CORS)
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for i in range(1, len(priorities)):
            prev_rank = priority_order.get(priorities[i - 1], 99)
            curr_rank = priority_order.get(priorities[i], 99)
            self.assertLessEqual(
                prev_rank, curr_rank,
                f"Priority order violation: {priorities[i-1]} before {priorities[i]} "
                f"at indices [{i-1},{i}]. Full order: {priorities}"
            )

        # Verify all expected categories appear
        self.assertIn("critical", priorities,
                      "Should have at least one critical item")
        self.assertIn("medium", priorities,
                      "Should have at least one medium item (CORS)")
        self.assertIn("high", priorities,
                      "Should have at least one high item (/config)")

        # Critical items must come before medium
        first_critical = priorities.index("critical")
        first_medium = priorities.index("medium")
        self.assertLess(first_critical, first_medium,
                        "Critical items must precede medium items")


class AutoReconScriptTest(unittest.TestCase):
    """Verify scripts/auto-recon.sh exists, is executable, and has required content."""

    def setUp(self):
        self.script_path = os.path.join(
            os.path.dirname(__file__), "..", "scripts", "auto-recon.sh")
        self.script_path = os.path.abspath(self.script_path)

    def test_script_exists(self):
        """auto-recon.sh must exist on disk."""
        self.assertTrue(
            os.path.isfile(self.script_path),
            f"auto-recon.sh missing at {self.script_path}")

    def test_script_executable(self):
        """auto-recon.sh must be executable."""
        self.assertTrue(
            os.access(self.script_path, os.X_OK),
            f"auto-recon.sh at {self.script_path} is not executable")

    def test_shebang(self):
        """auto-recon.sh must have proper #!/bin/bash shebang on line 1."""
        with open(self.script_path, "r", encoding="utf-8") as f:
            first_line = f.readline().strip()
        self.assertEqual(
            first_line, "#!/bin/bash",
            f"First line must be '#!/bin/bash', got: {first_line!r}")

    def test_key_lines(self):
        """Script must contain: recon command, report generation, QA smoke test calls."""
        with open(self.script_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Recon command invocation
        self.assertIn("intected recon", content,
                      "Script must contain the recon command invocation")

        # Report generation (grade computation)
        self.assertIn("compute_grade", content,
                      "Script must compute the grade for the report")

        # QA smoke test: pytest
        self.assertIn("pytest", content,
                      "QA smoke test must run pytest")

        # QA smoke test: curl-based endpoint checks
        self.assertIn("curl", content,
                      "QA smoke test must use curl to probe dashboard endpoints")

        # Reference to mission 8 (the production mission)
        self.assertIn("mission 8", content.lower().replace("-", " "),
                      "Script must reference mission 8")


    def test_summary_validation_guard(self):
        """Hallucination guard rejects summaries that contradict known facts."""
        from intected.summary import _validate_summary
        from intected.grading import GradeReport
        # Grade with deductions
        grade = GradeReport(score=75, letter='C',
            deductions=[{'reason': 'Port 22 open', 'points': 15, 'detail': 'SSH'}],
            positives=['No RDP'], fact_count=15)
        # Valid summary — mentions grade, doesn't claim "secure"
        self.assertTrue(_validate_summary(
            "Your security grade is a C. You have an open SSH port that needs attention.", grade))
        # Hallucination: claims "secure" despite deductions
        self.assertFalse(_validate_summary(
            "Your network is secure and has no issues. Grade: C.", grade))
        # No grade letter mentioned
        self.assertFalse(_validate_summary(
            "Everything looks good here. No problems found.", grade))
        # Too short
        self.assertFalse(_validate_summary("OK", grade))
        # Grade A with no deductions — "all clear" is OK then
        grade_a = GradeReport(score=100, letter='A', deductions=[], positives=[], fact_count=0)
        self.assertTrue(_validate_summary(
            "Your security grade is A. All clear — no issues found.", grade_a))


if __name__ == "__main__":
    unittest.main()
