"""Tests for compliance framework mapping: NIST CSF 2.0 + CIS Controls v8."""

import json
import os
import tempfile
import unittest
import sys

from intected import db
from intected.grading import compute_grade, GradeReport
from intected.compliance import (
    COMPLIANCE_MAP,
    compliance_summary,
    format_compliance_summary,
    ComplianceSummary,
    NIST_CSF_CATEGORIES,
    CIS_CONTROLS,
)


def _mission_with_facts(facts, targets=("127.0.0.1",)):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = db.connect(path)
    db.init_db(conn)
    mid = db.create_mission(conn, "compliance-test", list(targets), auth_ref="A-1")
    for tool, ftype, value, conf in facts:
        db.add_fact(conn, mid, tool, ftype, value,
                    evidence_ref=f"{tool}.raw",
                    sha256="ab" * 32, confidence=conf)
    return conn, mid, path


class ComplianceMapTest(unittest.TestCase):
    """Test the COMPLIANCE_MAP structure and coverage."""

    def test_all_db_fact_types_mapped(self):
        """Every fact_type in db.FACT_TYPES must have a COMPLIANCE_MAP entry."""
        for ftype in db.FACT_TYPES:
            with self.subTest(ftype=ftype):
                self.assertIn(ftype, COMPLIANCE_MAP,
                              f"fact_type '{ftype}' missing from COMPLIANCE_MAP")

    def test_header_fact_type_mapped(self):
        """header fact_type (security headers) is mapped."""
        self.assertIn("header", COMPLIANCE_MAP)

    def test_all_mappings_have_nist_subcategories(self):
        """Every mapping must have at least 1 NIST subcategory."""
        for ftype, mapping in COMPLIANCE_MAP.items():
            with self.subTest(ftype=ftype):
                self.assertGreater(len(mapping.nist_subcategories), 0,
                                   f"{ftype} has no NIST subcategories")
                self.assertGreater(len(mapping.cis_controls), 0,
                                   f"{ftype} has no CIS controls")

    def test_nist_categories_valid(self):
        """All NIST subcategories referenced must exist in NIST_CSF_CATEGORIES."""
        for ftype, mapping in COMPLIANCE_MAP.items():
            for nist in mapping.nist_subcategories:
                cat_root = nist.split("-")[0] if "-" in nist else nist
                with self.subTest(ftype=ftype, nist=nist):
                    self.assertIn(cat_root, NIST_CSF_CATEGORIES,
                                  f"{nist} root '{cat_root}' unknown in NIST_CSF_CATEGORIES")

    def test_cis_controls_valid(self):
        """All CIS control numbers must be valid (1-18)."""
        for ftype, mapping in COMPLIANCE_MAP.items():
            for ctrl in mapping.cis_controls:
                with self.subTest(ftype=ftype, cis=ctrl):
                    self.assertIn(ctrl, CIS_CONTROLS,
                                  f"CIS Control {ctrl} not in CIS_CONTROLS")
                    self.assertGreaterEqual(ctrl, 1)
                    self.assertLessEqual(ctrl, 18)

    def test_cve_maps_to_nist_id_ra1(self):
        """CVE fact type must map to NIST ID.RA-1."""
        mapping = COMPLIANCE_MAP["cve"]
        self.assertIn("ID.RA-1", mapping.nist_subcategories)

    def test_port_maps_to_nist_de_cm8(self):
        """Port fact type must map to NIST DE.CM-8."""
        mapping = COMPLIANCE_MAP["port"]
        self.assertIn("DE.CM-8", mapping.nist_subcategories)

    def test_credential_maps_to_nist_pr_ac1(self):
        """Credential fact type must map to NIST PR.AC-1."""
        mapping = COMPLIANCE_MAP["credential"]
        self.assertIn("PR.AC-1", mapping.nist_subcategories)


class ComplianceSummaryTest(unittest.TestCase):
    """Test the compliance_summary() function."""

    def test_empty_mission_zero_scores(self):
        """Mission with no facts should yield zero scores."""
        grade = GradeReport(score=100, letter="A", deductions=[], positives=[],
                            fact_count=0)
        summary = compliance_summary(grade, {})
        self.assertEqual(summary.nist_score, 0)
        self.assertEqual(summary.cis_score, 0)
        self.assertEqual(summary.nist_covered, 0)
        self.assertEqual(summary.cis_covered, 0)
        self.assertGreater(len(summary.gaps), 0)

    def test_port_fact_covers_controls(self):
        """A port fact should cover its mapped NIST + CIS controls."""
        grade = GradeReport(score=85, letter="B",
                            deductions=[{"reason": "Port 3389/tcp open", "points": 15,
                                         "detail": "RDP exposed"}],
                            positives=[],
                            fact_count=1)
        facts = {"port": [{"id": 1, "mission_id": 1, "tool": "nmap",
                           "fact_type": "port", "value": {"port": 3389}}]}
        summary = compliance_summary(grade, facts)

        self.assertGreater(summary.nist_score, 0)
        self.assertGreater(summary.cis_score, 0)
        self.assertGreater(summary.nist_covered, 0)

        # Port maps to DE.CM-8 and ID.AM-1
        nist_ids = {c["control_id"] for c in summary.mapped_controls
                    if c["framework"] == "NIST CSF 2.0" and c["status"] == "addressed"}
        self.assertIn("DE.CM-8", nist_ids)
        self.assertIn("ID.AM-1", nist_ids)

        # Port maps to CIS 4 and 12
        cis_ids = {c["control_id"] for c in summary.mapped_controls
                   if c["framework"] == "CIS Controls v8" and c["status"] == "addressed"}
        self.assertIn("4", cis_ids)
        self.assertIn("12", cis_ids)

    def test_cve_fact_covers_controls(self):
        """A CVE fact should map to ID.RA-1 and CIS 7."""
        grade = GradeReport(score=70, letter="C",
                            deductions=[{"reason": "CVE CVE-2021-44228 (critical)",
                                         "points": 30, "detail": "Log4Shell"}],
                            positives=[],
                            fact_count=1)
        facts = {"cve": [{"id": 1, "mission_id": 1, "tool": "nuclei",
                          "fact_type": "cve",
                          "value": {"cve_id": "CVE-2021-44228", "severity": "critical"}}]}
        summary = compliance_summary(grade, facts)

        nist_ids = {c["control_id"] for c in summary.mapped_controls
                    if c["framework"] == "NIST CSF 2.0" and c["status"] == "addressed"}
        self.assertIn("ID.RA-1", nist_ids)

        cis_ids = {c["control_id"] for c in summary.mapped_controls
                   if c["framework"] == "CIS Controls v8" and c["status"] == "addressed"}
        self.assertIn("7", cis_ids)

    def test_multiple_fact_types_cover_more(self):
        """More fact types → higher scores."""
        grade = GradeReport(score=50, letter="F",
                            deductions=[{"reason": "Many issues", "points": 50,
                                         "detail": "..."}],
                            positives=[],
                            fact_count=5)

        # Only port
        summary1 = compliance_summary(grade, {
            "port": [{"id": 1, "mission_id": 1, "tool": "nmap",
                      "fact_type": "port", "value": {"port": 80}}]})

        # Port + cve + credential
        summary2 = compliance_summary(grade, {
            "port": [{"id": 1, "mission_id": 1, "tool": "nmap",
                      "fact_type": "port", "value": {"port": 80}}],
            "cve": [{"id": 2, "mission_id": 1, "tool": "nuclei",
                     "fact_type": "cve",
                     "value": {"cve_id": "CVE-2022-0001", "severity": "high"}}],
            "credential": [{"id": 3, "mission_id": 1, "tool": "hydra",
                            "fact_type": "credential",
                            "value": {"username": "admin", "password": "admin"}}],
        })

        self.assertGreater(summary2.nist_score, summary1.nist_score,
                           "More fact types should yield higher NIST coverage")
        self.assertGreater(summary2.cis_score, summary1.cis_score,
                           "More fact types should yield higher CIS coverage")

    def test_compliance_summary_has_grade_report(self):
        """ComplianceSummary carries the grade report."""
        grade = GradeReport(score=90, letter="A", deductions=[], positives=[],
                            fact_count=0)
        summary = compliance_summary(grade, {})
        self.assertEqual(summary.grade_report.score, 90)
        self.assertEqual(summary.grade_report.letter, "A")

    def test_gaps_are_controls_with_no_evidence(self):
        """Gaps list should contain controls not addressed."""
        grade = GradeReport(score=100, letter="A", deductions=[], positives=[],
                            fact_count=0)
        # Only port facts
        facts = {"port": [{"id": 1, "mission_id": 1, "tool": "nmap",
                           "fact_type": "port", "value": {"port": 80}}]}
        summary = compliance_summary(grade, facts)

        self.assertGreater(len(summary.gaps), 0,
                           "Should have gaps when only one fact type present")
        # All gaps should be actual unfilled controls
        covered_nist = {c["control_id"] for c in summary.mapped_controls
                        if c["framework"] == "NIST CSF 2.0" and c["status"] == "addressed"}
        gap_nist = {g["control_id"] for g in summary.gaps
                    if g["framework"] == "NIST CSF 2.0"}
        self.assertTrue(covered_nist.isdisjoint(gap_nist),
                        "Gaps should not overlap with covered controls")


class ComplianceEndToEndTest(unittest.TestCase):
    """End-to-end tests with the real DB + compute_grade."""

    def test_full_pipeline_port_and_cve(self):
        """Real DB with port + CVE facts → compliance scores > 0."""
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 3389, "protocol": "tcp"}, 1.0),
            ("nuclei", "cve", {"cve_id": "CVE-2021-44228", "severity": "critical",
                               "summary": "Log4Shell RCE"}, 1.0),
        ])
        try:
            from intected.compliance import _load_facts
            facts = _load_facts(conn, mid, None)
            grade = compute_grade(conn, mid)
            summary = compliance_summary(grade, facts)

            self.assertGreater(summary.nist_score, 0)
            self.assertGreater(summary.cis_score, 0)
            self.assertTrue(any(c["status"] == "addressed" for c in summary.mapped_controls))
            self.assertIsNotNone(summary.grade_report)
        finally:
            conn.close()
            os.unlink(path)

    def test_full_pipeline_empty(self):
        """Mission with no facts → zero scores."""
        conn, mid, path = _mission_with_facts([])
        try:
            from intected.compliance import _load_facts
            facts = _load_facts(conn, mid, None)
            grade = compute_grade(conn, mid)
            summary = compliance_summary(grade, facts)

            self.assertEqual(summary.nist_score, 0)
            self.assertEqual(summary.cis_score, 0)
        finally:
            conn.close()
            os.unlink(path)


class ComplianceFormatTest(unittest.TestCase):
    """Test the format_compliance_summary() output."""

    def test_format_includes_scores(self):
        """Formatted output shows NIST and CIS scores."""
        summary = ComplianceSummary(
            nist_score=42, nist_covered=5, nist_total=12,
            cis_score=33, cis_covered=3, cis_total=9,
            mapped_controls=[
                {"control_id": "ID.RA-1", "framework": "NIST CSF 2.0",
                 "category": "Risk Assessment", "label": "",
                 "status": "addressed", "evidence_count": 2},
                {"control_id": "7", "framework": "CIS Controls v8",
                 "category": "", "label": "Continuous Vulnerability Management",
                 "status": "addressed", "evidence_count": 1},
            ],
            gaps=[
                {"control_id": "ID.AM-1", "framework": "NIST CSF 2.0",
                 "label": "Asset Management"},
            ],
            grade_report=GradeReport(score=85, letter="B",
                                     deductions=[], positives=[], fact_count=3),
        )
        output = format_compliance_summary(summary)
        self.assertIn("NIST CSF 2.0", output)
        self.assertIn("CIS Controls v8", output)
        self.assertIn("42%", output)
        self.assertIn("33%", output)
        self.assertIn("ADDRESSED", output)
        self.assertIn("GAPS", output)
        self.assertIn("B (85/100)", output)

    def test_format_no_gaps(self):
        """When there are no gaps, GAPS section should not appear."""
        summary = ComplianceSummary(
            nist_score=100, nist_covered=10, nist_total=10,
            cis_score=100, cis_covered=10, cis_total=10,
            mapped_controls=[],
            gaps=[],
            grade_report=None,
        )
        output = format_compliance_summary(summary)
        self.assertNotIn("GAPS", output)


class ComplianceCLITest(unittest.TestCase):
    """Test the `intected compliance` CLI command."""

    def test_compliance_command_help(self):
        """Verify the compliance subcommand is registered."""
        from intected.cli import main
        with self.assertRaises(SystemExit) as cm:
            main(["compliance", "--help"])
        self.assertEqual(cm.exception.code, 0)

    def test_compliance_command_no_mission(self):
        """Compliance without --mission should error."""
        from intected.cli import main
        with self.assertRaises(SystemExit):
            main(["compliance"])

    def test_compliance_command_bad_mission(self):
        """Non-existent mission returns error."""
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        conn = db.connect(path)
        db.init_db(conn)
        conn.close()

        try:
            from intected.cli import main
            import intected.config as cfg
            old_db = cfg.DB_PATH
            cfg.DB_PATH = path
            try:
                rc = main(["compliance", "--mission", "99999"])
                self.assertNotEqual(rc, 0,
                                    "Non-existent mission should return non-zero")
            finally:
                cfg.DB_PATH = old_db
        finally:
            os.unlink(path)

    def test_compliance_command_runs(self):
        """Compliance runs successfully with a valid mission."""
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        conn = db.connect(path)
        db.init_db(conn)
        mid = db.create_mission(conn, "compliance-cli", ["127.0.0.1"], auth_ref="A-1")
        db.add_fact(conn, mid, "nmap", "port", {"port": 80, "protocol": "tcp"},
                    evidence_ref="x.raw", sha256="ab" * 32)
        db.add_fact(conn, mid, "nuclei", "cve",
                    {"cve_id": "CVE-2021-44228", "severity": "critical"},
                    evidence_ref="y.raw", sha256="cd" * 32)
        conn.close()

        try:
            from intected.cli import main
            import intected.config as cfg
            old_db = cfg.DB_PATH
            cfg.DB_PATH = path
            try:
                rc = main(["compliance", "--mission", str(mid)])
                self.assertEqual(rc, 0)
            finally:
                cfg.DB_PATH = old_db
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
