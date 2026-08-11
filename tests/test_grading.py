"""Tests for the SMB grading engine: version patterns, header checking,
and report CLI command."""

import json
import os
import tempfile
import unittest
import sys
from unittest import mock

from intected import db
from intected.grading import (compute_grade, _load_facts, _scan_notes_for_headers,
                               _VERSION_PATTERNS, GradeReport)
from intected.checklist import generate_checklist, TECH_REMEDIATIONS, _match_tech_keyword
from intected.summary import _build_fallback_summary


def _mission_with_facts(facts, targets=("127.0.0.1",)):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = db.connect(path)
    db.init_db(conn)
    mid = db.create_mission(conn, "grading-test", list(targets), auth_ref="A-1")
    for tool, ftype, value, conf in facts:
        db.add_fact(conn, mid, tool, ftype, value,
                    evidence_ref=f"{tool}.raw",
                    sha256="ab" * 32, confidence=conf)
    return conn, mid, path


def _tech_fact(tech_name: str, confidence: float = 1.0):
    """Create a technology fact that will appear in the evidence graph."""
    return ("note", "note", {"technology": tech_name}, confidence)


class VersionPatternTest(unittest.TestCase):
    """Test that the expanded version pattern library catches various EOL software."""

    def test_wordpress_4x_detected(self):
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 80, "protocol": "tcp"}, 1.0),
            ("note", "note", {"technology": "WordPress 4.9.1"}, 1.0),
        ])
        try:
            grade = compute_grade(conn, mid)
            self.assertTrue(any("WordPress 3.x/4.x" in d["reason"] for d in grade.deductions),
                            f"Deductions: {grade.deductions}")
        finally:
            conn.close()
            os.unlink(path)

    def test_wordpress_5x_below_59_detected(self):
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 80, "protocol": "tcp"}, 1.0),
            ("note", "note", {"technology": "WordPress 5.7.1"}, 1.0),
        ])
        try:
            grade = compute_grade(conn, mid)
            self.assertTrue(any("WordPress 5.x < 5.9" in d["reason"] for d in grade.deductions))
        finally:
            conn.close()
            os.unlink(path)

    def test_wordpress_59_is_fine(self):
        """WordPress 5.9+ should not trigger the <5.9 pattern."""
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 80, "protocol": "tcp"}, 1.0),
            ("note", "note", {"technology": "WordPress 5.9.3"}, 1.0),
        ])
        try:
            grade = compute_grade(conn, mid)
            self.assertFalse(any("WordPress" in d["reason"] for d in grade.deductions))
        finally:
            conn.close()
            os.unlink(path)

    def test_drupal_7x_detected(self):
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 80, "protocol": "tcp"}, 1.0),
            ("note", "note", {"technology": "Drupal 7.80"}, 1.0),
        ])
        try:
            grade = compute_grade(conn, mid)
            self.assertTrue(any("Drupal 7.x" in d["reason"] for d in grade.deductions))
        finally:
            conn.close()
            os.unlink(path)

    def test_php5x_detected(self):
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 80, "protocol": "tcp"}, 1.0),
            ("nmap", "version", {"port": 80, "banner": "Apache/2.4.7 PHP/5.6.40"}, 1.0),
        ])
        try:
            grade = compute_grade(conn, mid)
            self.assertTrue(any("PHP 5.x" in d["reason"] for d in grade.deductions))
        finally:
            conn.close()
            os.unlink(path)

    def test_php73_eol_detected(self):
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 80, "protocol": "tcp"}, 1.0),
            ("nmap", "version", {"port": 80, "banner": "PHP/7.3.33"}, 1.0),
        ])
        try:
            grade = compute_grade(conn, mid)
            self.assertTrue(any("PHP 7.x < 7.4" in d["reason"] for d in grade.deductions))
        finally:
            conn.close()
            os.unlink(path)

    def test_openssl_10x_detected(self):
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 443, "protocol": "tcp"}, 1.0),
            ("nmap", "version", {"port": 443, "banner": "OpenSSL 1.0.2k-fips"}, 1.0),
        ])
        try:
            grade = compute_grade(conn, mid)
            self.assertTrue(any("OpenSSL 1.0.x" in d["reason"] for d in grade.deductions))
        finally:
            conn.close()
            os.unlink(path)

    def test_nginx_below_118_detected(self):
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 80, "protocol": "tcp"}, 1.0),
            ("nmap", "version", {"port": 80, "banner": "nginx 1.12.2"}, 1.0),
        ])
        try:
            grade = compute_grade(conn, mid)
            self.assertTrue(any("nginx < 1.18" in d["reason"] for d in grade.deductions))
        finally:
            conn.close()
            os.unlink(path)

    def test_iis_7x_detected(self):
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 80, "protocol": "tcp"}, 1.0),
            ("nmap", "version", {"port": 80, "banner": "Microsoft-IIS/7.5"}, 1.0),
        ])
        try:
            grade = compute_grade(conn, mid)
            self.assertTrue(any("IIS 7.x" in d["reason"] for d in grade.deductions))
        finally:
            conn.close()
            os.unlink(path)

    def test_exchange_2013_detected(self):
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 443, "protocol": "tcp"}, 1.0),
            ("nmap", "version", {"port": 443, "banner": "Exchange Server 2013 CU23"}, 1.0),
        ])
        try:
            grade = compute_grade(conn, mid)
            self.assertTrue(any("Exchange 2010-2016" in d["reason"] for d in grade.deductions))
        finally:
            conn.close()
            os.unlink(path)

    def test_jenkins_detected(self):
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 8080, "protocol": "tcp"}, 1.0),
            ("note", "note", {"technology": "Jenkins 2.332.1"}, 1.0),
        ])
        try:
            grade = compute_grade(conn, mid)
            self.assertTrue(any("Jenkins" in d["reason"] for d in grade.deductions))
        finally:
            conn.close()
            os.unlink(path)

    def test_docker_api_exposed_detected(self):
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 2375, "protocol": "tcp"}, 1.0),
            ("nmap", "version", {"port": 2375, "banner": "Docker API version 1.41"}, 1.0),
        ])
        try:
            grade = compute_grade(conn, mid)
            self.assertTrue(any("Docker API" in d["reason"] for d in grade.deductions))
        finally:
            conn.close()
            os.unlink(path)

    def test_phpmyadmin_3x_detected(self):
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 80, "protocol": "tcp"}, 1.0),
            ("note", "note", {"technology": "phpMyAdmin 3.5.8"}, 1.0),
        ])
        try:
            grade = compute_grade(conn, mid)
            self.assertTrue(any("phpMyAdmin 3.x/4.x" in d["reason"] for d in grade.deductions))
        finally:
            conn.close()
            os.unlink(path)

    def test_synology_dsm_detected(self):
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 5000, "protocol": "tcp"}, 1.0),
            ("nmap", "version", {"port": 5000, "banner": "Synology DSM 6.2.4"}, 1.0),
        ])
        try:
            grade = compute_grade(conn, mid)
            self.assertTrue(any("Synology" in d["reason"] for d in grade.deductions))
        finally:
            conn.close()
            os.unlink(path)

    def test_unifi_detected(self):
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 8443, "protocol": "tcp"}, 1.0),
            ("note", "note", {"technology": "UniFi Network 6.5.55"}, 1.0),
        ])
        try:
            grade = compute_grade(conn, mid)
            self.assertTrue(any("UniFi" in d["reason"] for d in grade.deductions))
        finally:
            conn.close()
            os.unlink(path)


class HeaderCheckingTest(unittest.TestCase):
    """Test that missing security headers are detected and scored."""

    def test_no_header_notes_no_deductions(self):
        """When there are no header-related notes, no header deductions should fire."""
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 80, "protocol": "tcp"}, 1.0),
        ])
        try:
            grade = compute_grade(conn, mid)
            self.assertFalse(any("Missing security header" in d["reason"] for d in grade.deductions))
        finally:
            conn.close()
            os.unlink(path)

    def test_partial_headers_trigger_missing(self):
        """When only some security headers are present, missing ones are flagged."""
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 80, "protocol": "tcp"}, 1.0),
            ("http_headers", "note", {
                "response_headers": (
                    "HTTP/1.1 200 OK\r\n"
                    "Date: Mon, 11 Aug 2026\r\n"
                    "Content-Security-Policy: default-src 'self'\r\n"
                    "X-Frame-Options: DENY\r\n"
                    "Content-Type: text/html\r\n"
                )
            }, 1.0),
        ])
        try:
            grade = compute_grade(conn, mid)
            deductions = [d for d in grade.deductions if "Missing security header" in d["reason"]]
            # CSP and XFO are present, but HSTS, XCTO, RP, PP are missing
            self.assertGreater(len(deductions), 0)
            missing = {d["reason"] for d in deductions}
            self.assertIn("Missing security header: Strict-Transport-Security", missing)
            self.assertIn("Missing security header: X-Content-Type-Options", missing)
        finally:
            conn.close()
            os.unlink(path)

    def test_all_headers_present_no_deductions(self):
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 80, "protocol": "tcp"}, 1.0),
            ("http_headers", "note", {
                "response_headers": (
                    "Content-Security-Policy: default-src 'self'\n"
                    "Strict-Transport-Security: max-age=31536000\n"
                    "X-Frame-Options: DENY\n"
                    "X-Content-Type-Options: nosniff\n"
                    "Referrer-Policy: strict-origin-when-cross-origin\n"
                    "Permissions-Policy: camera=()"
                )
            }, 1.0),
        ])
        try:
            grade = compute_grade(conn, mid)
            deductions = [d for d in grade.deductions if "Missing security header" in d["reason"]]
            self.assertEqual(len(deductions), 0)
            # should have positive findings for present headers
            headers_found = [p for p in grade.positives if "Security header present" in p]
            self.assertGreater(len(headers_found), 0)
        finally:
            conn.close()
            os.unlink(path)


class ChecklistTest(unittest.TestCase):
    """Test the tech-specific remediation templates and matching."""

    def test_synology_remediation_matched(self):
        kw = _match_tech_keyword("Outdated software: Synology DSM 4-6")
        self.assertEqual(kw, "synology")
        self.assertIn("synology", TECH_REMEDIATIONS)

    def test_unifi_remediation_matched(self):
        kw = _match_tech_keyword("Outdated software: UniFi 5.x/6.x")
        self.assertEqual(kw, "unifi")
        priority, title, steps = TECH_REMEDIATIONS["unifi"]
        self.assertEqual(priority, "critical")
        self.assertIn("ubnt", steps.lower())

    def test_wordpress_remediation_matched(self):
        kw = _match_tech_keyword("Outdated software: WordPress 3.x/4.x")
        self.assertEqual(kw, "wordpress")

    def test_exchange_remediation_matched(self):
        kw = _match_tech_keyword("Outdated software: Exchange 2010-2016")
        self.assertEqual(kw, "exchange")

    def test_docker_api_remediation_matched(self):
        kw = _match_tech_keyword("Outdated software: Docker API exposed")
        self.assertEqual(kw, "docker api")
        priority, title, steps = TECH_REMEDIATIONS["docker api"]
        self.assertIn("2375", steps)

    def test_all_tech_templates_have_required_keys(self):
        """Every tech remediation entry must have 3 elements: priority, title, steps."""
        for kw, entry in TECH_REMEDIATIONS.items():
            with self.subTest(kw=kw):
                self.assertIsInstance(entry, tuple, f"{kw} entry is not a tuple")
                self.assertEqual(len(entry), 3, f"{kw} entry has {len(entry)} elements, expected 3")
                priority, title, steps = entry
                self.assertIn(priority, ("critical", "high", "medium", "low"))
                self.assertIsInstance(title, str)
                self.assertGreater(len(title), 0)
                self.assertIsInstance(steps, str)
                self.assertGreater(len(steps), 50)

    def test_generate_checklist_with_tech_deductions(self):
        """Full pipeline: deductions → checklist with tech-specific items."""
        conn, mid, path = _mission_with_facts([
            ("nmap", "port", {"port": 80, "protocol": "tcp"}, 1.0),
            ("note", "note", {"technology": "WordPress 4.9.1"}, 1.0),
            ("nmap", "port", {"port": 5000, "protocol": "tcp"}, 1.0),
            ("nmap", "version", {"port": 5000, "banner": "Synology DSM 6.2.4"}, 1.0),
        ])
        try:
            grade = compute_grade(conn, mid)
            checklist = generate_checklist(grade, {})
            titles = {c["title"] for c in checklist}
            self.assertIn("Lock down your Synology NAS", titles)
            self.assertIn("Harden your WordPress site", titles)
        finally:
            conn.close()
            os.unlink(path)


class FallbackSummaryTest(unittest.TestCase):
    """Test the improved fallback summary generator."""

    def test_fallback_includes_grade_and_issue_count(self):
        grade = GradeReport(score=65, letter="D",
                            deductions=[{"reason": "Port 3389/tcp open", "points": 15,
                                         "detail": "RDP exposed"}],
                            positives=["Some good things"],
                            fact_count=10)
        summary = _build_fallback_summary(grade, {"port": []})
        self.assertIn("D (65/100)", summary)
        self.assertIn("1 security issue", summary)
        self.assertIn("WHAT TO DO TODAY", summary)
        self.assertIn("RDP", summary)

    def test_fallback_clean_scan(self):
        grade = GradeReport(score=100, letter="A",
                            deductions=[],
                            positives=["All good"],
                            fact_count=5)
        summary = _build_fallback_summary(grade, {"port": []})
        self.assertIn("A (100/100)", summary)
        self.assertIn("0 security issue", summary)
        self.assertIn("security posture looks solid", summary)

    def test_fallback_credential_focus(self):
        grade = GradeReport(score=40, letter="F",
                            deductions=[{"reason": "Default/weak credentials found", "points": 25,
                                         "detail": "default passwords"}],
                            positives=[],
                            fact_count=3)
        summary = _build_fallback_summary(grade, {"credential": [{"value": {}}]})
        self.assertIn("change all default passwords", summary)


class ReportCLITest(unittest.TestCase):
    """Test the `intected report` CLI command."""

    def test_report_command_help(self):
        """Verify the report subcommand is registered."""
        from intected.cli import main
        with self.assertRaises(SystemExit) as cm:
            main(["report", "--help"])
        self.assertEqual(cm.exception.code, 0)

    def test_report_command_no_mission(self):
        """Report without --mission should error cleanly."""
        from intected.cli import main
        with self.assertRaises(SystemExit):
            main(["report"])

    def test_report_command_runs(self):
        """Report runs successfully with a valid mission."""
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        conn = db.connect(path)
        db.init_db(conn)
        mid = db.create_mission(conn, "report-test", ["127.0.0.1"], auth_ref="A-1")
        db.add_fact(conn, mid, "nmap", "port", {"port": 80, "protocol": "tcp"},
                    evidence_ref="x.raw", sha256="ab" * 32)
        conn.close()

        try:
            from intected.cli import main
            import intected.config as cfg
            old_db = cfg.DB_PATH
            cfg.DB_PATH = path
            try:
                rc = main(["report", "--mission", str(mid)])
                self.assertEqual(rc, 0)
            finally:
                cfg.DB_PATH = old_db
        finally:
            os.unlink(path)

    def test_report_command_bad_mission(self):
        """Report with a non-existent mission produces a clean empty report (graceful)."""
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
                rc = main(["report", "--mission", "99999"])
                self.assertEqual(rc, 0, "Empty report on unknown mission is graceful")
            finally:
                cfg.DB_PATH = old_db
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
