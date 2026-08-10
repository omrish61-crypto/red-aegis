"""Arsenal catalog tests — schema sanity + probe parsing (no live WSL needed)."""

import pytest

from intected import arsenal


def test_catalog_schema():
    """Every entry has the required keys and a valid phase."""
    names = set()
    for e in arsenal.ARSENAL:
        assert set(e) >= {"name", "phase", "host", "probe", "purpose",
                          "template", "guardrail"}, f"bad entry: {e}"
        assert e["phase"] in arsenal.PHASES, f"bad phase: {e['name']}"
        assert e["name"] not in names, f"duplicate tool: {e['name']}"
        names.add(e["name"])
        if e["host"] == "kali":
            assert e["probe"], f"kali tool needs a probe binary: {e['name']}"
    # the 6 requested phases are all present
    assert set(arsenal.PHASES) == {"recon", "initial_access", "c2", "privesc",
                                   "lateral", "evasion"}


def test_probe_kali_parses_batch_output(monkeypatch):
    """A real `command -v` batch maps to ok/miss correctly (parsing logic)."""
    fake = ("ok amass\nmiss sublist3r\nok nmap\n")

    class _R:
        returncode = 0
        stdout = fake

    def fake_run(*a, **k):
        return _R()

    monkeypatch.setattr(arsenal.subprocess, "run", fake_run)
    found = arsenal._probe_kali(["amass", "sublist3r", "nmap", "ghost"])
    assert found == {"amass": True, "sublist3r": False,
                     "nmap": True, "ghost": False}


def test_probe_arsenal_statuses(monkeypatch):
    """host-based status mapping: kali->ok/missing, license/deprecated static."""
    class _R:
        returncode = 0
        stdout = "ok nmap\n"

    def fake_run(*a, **k):
        return _R()

    monkeypatch.setattr(arsenal.subprocess, "run", fake_run)
    probe = arsenal.probe_arsenal(force=True)
    assert probe["nmap"] == "ok"
    assert probe["cobalt-strike"] == "license"
    assert probe["aquatone"] == "deprecated"
    assert probe["syswhispers"] == "windows-host"
    assert "sublist3r" in probe  # present in catalog


def test_arsenal_summary_only_ok_tools(monkeypatch):
    """Summary lists only tools whose probe is 'ok'."""
    probe = {"nmap": "ok", "masscan": "ok", "amass": "missing",
             "cobalt-strike": "license", "syswhispers": "windows-host"}
    summary = arsenal.arsenal_summary(probe)
    assert "nmap" in summary and "masscan" in summary
    assert "amass" not in summary
    assert "cobalt-strike" not in summary
    # per-phase formatting present
    assert "recon:" in summary


def test_format_table_mentions_every_entry(monkeypatch):
    probe = {e["name"]: "ok" for e in arsenal.ARSENAL}
    table = arsenal.format_arsenal_table(probe)
    for e in arsenal.ARSENAL:
        assert e["name"] in table


def test_templates_are_shell_shaped():
    """Every kali/install tool has a non-empty single-purpose command template."""
    for e in arsenal.ARSENAL:
        if e["host"] in ("kali", "install"):
            assert e["template"], f"tool needs a template: {e['name']}"
