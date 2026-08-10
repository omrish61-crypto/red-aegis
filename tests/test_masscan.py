"""masscan extractor tests.

masscan -oX emits the nmap XML dialect (same <host>/<port>/<state> element
tree), so the extractor delegates to the validated nmap XML parser. The fixture
is REAL captured nmap XML (Nmap 7.99 -sV against the DVWA lab on
127.0.0.1:8001, Kali-WSL2, 2026-08-10) — live masscan output is not producible
on this host (masscan TX is broken in Kali-WSL2; see the extractor docstring).
"""

import xml.etree.ElementTree as ET
from pathlib import Path

from intected.parsing.extractors.masscan import extract as extract_masscan

FIXTURE = Path(__file__).parent / "fixtures" / "nmap-dvwa-live.xml"


def test_fixture_is_valid_xml():
    """Anti-silent-failure guard: a broken fixture must fail LOUDLY, not
    produce an empty pass (parsers return [] on ParseError)."""
    ET.fromstring(FIXTURE.read_text(encoding="utf-8"))


def test_masscan_parses_real_port_scan_xml():
    text = FIXTURE.read_text(encoding="utf-8")
    facts, warnings = extract_masscan(text)
    ports = [f for f in facts if f["fact_type"] == "port"]
    assert any(p["value"]["port"] == 8001 for p in ports), f"no 8001: {facts}"
    # the -sV capture carries service facts
    assert any(f["fact_type"] == "service" for f in facts)
    assert warnings == [], f"unexpected warnings: {warnings}"


def test_masscan_rejects_non_xml():
    facts, warnings = extract_masscan("Starting masscan 1.3.2 (http://bit.ly/14GZzcT)")
    assert facts == []
    assert warnings and "XML" in warnings[0]
