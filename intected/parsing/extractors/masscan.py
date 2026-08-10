"""masscan extractor — masscan -oX emits the nmap XML dialect.

masscan's `-oX` output is intentionally nmap-compatible: root element
`<nmaprun scanner="masscan" ...>` with the identical `<host>` / `<address>` /
`<ports>` / `<port>` / `<state>` element tree. This adapter delegates to the
validated nmap XML parser (`extract_xml`).

VALIDATION NOTE (2026-08-10): live masscan output could NOT be captured on this
host — masscan 1.3.2 in Kali-WSL2 binds the adapter but never transmits (TX
rate stays 0.00-kpps; `-oX` output file is empty). This parser is validated
against REAL captured nmap XML of the same element tree
(tests/fixtures/nmap-dvwa-live.xml — Nmap 7.99, DVWA lab on 127.0.0.1:8001).
The residual risk (any masscan-specific element divergence) is documented, not
hidden: treat masscan findings on this host as suspect until a live capture is
parsed on a host where masscan can actually transmit.
"""

from .nmap import extract_xml


def extract(text: str):
    text = text.strip()
    if not text or not text.lstrip().startswith("<"):
        return [], ["masscan: expected XML (-oX) input, got non-XML text"]
    return extract_xml(text)
