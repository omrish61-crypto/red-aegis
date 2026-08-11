"""PII guard — GDPR/SOC2 behavior (spec: prove access, never extract PII).

Applied at parse time: fact values and evidence previews are scanned for PII
patterns (emails, phone numbers, credit cards, government-ID shapes). Matches
are REDACTED in stored fact values and flagged on the fact row; raw evidence
files are never logged into the DB verbatim by the extractors anyway.

The DB-proof rule is enforced at the tool/supervisor layer (sqlmap --dump and
table reads are banned; SELECT version()-style proof is the only allowed
data-plane action and it is PII-safe by construction).
"""

import re

_PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "phone": re.compile(r"\+?[0-9][0-9 ()\-]{7,}[0-9]"),
    "credit_card": re.compile(r"\b(?:\d[ -]*){13,16}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
}
REDACTED = "[PII-REDACTED]"


def detect(text: str) -> list[str]:
    """PII categories present in the text (never the values)."""
    found = []
    for name, pattern in _PATTERNS.items():
        if pattern.search(text or ""):
            found.append(name)
    return found


def redact(text: str) -> str:
    """Replace PII matches with a fixed placeholder."""
    for pattern in _PATTERNS.values():
        text = pattern.sub(REDACTED, text or "")
    return text


def is_pii_safe(text: str) -> bool:
    """True when the text carries no detectable PII."""
    return not detect(text)
