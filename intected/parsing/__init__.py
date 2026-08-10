"""Parsing module — raw tool output -> structured facts.

Architecture (no-simulation by construction):
- Every extractor is a pure function: text in, fact dicts out.
- `parse_tool_output()` reads a RAW evidence file, re-hashes it, runs the
  extractor, and writes facts to the DB **always** with evidence_ref + sha256.
  A fact without an evidence ref cannot be created through this module.
- Extractors never crash on garbage: per-record errors are skipped and
  collected as warnings. Empty input is a valid outcome (0 facts), not an error.
"""

import hashlib
import os
from pathlib import Path

from .. import db

# Extractors are imported EAGERLY — a lazy try/except registry would swallow
# real extractor bugs (proven pitfall from pentest-core's registry).
from .extractors.burp import extract as extract_burp
from .extractors.ffuf import extract as extract_ffuf
from .extractors.gobuster import extract as extract_gobuster
from .extractors.masscan import extract as extract_masscan
from .extractors.nikto import extract as extract_nikto
from .extractors.nmap import extract as extract_nmap
from .extractors.nuclei import extract as extract_nuclei
from .extractors.sqlmap import extract as extract_sqlmap
from .extractors.zap import extract as extract_zap

EXTRACTORS = {
    "nmap": extract_nmap,
    "gobuster": extract_gobuster,
    "ffuf": extract_ffuf,
    "nuclei": extract_nuclei,
    "sqlmap": extract_sqlmap,
    "zap": extract_zap,
    "burp": extract_burp,
    "nikto": extract_nikto,
    "masscan": extract_masscan,
}


class ParseError(RuntimeError):
    """Unknown tool or catastrophic parse failure."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def store_evidence(mission_id: int, tool: str, raw: bytes,
                   evidence_dir: str) -> tuple[str, str]:
    """Persist raw output verbatim; return (path, sha256)."""
    sha = sha256_bytes(raw)
    ev_dir = os.path.join(evidence_dir, f"mission-{mission_id}")
    os.makedirs(ev_dir, exist_ok=True)
    path = os.path.join(ev_dir, f"{tool}-{sha[:12]}.raw")
    with open(path, "wb") as fh:
        fh.write(raw)
    return path, sha


def verify_evidence(path: str, expected_sha: str) -> bool:
    """Re-hash a raw file; True only if it matches the recorded sha256."""
    try:
        actual = sha256_bytes(Path(path).read_bytes())
    except OSError:
        return False
    return actual == expected_sha


def _decode(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


def parse_tool_output(conn, mission_id: int, tool: str, raw_path: str,
                      task_id: int | None = None) -> dict:
    """Parse a raw evidence file into DB facts.

    Returns {"facts": [ids], "warnings": [...], "sha256": str}.
    Raises ParseError for unknown tools; extractor warnings never raise.
    """
    if tool not in EXTRACTORS:
        raise ParseError(f"unknown tool {tool!r}; known: {sorted(EXTRACTORS)}")
    try:
        raw = Path(raw_path).read_bytes()
    except OSError as exc:
        raise ParseError(f"cannot read raw file {raw_path!r}: {exc}") from exc
    sha = sha256_bytes(raw)
    text = _decode(raw)
    extractor = EXTRACTORS[tool]
    facts, warnings = extractor(text)
    ids = []
    for fact in facts:
        fid = db.add_fact(
            conn, mission_id, tool=tool,
            fact_type=fact["fact_type"],
            value=fact["value"],
            confidence=fact.get("confidence", 1.0),
            evidence_ref=str(raw_path),
            sha256=sha,
            task_id=task_id,
        )
        ids.append(fid)
    return {"facts": ids, "warnings": warnings, "sha256": sha}
