"""gobuster extractor — dir mode stdout + stderr.

Dir-mode lines (v3.x):
  /login.php          (Status: 200) [Size: 1523]
  /admin              (Status: 301) [Size: 312] [--> http://host/admin/]
or (v3.6+ default format):
  Status: 200, Size: 11321, Words: 2369, Lines: 225, Directory: http://host/admin/
Error lines (stderr): "error on running gobuster on <url>: <reason>"
  -> recorded as note (engine_note semantics: explain, don't hide).
"""

import re

from .common import dedupe_facts, note, path_fact

_LINE_RE = re.compile(
    r"^\s*(?P<path>\S+?)\s*\(Status:\s*(?P<status>\d+)\)"
    r"(?:\s*\[Size:\s*(?P<size>\d+)\])?"
    r"(?:\s*\[--> (?P<redirect>[^\]]+)\])?"
)
_STATUS_RE = re.compile(
    r"Status:\s*(?P<status>\d+),\s*Size:\s*(?P<size>\d+)(?:,\s*\w+:\s*\d+)*,"
    r"\s*Directory:\s*(?P<dir>\S+)"
)
_ERROR_RE = re.compile(r"error on running gobuster on (\S+): (.+)$")


def extract(text: str):
    facts = []
    warnings = []
    saw_lines = False
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _LINE_RE.match(line)
        if m:
            saw_lines = True
            facts.append(path_fact(
                m.group("path"),
                status=int(m.group("status")),
                size=int(m.group("size")) if m.group("size") else None,
                redirect=m.group("redirect"),
            ))
            continue
        m = _STATUS_RE.search(line)
        if m:
            saw_lines = True
            facts.append(path_fact(
                m.group("dir"), status=int(m.group("status")),
                size=int(m.group("size"))))
            continue
        m = _ERROR_RE.search(line)
        if m:
            warnings.append(f"gobuster error for {m.group(1)}: {m.group(2)}")
            facts.append(note(f"gobuster error on {m.group(1)}: {m.group(2)}"))
            continue
        if not saw_lines:
            warnings.append(f"unparsed gobuster line: {line[:120]!r}")
    return dedupe_facts(facts), warnings
