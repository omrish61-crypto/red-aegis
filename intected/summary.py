"""
SMB Plain-English Summary — LLM prompt chain that translates technical
evidence into an executive briefing a business owner can actually read.

Design: one-shot summarisation (not multi-turn). The prompt is engineered
to produce a 3-paragraph output: (1) what's at risk, (2) real-world impact,
(3) what to do next.
"""
from __future__ import annotations

import json
from .config import BRIDGE_URL
from .grading import GradeReport


SUMMARY_PROMPT = """You are a cyber-security translator writing for a small-business owner who
has zero technical background. They run a company like a dental office, a law firm,
or a local manufacturing shop.

Below is a security scan of their systems. Turn it into a 3-paragraph executive
summary a busy owner can read in 60 seconds.

**PARAGRAPH 1 — "What we found":** explain the overall security grade and the
2–3 most important problems in plain language. No jargon, no CVE numbers.
Example: "Your office network has a door that's been left unlocked — anyone
on the internet could walk in."

**PARAGRAPH 2 — "Why it matters":** explain what could actually happen to their
business if these aren't fixed. Ransomware, insurance denial, client data leak,
downtime. Make it feel real but not alarmist.

**PARAGRAPH 3 — "What to do":** give them a clear, concrete first step they can
take TODAY. Something they can hand to their IT person or consultant.

Use short sentences. Avoid bullet points. The output must be exactly three
paragraphs separated by blank lines. No preamble, no sign-off.

Grade: {letter} ({score}/100)
Deductions:
{deductions}
Positives:
{positives}
Technical facts ({fact_count} pieces of evidence):
{surface_summary}"""


def generate_summary(grade: GradeReport, facts: dict[str, list]) -> str:
    """Call the LLM bridge and return a 3-paragraph plain-English summary."""
    import httpx

    deductions_text = "\n".join(
        f"  - {d['reason']}: {d['detail'][:150]}" for d in grade.deductions
    ) or "(no deductions — clean scan)"
    positives_text = "\n".join(f"  - {p}" for p in grade.positives) or "(none)"

    # surface summary: a few key things from the facts
    surface_parts = []
    for f in facts.get("port", [])[:5]:
        v = f.get("value", {})
        surface_parts.append(f"open port {v.get('port')}/{v.get('protocol','tcp')}")
    for f in facts.get("cve", [])[:3]:
        v = f.get("value", {})
        surface_parts.append(f"CVE {v.get('cve_id')} ({v.get('severity')}) — {v.get('summary','')[:60]}")
    for f in facts.get("path", [])[:5]:
        surface_parts.append(f"public path {f.get('value',{}).get('path','?')}")
    surface_summary = "\n".join(surface_parts) or "basic network scan"

    prompt = SUMMARY_PROMPT.format(
        letter=grade.letter,
        score=grade.score,
        deductions=deductions_text,
        positives=positives_text,
        fact_count=grade.fact_count,
        surface_summary=surface_summary,
    )

    try:
        with httpx.Client(timeout=40) as client:
            resp = client.post(
                f"{BRIDGE_URL}/chat/completions",
                json={
                    "model": "deepseek-v4-flash",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.7,
                    "max_tokens": 600,
                },
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            return content.strip()
    except Exception as exc:
        # graceful fallback — the summary engine is never a hard dependency
        return (
            f"RedAegis Security Report — Grade: {grade.letter} ({grade.score}/100)\n\n"
            f"The automated summary could not be generated ({exc}). "
            f"Please review the detailed findings below.\n\n"
            f"Key issues: {len(grade.deductions)} risk(s) identified. "
            f"Top action: review the Checklist section for your IT team."
        )
