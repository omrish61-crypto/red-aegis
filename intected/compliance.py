"""
Compliance framework mapping: NIST CSF 2.0 + CIS Controls v8 → fact_type.

Maps RedAegis/INTECTED fact types to relevant NIST CSF 2.0 subcategories
and CIS Controls v8 safeguards, enabling compliance-scoring of pentest
evidence.

Reference: NIST CSF 2.0 (Feb 2024), CIS Critical Security Controls v8.1
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .grading import compute_grade, GradeReport, _load_facts

# ── Framework definitions ───────────────────────────────────────────────────

NIST_CSF_CATEGORIES: dict[str, str] = {
    # IDENTIFY (ID)
    "ID.AM": "Asset Management",
    "ID.RA": "Risk Assessment",
    "ID.IM": "Improvement",
    # PROTECT (PR)
    "PR.AC": "Identity Management, Authentication & Access Control",
    "PR.AT": "Awareness & Training",
    "PR.DS": "Data Security",
    "PR.PT": "Platform Security",
    "PR.IR": "Technology Infrastructure Resilience",
    # DETECT (DE)
    "DE.CM": "Continuous Monitoring",
    "DE.AE": "Adverse Event Analysis",
    # RESPOND (RS)
    "RS.MA": "Incident Management",
    "RS.AN": "Incident Analysis",
    "RS.RP": "Incident Response Reporting & Communication",
    "RS.MI": "Mitigation",
    # RECOVER (RC)
    "RC.RP": "Incident Recovery Plan Execution",
    "RC.CO": "Incident Recovery Communication",
    # GOVERN (GV)
    "GV.OC": "Organizational Context",
    "GV.RM": "Risk Management Strategy",
    "GV.RR": "Roles, Responsibilities & Authorities",
    "GV.PO": "Policies, Processes & Procedures",
    "GV.OV": "Oversight",
    "GV.SC": "Supply Chain Risk Management",
}

CIS_CONTROLS: dict[int, str] = {
    1:  "Inventory and Control of Enterprise Assets",
    2:  "Inventory and Control of Software Assets",
    3:  "Data Protection",
    4:  "Secure Configuration of Enterprise Assets and Software",
    5:  "Account Management",
    6:  "Access Control Management",
    7:  "Continuous Vulnerability Management",
    8:  "Audit Log Management",
    9:  "Email and Web Browser Protections",
    10: "Malware Defenses",
    11: "Data Recovery",
    12: "Network Infrastructure Management",
    13: "Network Monitoring and Defense",
    14: "Security Awareness and Skills Training",
    15: "Service Provider Management",
    16: "Application Software Security",
    17: "Incident Response Management",
    18: "Penetration Testing",
}


# ── Fact-type → frameworks mapping ──────────────────────────────────────────

@dataclass
class FrameworkMapping:
    """NIST + CIS mapping for a single fact_type."""
    nist_subcategories: list[str]
    nist_labels: list[str]
    cis_controls: list[int]
    cis_labels: list[str]


# Maps each fact_type to the NIST CSF 2.0 subcategories and CIS Controls
# it directly addresses.
COMPLIANCE_MAP: dict[str, FrameworkMapping] = {
    "port": FrameworkMapping(
        nist_subcategories=["DE.CM-8", "ID.AM-1"],
        nist_labels=[
            "DE.CM-8 (Vulnerability Scans)",
            "ID.AM-1 (Asset Inventory)",
        ],
        cis_controls=[4, 12],
        cis_labels=[
            "Control 4 (Secure Configuration of Enterprise Assets and Software)",
            "Control 12 (Network Infrastructure Management)",
        ],
    ),
    "service": FrameworkMapping(
        nist_subcategories=["ID.AM-1", "ID.AM-2"],
        nist_labels=[
            "ID.AM-1 (Asset Inventory)",
            "ID.AM-2 (Software Inventory)",
        ],
        cis_controls=[1, 2],
        cis_labels=[
            "Control 1 (Inventory and Control of Enterprise Assets)",
            "Control 2 (Inventory and Control of Software Assets)",
        ],
    ),
    "version": FrameworkMapping(
        nist_subcategories=["ID.RA-1", "ID.RA-2"],
        nist_labels=[
            "ID.RA-1 (Vulnerability Identification)",
            "ID.RA-2 (Threat Intelligence)",
        ],
        cis_controls=[7, 2],
        cis_labels=[
            "Control 7 (Continuous Vulnerability Management)",
            "Control 2 (Inventory and Control of Software Assets)",
        ],
    ),
    "path": FrameworkMapping(
        nist_subcategories=["DE.CM-1", "PR.PT-3", "PR.DS-2"],
        nist_labels=[
            "DE.CM-1 (Network Monitoring)",
            "PR.PT-3 (Least Functionality)",
            "PR.DS-2 (Data-at-Rest Protection)",
        ],
        cis_controls=[3, 13, 4],
        cis_labels=[
            "Control 3 (Data Protection)",
            "Control 13 (Network Monitoring and Defense)",
            "Control 4 (Secure Configuration of Enterprise Assets and Software)",
        ],
    ),
    "param": FrameworkMapping(
        nist_subcategories=["PR.PT-3", "ID.RA-5"],
        nist_labels=[
            "PR.PT-3 (Least Functionality)",
            "ID.RA-5 (Threats, Vulnerabilities, Likelihoods & Impacts)",
        ],
        cis_controls=[4, 16],
        cis_labels=[
            "Control 4 (Secure Configuration of Enterprise Assets and Software)",
            "Control 16 (Application Software Security)",
        ],
    ),
    "cve": FrameworkMapping(
        nist_subcategories=["ID.RA-1", "ID.RA-2", "RS.AN-3"],
        nist_labels=[
            "ID.RA-1 (Vulnerability Identification)",
            "ID.RA-2 (Threat Intelligence)",
            "RS.AN-3 (Incident Forensics)",
        ],
        cis_controls=[7, 18],
        cis_labels=[
            "Control 7 (Continuous Vulnerability Management)",
            "Control 18 (Penetration Testing)",
        ],
    ),
    "credential": FrameworkMapping(
        nist_subcategories=["PR.AC-1", "PR.AC-3", "PR.AC-7"],
        nist_labels=[
            "PR.AC-1 (Identity Management)",
            "PR.AC-3 (Access Enforcement)",
            "PR.AC-7 (Authentication)",
        ],
        cis_controls=[5, 6],
        cis_labels=[
            "Control 5 (Account Management)",
            "Control 6 (Access Control Management)",
        ],
    ),
    "note": FrameworkMapping(
        nist_subcategories=["DE.AE-1", "RS.MA-1"],
        nist_labels=[
            "DE.AE-1 (Event Detection)",
            "RS.MA-1 (Incident Management)",
        ],
        cis_controls=[17, 8],
        cis_labels=[
            "Control 17 (Incident Response Management)",
            "Control 8 (Audit Log Management)",
        ],
    ),
    "header": FrameworkMapping(
        nist_subcategories=["PR.PT-3", "PR.AC-5", "PR.DS-5"],
        nist_labels=[
            "PR.PT-3 (Least Functionality)",
            "PR.AC-5 (Network Integrity)",
            "PR.DS-5 (Data-in-Transit Protection)",
        ],
        cis_controls=[4, 16, 9],
        cis_labels=[
            "Control 4 (Secure Configuration of Enterprise Assets and Software)",
            "Control 16 (Application Software Security)",
            "Control 9 (Email and Web Browser Protections)",
        ],
    ),
}


# ── Compliance scoring ──────────────────────────────────────────────────────

@dataclass
class ComplianceSummary:
    """Result of compliance_summary()."""
    nist_score: int                  # 0–100
    nist_covered: int                # count of unique NIST subcategories covered
    nist_total: int                  # total unique NIST subcategories in scope
    cis_score: int                   # 0–100
    cis_covered: int                 # count of unique CIS controls covered
    cis_total: int                   # total unique CIS controls in scope
    mapped_controls: list[dict]      # [{control_id, framework, status, evidence_count}, ...]
    gaps: list[dict]                 # [{control_id, framework, label}] — controls with no evidence
    grade_report: GradeReport | None # the full compute_grade() report, if available


def compliance_summary(
    grade_report: GradeReport,
    facts: dict[str, list],
) -> ComplianceSummary:
    """Compute a NIST CSF + CIS compliance score from grade deductions and facts.

    The score is based on coverage: which NIST subcategories and CIS controls
    are addressed by the fact types present in the evidence.

    Args:
        grade_report: The output of compute_grade().
        facts: Raw facts grouped by fact_type (from _load_facts or similar).

    Returns:
        ComplianceSummary with scores, mapped controls, and gaps.
    """
    # ── 1. Collect NIST subcategories and CIS controls addressed ─────────
    nist_covered_set: set[str] = set()
    cis_covered_set: set[int] = set()
    fact_type_counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"nist": defaultdict(int), "cis": defaultdict(int)},
    )

    for ftype, flist in facts.items():
        if not flist:
            continue
        mapping = COMPLIANCE_MAP.get(ftype)
        if mapping is None:
            continue

        count = len(flist)
        for nist_cat in mapping.nist_subcategories:
            nist_covered_set.add(nist_cat)
            # Track which fact_type contributed to this category
            fact_type_counts[nist_cat]["nist"][ftype] += count
        for cis_ctrl in mapping.cis_controls:
            cis_covered_set.add(cis_ctrl)
            fact_type_counts[cis_ctrl]["cis"][ftype] += count

    # ── 2. Compute the full universe ────────────────────────────────────
    all_nist = set()
    all_cis = set()
    for mapping in COMPLIANCE_MAP.values():
        all_nist.update(mapping.nist_subcategories)
        all_cis.update(mapping.cis_controls)

    nist_score = (len(nist_covered_set) / len(all_nist) * 100) if all_nist else 0
    cis_score = (len(cis_covered_set) / len(all_cis) * 100) if all_cis else 0

    # ── 3. Build mapped_controls list ───────────────────────────────────
    mapped_controls: list[dict] = []

    # Helper: resolve a NIST subcategory to its descriptive label
    _nist_label_cache: dict[str, str] = {
        nist: label
        for mapping in COMPLIANCE_MAP.values()
        for nist, label in zip(mapping.nist_subcategories, mapping.nist_labels)
    }

    # NIST entries
    for nist_cat in sorted(all_nist):
        cat_root = nist_cat.split("-")[0] if "-" in nist_cat else nist_cat
        cat_label = NIST_CSF_CATEGORIES.get(cat_root, "")
        covered = nist_cat in nist_covered_set
        evidence_count = 0
        if covered:
            for _, fcounts in fact_type_counts[nist_cat]["nist"].items():
                evidence_count += fcounts

        mapped_controls.append({
            "control_id": nist_cat,
            "framework": "NIST CSF 2.0",
            "category": cat_label,
            "label": _nist_label_cache.get(nist_cat, cat_label),
            "status": "addressed" if covered else "gap",
            "evidence_count": evidence_count,
        })

    # CIS entries
    for cis_ctrl in sorted(all_cis):
        ctrl_label = CIS_CONTROLS.get(cis_ctrl, f"Control {cis_ctrl}")
        covered = cis_ctrl in cis_covered_set
        evidence_count = 0
        if covered:
            for _, fcounts in fact_type_counts[cis_ctrl]["cis"].items():
                evidence_count += fcounts

        mapped_controls.append({
            "control_id": str(cis_ctrl),
            "framework": "CIS Controls v8",
            "category": "",
            "label": ctrl_label,
            "status": "addressed" if covered else "gap",
            "evidence_count": evidence_count,
        })

    # ── 4. Build gaps list ──────────────────────────────────────────────
    gaps: list[dict] = []

    for nist_cat in sorted(all_nist - nist_covered_set):
        cat_root = nist_cat.split("-")[0] if "-" in nist_cat else nist_cat
        gaps.append({
            "control_id": nist_cat,
            "framework": "NIST CSF 2.0",
            "label": NIST_CSF_CATEGORIES.get(cat_root, cat_root),
        })

    for cis_ctrl in sorted(all_cis - cis_covered_set):
        gaps.append({
            "control_id": str(cis_ctrl),
            "framework": "CIS Controls v8",
            "label": CIS_CONTROLS.get(cis_ctrl, f"Control {cis_ctrl}"),
        })

    return ComplianceSummary(
        nist_score=round(nist_score),
        nist_covered=len(nist_covered_set),
        nist_total=len(all_nist),
        cis_score=round(cis_score),
        cis_covered=len(cis_covered_set),
        cis_total=len(all_cis),
        mapped_controls=mapped_controls,
        gaps=gaps,
        grade_report=grade_report,
    )


def format_compliance_summary(summary: ComplianceSummary) -> str:
    """Render a ComplianceSummary as a human-readable text block."""
    lines: list[str] = []
    lines.append("╔══════════════════════════════════════════════════════╗")
    lines.append("║         COMPLIANCE FRAMEWORK SUMMARY                ║")
    lines.append("╠══════════════════════════════════════════════════════╣")
    lines.append(f"║  NIST CSF 2.0  │  Score: {summary.nist_score:>3}%  "
                 f"({summary.nist_covered}/{summary.nist_total} subcategories)  ║")
    lines.append(f"║  CIS Controls v8│  Score: {summary.cis_score:>3}%  "
                 f"({summary.cis_covered}/{summary.cis_total} controls)      ║")
    lines.append("╠══════════════════════════════════════════════════════╣")

    if summary.grade_report:
        gr = summary.grade_report
        lines.append(f"║  Security Grade │  {gr.letter} ({gr.score}/100)  "
                     f" — {len(gr.deductions)} issue(s)                     ║")

    lines.append("╠══════════════════════════════════════════════════════╣")
    lines.append("║  ADDRESSED CONTROLS                                 ║")

    addressed = [c for c in summary.mapped_controls if c["status"] == "addressed"]
    for c in addressed:
        lines.append(f"║  ✓ {c['control_id']:<12} {c['framework']:<14} "
                     f"{c.get('label', '')[:30]:<30} ║")

    if summary.gaps:
        lines.append("╠══════════════════════════════════════════════════════╣")
        lines.append("║  GAPS (not addressed by current evidence)           ║")
        for g in summary.gaps:
            lines.append(f"║  ✗ {g['control_id']:<12} {g['framework']:<14} "
                         f"{g['label'][:30]:<30} ║")

    lines.append("╚══════════════════════════════════════════════════════╝")
    return "\n".join(lines)
