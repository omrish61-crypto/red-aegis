"""
SMB Fix-It Checklist — template-based remediation steps from technical findings.

Every item is something an SMB IT generalist (or the owner themselves) can
copy-paste into a terminal or follow as a click-path. No Kali, no exploits.
"""
from __future__ import annotations

from .grading import GradeReport

REMEDIATIONS = {
    # ── high-risk ports ─────────────────────────────────────────────
    3389: (
        "Disable Remote Desktop (RDP) on your server.",
        "On Windows: Settings → System → Remote Desktop → Off.\n"
        "On your router: Firewall → Port Forwarding → delete rule for port 3389.",
    ),
    445: (
        "Close the SMB (file sharing) port on your firewall.",
        "On your router: Firewall → Port Forwarding → delete any rule for port 445.\n"
        "On Windows: Control Panel → Network and Sharing → Turn off file and printer sharing.",
    ),
    23: (
        "Disable Telnet — it sends passwords in plain text over the internet.",
        "On Linux: sudo systemctl disable --now telnet.socket.\n"
        "On your router: Administration → Disable Telnet.",
    ),
    21: (
        "Disable the FTP server — use SFTP (port 22 over SSH) for file transfers.",
        "On Linux: sudo systemctl disable --now vsftpd.\n"
        "On Windows: Server Manager → Remove FTP Server role.",
    ),
    22: (
        "Restrict SSH access with a firewall rule (allow only your office IP).",
        "On your router: Firewall → add a rule allowing port 22 only from your "
        "office's public IP address.\n"
        "Alternative: disable password login and use SSH keys only: "
        "sudo nano /etc/ssh/sshd_config → PasswordAuthentication no.",
    ),
    3306: (
        "MySQL is exposed to the internet — attackers scan for open databases.",
        "On your firewall: block port 3306 from the internet.\n"
        "On the server: bind MySQL to localhost only — "
        "edit /etc/mysql/my.cnf → bind-address = 127.0.0.1.",
    ),
    5432: (
        "PostgreSQL is exposed to the internet.",
        "On your firewall: block port 5432.\n"
        "On the server: edit postgresql.conf → listen_addresses = 'localhost'.",
    ),
    6379: (
        "Redis is exposed — attackers can read/write all your data without a password.",
        "On your firewall: block port 6379.\n"
        "On the server: edit redis.conf → requirepass <strong-password>, "
        "bind 127.0.0.1, and disable 'CONFIG' command.",
    ),
    27017: (
        "MongoDB is exposed to the internet — a common ransomware target.",
        "On your firewall: block port 27017.\n"
        "On the server: edit mongod.conf → bindIp: 127.0.0.1 and enable auth.",
    ),
}

CVE_FIX_TEMPLATE = {
    "critical": (
        "CRITICAL: {cve_id} — {summary}\n"
        "PATCH IMMEDIATELY. Run: sudo apt-get update && sudo apt-get upgrade\n"
        "or contact your software vendor for an emergency patch."
    ),
    "high": (
        "HIGH: {cve_id} — {summary}\n"
        "Apply the latest security patch from your software vendor.\n"
        "On Debian/Ubuntu: sudo apt-get update && sudo apt-get upgrade."
    ),
    "medium": (
        "MEDIUM: {cve_id} — {summary}\n"
        "Plan to update this within your next maintenance window."
    ),
    "low": (
        "LOW: {cve_id} — {summary}\n"
        "This is a lower-priority item — address during regular patching."
    ),
}

DEFAULT_PORT_FIX = (
    "Port {port}/tcp is open to the internet — review whether it needs to be.",
    "Check your firewall/router port-forwarding rules and remove any you don't "
    "recognize. If this port must stay open, restrict access to your office IP only.",
)


def generate_checklist(grade: GradeReport, facts: dict[str, list]) -> list[dict]:
    """Produce a prioritised remediation checklist from scan findings.

    Returns a list of {priority, title, steps, category} dicts sorted by
    priority (critical first).
    """
    items: list[dict] = []

    for d in grade.deductions:
        reason = d["reason"]
        detail = d.get("detail", "")

        # port-based fix
        for port, (title, steps) in REMEDIATIONS.items():
            if f"Port {port}" in reason:
                items.append({
                    "priority": "critical" if port in (3389, 445, 23, 6379) else "high",
                    "title": title,
                    "steps": steps,
                    "category": "network",
                })
                break
        else:
            # CVE fix
            if reason.startswith("CVE "):
                cve_id = reason.split(" ")[1]
                sev = reason.split("(")[-1].rstrip(")")
                template = CVE_FIX_TEMPLATE.get(sev, CVE_FIX_TEMPLATE["medium"])
                items.append({
                    "priority": sev if sev in ("critical", "high") else "medium",
                    "title": f"Patch {cve_id} ({sev})",
                    "steps": template.format(cve_id=cve_id, summary=detail[:100]),
                    "category": "patching",
                })

            # CORS
            elif "CORS" in reason:
                items.append({
                    "priority": "medium",
                    "title": "Restrict cross-origin access (CORS policy)",
                    "steps": (
                        "Configure your web server to only allow your own domain:\n"
                        "Apache: Header set Access-Control-Allow-Origin 'https://yoursite.com'\n"
                        "nginx: add_header Access-Control-Allow-Origin 'https://yoursite.com';"
                    ),
                    "category": "web",
                })

            # exposed admin path
            elif "Exposed admin" in reason:
                path = reason.split("path")[-1].strip()
                items.append({
                    "priority": "high",
                    "title": f"Restrict access to {path}",
                    "steps": (
                        f"The path {path} should not be reachable from the internet.\n"
                        f"Option 1: Add a password (HTTP Basic Auth) to that directory.\n"
                        f"Option 2: Restrict it to your office IP address in the firewall.\n"
                        f"Option 3: Remove the directory if it's not needed."
                    ),
                    "category": "web",
                })

            # outdated software
            elif "Outdated" in reason:
                tech = reason.replace("Outdated software: ", "")
                items.append({
                    "priority": "high",
                    "title": f"Update {tech}",
                    "steps": (
                        f"Your version of {tech} is outdated and has known security holes.\n"
                        f"1. Check your vendor's website for the latest version.\n"
                        f"2. Apply the update during your next maintenance window.\n"
                        f"3. Debian/Ubuntu: sudo apt-get update && sudo apt-get upgrade {tech.split()[0].lower()}"
                    ),
                    "category": "patching",
                })

            # default credentials
            elif "credentials" in reason.lower():
                items.append({
                    "priority": "critical",
                    "title": "Change all default usernames and passwords IMMEDIATELY",
                    "steps": (
                        "Your system is using a default or easily-guessed password. "
                        "This is the #1 way ransomware gets into small businesses.\n"
                        "1. Log into every device/server you own.\n"
                        "2. Change the default admin password to a strong, unique one.\n"
                        "3. Use a password manager (Bitwarden is free).\n"
                        "4. Enable two-factor authentication if the device supports it."
                    ),
                    "category": "credentials",
                })

    # deduplicate
    seen = set()
    unique = []
    for item in items:
        key = item["title"]
        if key not in seen:
            seen.add(key)
            unique.append(item)

    # sort critical → high → medium → low
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    unique.sort(key=lambda x: order.get(x["priority"], 99))
    return unique
