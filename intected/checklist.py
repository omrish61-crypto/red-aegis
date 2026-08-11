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

# ── tech-specific remediation templates (name or keyword → (title, steps)) ─
TECH_REMEDIATIONS: dict[str, tuple[str, str, str]] = {
    "synology": (
        "critical",
        "Lock down your Synology NAS",
        "Synology DiskStations are frequent ransomware targets.\n"
        "1. Log into DSM → Control Panel → Update & Restore → install latest DSM.\n"
        "2. Control Panel → Security → Firewall → block all ports from WAN except VPN.\n"
        "3. Disable admin account → create a new admin user with a strong password.\n"
        "4. Control Panel → QuickConnect → disable if not needed.\n"
        "5. Enable 2FA: Personal → Account → 2-Factor Authentication.",
    ),
    "unifi": (
        "critical",
        "Secure your Ubiquiti UniFi equipment",
        "UniFi devices often ship with default credentials (ubnt/ubnt).\n"
        "1. Log into the UniFi Controller → Settings → Admins.\n"
        "2. Change the default super-admin password to a strong, unique one.\n"
        "3. Settings → System → check for firmware updates on all devices.\n"
        "4. Disable remote access (UniFi Cloud) unless absolutely needed.\n"
        "5. Enable local-only management: Settings → System → Remote Access → Off.",
    ),
    "wordpress": (
        "critical",
        "Harden your WordPress site",
        "WordPress is the most targeted CMS on the internet.\n"
        "1. Log into wp-admin → Dashboard → Updates → install all pending updates.\n"
        "2. Remove unused plugins and themes immediately.\n"
        "3. Install a security plugin: Wordfence (free) or Sucuri.\n"
        "4. Change the default 'admin' username if it exists.\n"
        "5. Add password protection to /wp-admin via your hosting panel.\n"
        "6. Run: wp plugin update --all && wp core update (if you have WP-CLI).",
    ),
    "wp-admin": (
        "high",
        "Restrict access to WordPress admin panel",
        "The /wp-admin login page is publicly accessible — attackers constantly probe it.\n"
        "1. Add HTTP Basic Auth to /wp-admin via your .htaccess file:\n"
        "   AuthType Basic\n"
        "   AuthName \"Admin Area\"\n"
        "   AuthUserFile /path/to/.htpasswd\n"
        "   Require valid-user\n"
        "2. Or use a WordPress plugin like 'WPS Hide Login' to change the login URL.\n"
        "3. Limit login attempts: install 'Limit Login Attempts Reloaded'.",
    ),
    "rdp": (
        "critical",
        "Remove RDP from the internet — use a VPN instead",
        "Exposed RDP is the #1 ransomware entry vector for small businesses.\n"
        "1. On your router: Firewall → Port Forwarding → DELETE rule for 3389.\n"
        "2. Install Tailscale (free) or ZeroTier for secure remote access.\n"
        "3. If you must keep RDP: use RD Gateway with Network Level Authentication.\n"
        "4. Verify port is closed: go to yougetsignal.com/tools/open-ports and check 3389.",
    ),
    "exchange": (
        "critical",
        "Secure your Exchange Server / OWA",
        "Exchange servers are high-value targets (ProxyLogon, ProxyShell).\n"
        "1. Run Windows Update immediately — install all security patches.\n"
        "2. Check for compromise: Microsoft Safety Scanner (msert.exe).\n"
        "3. Disable Outlook Web Access (OWA) if not needed externally.\n"
        "4. Enable Extended Protection: https://aka.ms/ExchangeEP.\n"
        "5. If on Exchange 2016 or older, plan migration to 2019 or Exchange Online.",
    ),
    "owa": (
        "high",
        "Restrict Outlook Web Access exposure",
        "OWA exposed externally is a common attack vector.\n"
        "1. Add IP-based restrictions in IIS → OWA → IP Address and Domain Restrictions.\n"
        "2. Require multi-factor authentication for all external OWA users.\n"
        "3. Consider moving to Exchange Online (Microsoft 365) to eliminate on-prem risk.",
    ),
    "phpmyadmin": (
        "critical",
        "Secure or remove phpMyAdmin",
        "phpMyAdmin gives attackers full database access if they find the login page.\n"
        "1. DELETE phpMyAdmin entirely if you don't use it daily.\n"
        "2. If you must keep it: add .htaccess password protection.\n"
        "3. Restrict access to your office IP only via Apache/nginx config.\n"
        "4. Run: sudo apt-get update && sudo apt-get upgrade phpmyadmin.",
    ),
    "jenkins": (
        "critical",
        "Harden your Jenkins CI server",
        "Jenkins servers can execute arbitrary code — they're prime ransomware targets.\n"
        "1. Update: Manage Jenkins → Manage Plugins → Update all.\n"
        "2. Restrict access: Configure Global Security → enable authentication.\n"
        "3. Move Jenkins behind a VPN — never expose it directly to the internet.\n"
        "4. Audit user accounts: remove old users and enforce strong passwords.\n"
        "5. Disable anonymous read access: Manage Jenkins → Configure Global Security.",
    ),
    "docker api": (
        "critical",
        "Secure the Docker API",
        "An exposed Docker API lets attackers deploy malicious containers — including\n"
        "crypto miners and reverse shells.\n"
        "1. NEVER expose Docker on port 2375/2376 without TLS auth.\n"
        "2. If using Docker remotely, use: docker -H ssh://user@host (SSH tunnel).\n"
        "3. Block ports 2375-2376 on your firewall immediately.\n"
        "4. Verify: curl http://your-server:2375/containers/json should fail.",
    ),
    "docker": (
        "high",
        "Review Docker Engine security",
        "Docker containers need regular patching like any other software.\n"
        "1. Run: docker ps → note all running containers.\n"
        "2. Update: docker pull <image> for each container, then restart.\n"
        "3. Run Docker Bench for Security: docker run --rm --net host \\\n"
        "   --pid host -v /var/run/docker.sock:/var/run/docker.sock \\\n"
        "   docker/docker-bench-security\n"
        "4. Use non-root users in Dockerfiles: USER 1000.",
    ),
    "mongodb": (
        "critical",
        "Secure your MongoDB database",
        "Exposed MongoDB instances without auth are a common ransomware target.\n"
        "1. Enable authentication: edit mongod.conf → security: authorization: enabled.\n"
        "2. Bind to localhost: net: bindIp: 127.0.0.1.\n"
        "3. Create an admin user: db.createUser({user:'admin', pwd:'<strong>', roles:['root']}).\n"
        "4. Update to latest version: mongosh --eval 'db.version()'.",
    ),
    "redis": (
        "critical",
        "Secure your Redis instance",
        "Unauthenticated Redis lets attackers write SSH keys and take over servers.\n"
        "1. Set a strong password: redis-cli CONFIG SET requirepass '<strong-password>'.\n"
        "2. Bind to localhost: edit redis.conf → bind 127.0.0.1.\n"
        "3. Disable dangerous commands: rename-command CONFIG \"\" and FLUSHDB \"\".\n"
        "4. Update Redis: sudo apt-get update && sudo apt-get install redis-server.",
    ),
    "drupal": (
        "high",
        "Update your Drupal installation",
        "Drupal EOL versions have unpatched security holes.\n"
        "1. Check version: admin/reports/status or drush status.\n"
        "2. Update: composer update drupal/core-recommended --with-dependencies.\n"
        "3. If on Drupal 7: plan migration to Drupal 10/11 immediately (EOL Jan 2025).\n"
        "4. Run: drush updb && drush cr after every update.",
    ),
    "php 5": (
        "critical",
        "Migrate from PHP 5.x (end-of-life since 2019)",
        "PHP 5.x is EOL and receives NO security patches — a critical risk.\n"
        "1. Check version: php -v.\n"
        "2. Plan migration to PHP 8.x — test your site on a staging server first.\n"
        "3. The most common breaking changes: mysql_* functions → PDO/MySQLi.\n"
        "4. Use PHP Compatibility Scanner to identify issues before upgrading.",
    ),
    "php 7.4": (
        "high",
        "Upgrade from PHP 7.4 (end-of-life Nov 2022)",
        "PHP 7.4 is EOL and no longer receives security updates.\n"
        "1. Check your hosting panel — many hosts offer one-click PHP version changes.\n"
        "2. Upgrade to PHP 8.1+ (8.1 is current LTS).\n"
        "3. Test your site with the new PHP version on a staging URL first.\n"
        "4. Most WordPress/plugin combos now support PHP 8.x.",
    ),
    "openssl": (
        "critical",
        "Upgrade OpenSSL to 3.x",
        "OpenSSL 1.0.x was the Heartbleed era — 1.1.x reached EOL in 2023.\n"
        "1. Check version: openssl version.\n"
        "2. On Debian/Ubuntu: sudo apt-get update && sudo apt-get install --only-upgrade openssl.\n"
        "3. Restart all services using SSL: sudo systemctl restart nginx apache2.\n"
        "4. Reissue any SSL/TLS certificates if migrating from 1.0.x.",
    ),
    "iis": (
        "high",
        "Harden Microsoft IIS web server",
        "IIS needs regular Windows Update patching and configuration hardening.\n"
        "1. Run Windows Update → install ALL security patches.\n"
        "2. IIS Manager → Server Certificates → ensure TLS 1.2+ is enabled.\n"
        "3. Remove unused modules: Server Manager → Remove Roles and Features.\n"
        "4. Disable directory browsing: IIS → Directory Browsing → Disable.\n"
        "5. Remove the X-Powered-By header: HTTP Response Headers → remove X-Powered-By.",
    ),
    "nginx": (
        "high",
        "Upgrade nginx to latest stable (1.24+)",
        "Older nginx versions have known vulnerabilities.\n"
        "1. Check version: nginx -v.\n"
        "2. On Debian/Ubuntu: sudo apt-get update && sudo apt-get install --only-upgrade nginx.\n"
        "3. Test config before restarting: sudo nginx -t.\n"
        "4. Restart: sudo systemctl restart nginx.",
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


def _match_tech_keyword(reason: str) -> str | None:
    """Match a reason string to a TECH_REMEDIATIONS key."""
    reason_lower = reason.lower()
    # Check for specific tech keywords in priority order
    keywords = [
        "synology", "unifi", "wordpress", "wp-admin",
        "rdp", "exchange", "owa", "phpmyadmin", "jenkins",
        "docker api", "docker", "mongodb", "redis",
        "drupal", "php 5", "php 7.4", "openssl", "iis", "nginx",
    ]
    for kw in keywords:
        if kw in reason_lower:
            return kw
    return None


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
        matched_port = False
        for port, (title, steps) in REMEDIATIONS.items():
            if f"Port {port}" in reason:
                items.append({
                    "priority": "critical" if port in (3389, 445, 23, 6379) else "high",
                    "title": title,
                    "steps": steps,
                    "category": "network",
                })
                matched_port = True
                break
        if matched_port:
            continue

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
            continue

        # tech-specific remediation (Synology, UniFi, WordPress, etc.)
        tech_kw = _match_tech_keyword(reason)
        if tech_kw and tech_kw in TECH_REMEDIATIONS:
            priority, title, steps = TECH_REMEDIATIONS[tech_kw]
            items.append({
                "priority": priority,
                "title": title,
                "steps": steps,
                "category": "tech",
            })
            continue

        # missing security headers
        if reason.startswith("Missing security header"):
            header_name = reason.replace("Missing security header: ", "")
            items.append({
                "priority": "medium",
                "title": f"Add {header_name} security header",
                "steps": (
                    f"Add the {header_name} HTTP header to your web server config:\n"
                    f"nginx: add_header {header_name} '...' always;\n"
                    f"Apache: Header always set {header_name} '...'\n"
                    f"See https://securityheaders.com for best-practice values."
                ),
                "category": "web",
            })
            continue

        # CORS
        if "CORS" in reason:
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
            continue

        # exposed admin path
        if "Exposed admin" in reason:
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
            continue

        # outdated software (generic fallback — only if no tech-specific match)
        if "Outdated" in reason and not tech_kw:
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
            continue

        # default credentials
        if "credentials" in reason.lower():
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
            continue

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
