"""Command linting: a quote proves where a command came from, not that it is safe to run.

Commands that download-and-execute, disable security controls, or stop/restart services are forced to risk 3 with a
plain warning, whatever the model said.
"""

from __future__ import annotations

import re

_DANGEROUS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\|\s*(sudo\s+)?(ba|z|da)?sh\b|\|\s*python\d?\b|\|\s*perl\b", re.I),
     "pipes downloaded content into an interpreter"),
    (re.compile(r"\b(iex|invoke-expression)\b|downloadstring\s*\(|new-object\s+net\.webclient", re.I),
     "downloads and runs code"),
    (re.compile(r"set-mppreference\b.*-disable\w*\s+\$?true|disablerealtimemonitoring", re.I),
     "turns off Microsoft Defender protection"),
    (re.compile(r"netsh\s+advfirewall\s+set\s+\w+\s+state\s+off|ufw\s+disable|setenforce\s+0|iptables\s+-f\b",
                re.I), "turns off a firewall or SELinux"),
    (re.compile(r"systemctl\s+(stop|disable|mask)\s+(firewalld|ufw|auditd|falcon|sentinel|mdatp)", re.I),
     "stops a security service"),
    (re.compile(r"\brm\s+-rf\s+/(\s|$)|\bformat\s+[a-z]:|\bdel\s+/s\s+/q\s+[a-z]:\\", re.I),
     "deletes data broadly"),
)
_DISRUPTIVE = re.compile(
    r"\b(restart|reboot|shutdown|stop-service|stop\b|kill|pkill|taskkill|disable|mask|rmmod|modprobe\s+-r|"
    r"uninstall|remove-windowsfeature|disable-windowsoptionalfeature)\b",
    re.I,
)
_CHANGES = re.compile(
    r"\b(reg\s+(add|delete|import)|set-itemproperty|new-itemproperty|remove-item|sysctl\s+-w|sed\s+-i|echo\b.*>|"
    r"tee\b|chmod|chown|apt|yum|dnf|zypper|install|set|enable|config|copy|move|mv|cp|rm)\b",
    re.I,
)


def lint_command(command: str, risk: int) -> tuple[int, str | None]:
    """Return the (possibly raised) risk and a warning for a command."""
    for pattern, why in _DANGEROUS:
        if pattern.search(command):
            return 3, f"This command {why}. Review it carefully before running it."
    if _DISRUPTIVE.search(command):
        return max(risk, 3), "Stops, restarts or disables something; plan a maintenance window."
    if _CHANGES.search(command):
        return max(risk, 2), None
    return risk, None
