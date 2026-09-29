"""
Vulnerability Scanner Signatures detection rule (Bot Protection 960100).
Detects automated vulnerability assessment and reconnaissance scanners.
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict

_SCANNER_PATTERNS: List[Tuple[str, str]] = [
    (r"\b(?:sqlmap|nikto|acunetix|nessus|openvas|qualys|wpscan|nuclei|jaeles|dalfox|commix)\b", "Automated vulnerability scanner"),
    (r"\b(?:nmap|masscan|zgrab|shodan|censys|zoomeye)\b", "Network reconnaissance / port scanner"),
    (r"\b(?:gobuster|dirbuster|ffuf|feroxbuster|wfuzz|dirb)\b", "Content / directory brute-force fuzzer"),
    (r"\b(?:burpcollaborator|oastify|interactsh|canarytokens|requestbin)\b", "Out-of-Band (OAST) interaction probe"),
]

_COMPILED_SCANNERS = [(re.compile(pattern, re.IGNORECASE), reason) for pattern, reason in _SCANNER_PATTERNS]


class BotScannerRule(Rule):
    RULE_ID = "960100"
    NAME = "Vulnerability Scanner Signatures Shield"
    CATEGORY = "Bot Protection"

    def match(self, request) -> Verdict:
        # Check User-Agent and headers
        ua = request.headers.get("user-agent", "")
        for pattern, reason in _COMPILED_SCANNERS:
            if pattern.search(ua):
                return Verdict(
                    blocked=True,
                    rule_id=self.RULE_ID,
                    reason=f"Bot Protection: {reason} identified in User-Agent ({ua[:60]})",
                    meta={"user_agent": ua[:100]},
                )

        # Check all payload values for OAST collaborator callback domains
        for field_label, value in request.iter_values():
            if not value:
                continue
            if re.search(r"\b(?:oastify\.com|interact\.sh|burpcollaborator\.net|canarytokens\.org)\b", value, re.IGNORECASE):
                return Verdict(
                    blocked=True,
                    rule_id=self.RULE_ID,
                    reason="Bot Protection: Out-of-Band (OAST) vulnerability callback domain probe",
                    meta={"field": field_label, "value": value[:100]},
                )

        return Verdict.clean(self.RULE_ID)
