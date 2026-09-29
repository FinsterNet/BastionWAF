"""
Sensitive Configuration & Backup Snooping detection rule (OWASP CRS 930200).
Detects automated probing for .env, .git, cloud credentials, database backups, and server configuration files.
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict

_SENSITIVE_PATHS: List[Tuple[str, str]] = [
    # Environment and configuration files
    (r"(?:^|/)\.env(?:\.[a-zA-Z0-9_-]+)?$", "Environment variable configuration file (.env)"),
    (r"(?:^|/)(?:wp-config\.php(?:\.bak|\.old|\.swp|\.save)?|configuration\.php|config\.inc\.php)$", "Web application core configuration file"),
    # Version control repositories
    (r"(?:^|/)\.git/(?:config|HEAD|index|logs/HEAD|FETCH_HEAD)", "Git repository metadata / config inspection"),
    (r"(?:^|/)\.svn/(?:entries|wc\.db)", "SVN repository metadata exposure"),
    # Cloud and SSH credentials
    (r"(?:^|/)\.(?:aws/credentials|ssh/id_rsa|ssh/id_ed25519|ssh/authorized_keys|kube/config)", "Cloud provider / SSH private credential exposure"),
    (r"(?:^|/)(?:docker-compose\.yml|Dockerfile|\.docker/config\.json)$", "Docker deployment & secret configuration"),
    # Database and source backups
    (r"(?:^|/)[a-zA-Z0-9_-]+\.(?:sql|sql\.gz|sql\.tar|bak|backup|tar\.gz|tgz|zip|7z)$", "Raw database dump / archive backup probe"),
]

_COMPILED_SENSITIVE = [(re.compile(pattern, re.IGNORECASE), desc) for pattern, desc in _SENSITIVE_PATHS]


class SensitiveFilesRule(Rule):
    RULE_ID = "930200"
    NAME = "Sensitive Config & Backup Snooping Guard"
    CATEGORY = "OWASP Top 10"

    def match(self, request) -> Verdict:
        path = request.path or "/"
        for pattern, desc in _COMPILED_SENSITIVE:
            if pattern.search(path):
                return Verdict(
                    blocked=True,
                    rule_id=self.RULE_ID,
                    reason=f"Sensitive Reconnaissance: Probing for {desc}",
                    meta={"path": path},
                )
        return Verdict.clean(self.RULE_ID)
