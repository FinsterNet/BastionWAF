"""
Malicious File Upload and Webshell detection rule (OWASP CRS 933400).
Detects executable script extensions, polyglots, and inline webshell signatures.
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict

_WEBSHELL_PATTERNS: List[Tuple[str, str]] = [
    # Executable script extensions in filename parameters or multipart headers
    (r"filename\s*=\s*['\"][^'\"]*\.(?:php[2-8]?|phtml|phar|jsp[xa]?|asp[xa]?|cgi|pl|py|sh|bash|exe|dll)['\"]", "Executable server-side script file upload attempt"),
    # Double extension evasion (e.g. shell.php.jpg, backdoor.jsp.png)
    (r"filename\s*=\s*['\"][^'\"]*\.(?:php|phtml|jsp|asp|aspx)\.(?:jpg|png|gif|pdf|txt)['\"]", "Double extension bypass attempt"),
    # Inline webshell payload signatures in body/files
    (r"(?:<\?(?:php|=)[\s\S]*?(?:eval|assert|system|passthru|shell_exec|base64_decode|gzinflate)\s*\()", "PHP one-word webshell backdoor signature"),
    (r"(?:Runtime\.getRuntime\(\)\.exec|<%@\s*page\s+import=[\"']java\.io)", "JSP webshell backdoor signature"),
    (r"(?:<%[\s\S]*?(?:eval\s*\(|execute\s*\(|request\(\"[a-zA-Z0-9_-]+\"\)))", "ASP/ASPX classic webshell execution sink"),
    # Weevely / China Chopper / Godzilla webshell markers
    (r"\b(?:eval\s*\(\s*\$_POST\[|assert\s*\(\s*\$_POST\[|\$_REQUEST\[['\"][a-zA-Z0-9]+['\"]\]\s*\()", "China Chopper / Weevely webshell evaluation signature"),
]

_COMPILED_WEBSHELL = [(re.compile(pattern, re.IGNORECASE), reason) for pattern, reason in _WEBSHELL_PATTERNS]


class WebshellUploadRule(Rule):
    RULE_ID = "933400"
    NAME = "Malicious File Upload & Webshell Guard"
    CATEGORY = "OWASP Top 10"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_WEBSHELL:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=f"Semantic Upload: {reason}",
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)
