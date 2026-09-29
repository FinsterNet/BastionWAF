"""
Headless Automation Framework detection rule (Bot Protection 960200).
Detects headless browser scrapers and unauthenticated script automation clients.
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict

_HEADLESS_PATTERNS: List[Tuple[str, str]] = [
    (r"\b(?:HeadlessChrome|PhantomJS|Selenium|Puppeteer|Playwright|Nightmare)\b", "Headless browser automation tool"),
    (r"\b(?:python-requests|aiohttp|urllib|httpx|httpclient|Go-http-client|Java/|Apache-HttpClient|node-fetch|axios/|libcurl|curl/\d|Wget/)\b", "Generic HTTP script/library client"),
    (r"\b(?:Scrapy|BeautifulSoup|mechanize|colly)\b", "Web scraper bot framework"),
]

_COMPILED_HEADLESS = [(re.compile(pattern, re.IGNORECASE), reason) for pattern, reason in _HEADLESS_PATTERNS]


class BotHeadlessRule(Rule):
    RULE_ID = "960200"
    NAME = "Headless Automation Framework Guard"
    CATEGORY = "Bot Protection"

    def match(self, request) -> Verdict:
        ua = request.headers.get("user-agent", "")

        # 1. Match headless / script bot patterns
        for pattern, reason in _COMPILED_HEADLESS:
            if pattern.search(ua):
                return Verdict(
                    blocked=True,
                    rule_id=self.RULE_ID,
                    reason=f"Bot Protection: {reason} detected ({ua[:60]})",
                    meta={"user_agent": ua[:100]},
                )

        return Verdict.clean(self.RULE_ID)
