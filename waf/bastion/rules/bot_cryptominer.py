"""
Cryptomining Script & Stratum Protocol Blocker (Bot Protection 960600).
Detects in-browser WebAssembly cryptocurrency miners, Coinhive scripts, and Stratum mining pool traffic.
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict

_MINER_PATTERNS: List[Tuple[str, str]] = [
    # In-browser JS miners and WebAssembly modules
    (r"\b(?:coinhive(?:\.min)?\.js|cryptonight\.wasm|deepMiner\.js|coin-hive|webminepool|crypto-loot|authedmine)\b", "In-browser cryptocurrency mining script / WebAssembly module"),
    # Stratum pool protocol URI
    (r"\bstratum\+tcp://[a-zA-Z0-9_\-\.]+:\d+", "Cryptocurrency Stratum mining pool connection URI"),
    # Common miner JS invocation signatures
    (r"(?:CoinHive\.Anonymous|CoinHive\.User|new\s+CoinHive|miner\.start\(\)|CryptoLoot\.Anonymous)", "Cryptominer JavaScript runtime initialization"),
]

_COMPILED_MINERS = [(re.compile(pattern, re.IGNORECASE), reason) for pattern, reason in _MINER_PATTERNS]


class BotCryptominerRule(Rule):
    RULE_ID = "960600"
    NAME = "Cryptomining Script & Stratum Blocker"
    CATEGORY = "Bot Protection"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_MINERS:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=f"Bot Protection: {reason}",
                        meta={"field": field_label, "matched_value": value[:200]},
                    )

        return Verdict.clean(self.RULE_ID)
