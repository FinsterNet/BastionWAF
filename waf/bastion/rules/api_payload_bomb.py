"""
JSON / XML Payload Bomb & Resource Exhaustion detection rule (OWASP API Security 950500).
Detects deeply nested JSON/XML payload structures (>15 levels) designed to crash backend parsers (Billion Laughs / Stack Overflow).
"""

import json
from typing import Any, Dict, List, Tuple
from .base import Rule, Verdict


def _calculate_json_depth(obj: Any) -> int:
    if isinstance(obj, dict):
        if not obj:
            return 1
        return 1 + max(_calculate_json_depth(v) for v in obj.values())
    elif isinstance(obj, list):
        if not obj:
            return 1
        return 1 + max(_calculate_json_depth(item) for item in obj)
    return 0


class APIPayloadBombRule(Rule):
    RULE_ID = "950500"
    NAME = "JSON/XML Payload Bomb & Parser DoS Guard"
    CATEGORY = "API Security"

    def match(self, request) -> Verdict:
        body = request.body
        if not body or len(body) < 50:
            return Verdict.clean(self.RULE_ID)

        # 1. Fast bracket depth check for JSON structures
        if body.startswith("{") or body.startswith("["):
            depth = 0
            max_depth = 0
            for char in body:
                if char in ('{', '['):
                    depth += 1
                    if depth > max_depth:
                        max_depth = depth
                elif char in ('}', ']'):
                    depth = max(0, depth - 1)

            if max_depth > 15:
                return Verdict(
                    blocked=True,
                    rule_id=self.RULE_ID,
                    reason=f"API Security: JSON payload nesting depth exceeded ({max_depth} levels > limit of 15)",
                    meta={"nesting_depth": max_depth},
                )

            # Validate by parsing JSON
            try:
                parsed = json.loads(body)
                actual_depth = _calculate_json_depth(parsed)
                if actual_depth > 15:
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=f"API Security: JSON payload recursion depth exceeded ({actual_depth} levels)",
                        meta={"actual_depth": actual_depth},
                    )
            except Exception:
                pass

        # 2. Fast tag depth check for XML structures
        if "<" in body and ">" in body and ("<?xml" in body or "<!DOCTYPE" in body):
            xml_depth = 0
            max_xml_depth = 0
            for i in range(len(body) - 1):
                if body[i] == '<' and body[i + 1] not in ('/', '!', '?'):
                    xml_depth += 1
                    if xml_depth > max_xml_depth:
                        max_xml_depth = xml_depth
                elif body[i] == '<' and body[i + 1] == '/':
                    xml_depth = max(0, xml_depth - 1)

            if max_xml_depth > 15:
                return Verdict(
                    blocked=True,
                    rule_id=self.RULE_ID,
                    reason=f"API Security: XML entity nesting depth exceeded ({max_xml_depth} levels > limit of 15)",
                    meta={"xml_depth": max_xml_depth},
                )

        return Verdict.clean(self.RULE_ID)
