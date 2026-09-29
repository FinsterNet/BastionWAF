"""
GraphQL Introspection & Query Depth Abuse detection rule (OWASP API Security 950200).
Detects full schema introspection extraction and circular recursive query depth exhaustion.
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict

_INTROSPECTION_PATTERNS: List[Tuple[str, str]] = [
    # GraphQL Schema Introspection
    (r"\b__schema\s*\{", "GraphQL schema introspection query (__schema)"),
    (r"\b__type\s*\(\s*name\s*:", "GraphQL type inspection query (__type)"),
    (r"\b__directive\s*\{", "GraphQL directive introspection query"),
]

_COMPILED_GRAPHQL = [(re.compile(pattern, re.IGNORECASE), reason) for pattern, reason in _INTROSPECTION_PATTERNS]


class APIGraphQLAbuseRule(Rule):
    RULE_ID = "950200"
    NAME = "GraphQL Introspection & Depth Abuse Guard"
    CATEGORY = "API Security"

    def match(self, request) -> Verdict:
        # Check if GraphQL endpoint or contains query
        path = request.path.lower()
        body = request.body

        # 1. Introspection check
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_GRAPHQL:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=f"API Security: {reason}",
                        meta={"field": field_label, "matched": value[:100]},
                    )

        # 2. Query depth limit check (max 8 nested braces in GraphQL queries)
        if "graphql" in path or "query" in body.lower():
            depth = 0
            max_depth = 0
            for char in body:
                if char == '{':
                    depth += 1
                    if depth > max_depth:
                        max_depth = depth
                elif char == '}':
                    depth = max(0, depth - 1)

            if max_depth > 8:
                return Verdict(
                    blocked=True,
                    rule_id=self.RULE_ID,
                    reason=f"API Security: Excessive GraphQL query nesting depth ({max_depth} levels > limit of 8)",
                    meta={"max_depth": max_depth},
                )

        return Verdict.clean(self.RULE_ID)
