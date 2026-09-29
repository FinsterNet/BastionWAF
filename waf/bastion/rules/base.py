"""
Base interface for all Bastion detection rules (with Weighted Anomaly Scoring).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class Verdict:
    """Result of running a rule against a request."""

    blocked: bool
    rule_id: str
    reason: str = ""
    weight: float = 5.0
    meta: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def clean(cls, rule_id: str) -> "Verdict":
        """Shorthand for 'this rule found nothing.'"""
        return cls(blocked=False, rule_id=rule_id, weight=0.0)


class Rule(ABC):
    """
    Every detection rule implements this.
    """

    RULE_ID: str = "UNSET"
    NAME: str = "Unnamed Rule"
    CATEGORY: str = "OWASP Top 10"
    WEIGHT: float = 5.0  # Anomaly severity weight (1.0 to 5.0)

    @abstractmethod
    def match(self, request: Any) -> Verdict:
        """
        Inspect a normalized request and return a Verdict.
        """
        raise NotImplementedError
