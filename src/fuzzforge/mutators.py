"""Security mutators that transform base LLM-generated tests into targeted attacks.

Includes InjectionMutator, AuthBypassMutator, and LogicMutator. Each
implements the apply() contract to return a mutated TestCase copy.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Optional


class Mutator(ABC):
    """Abstract base for all test mutators."""

    name: str = "base"
    description: str = "Base mutator"

    def __init__(self) -> None:
        self.common_payloads: Dict[str, List[str]] = {
            "xss": [
                "<script>alert(1)</script>",
                "\"><svg/onload=alert(1)>",
                "javascript:alert(1)",
            ],
            "sqli": ["' OR '1'='1", "'; DROP TABLE users;--", "1 UNION SELECT 1,2,3"],
            "cmdi": ["; cat /etc/passwd", "$(whoami)", "| ls -la"],
        }

    @abstractmethod
    def apply(self, test: TestCase) -> Optional[TestCase]:
        """Return a mutated copy of the test case or None if inapplicable.

        Implementations must not modify the original test object.
        """
        raise NotImplementedError


class InjectionMutator(Mutator):
    """Injects XSS, SQLi, and command-injection payloads into string fields."""

    name = "injection"
    description = "Adds injection payloads while preserving endpoint semantics"

    def apply(self, test: TestCase) -> Optional[TestCase]:
        mutated = test.model_copy(deep=True)
        mutated.tags = list({*mutated.tags, "injection", "xss"})

        if not mutated.description:
            mutated.description = "Injection test (XSS/SQLi)"
        else:
            mutated.description = f"{mutated.description} + injection vector"

        payload = dict(mutated.payload)
        if not payload:
            payload = {"input": self.common_payloads["xss"][0]}
        else:
            # Mutate the first string or numeric field
            for key, value in list(payload.items()):
                if isinstance(value, (str, int, float)):
                    payload[key] = self.common_payloads["xss"][0]
                    break
            else:
                payload["param"] = self.common_payloads["sqli"][0]

        mutated.payload = payload
        mutated.risk_potential = "high"
        return mutated


class AuthBypassMutator(Mutator):
    """Attempts common authentication and authorization bypass techniques."""

    name = "auth_bypass"
    description = "Tries to bypass auth using malformed tokens and privilege-escalation headers"

    def apply(self, test: TestCase) -> Optional[TestCase]:
        mutated = test.model_copy(deep=True)
        mutated.tags = list({*mutated.tags, "auth_bypass", "authorization"})

        if not mutated.description:
            mutated.description = "Authentication bypass attempt"
        else:
            mutated.description += " (auth bypass variant)"

        headers = dict(mutated.headers)
        headers.update(
            {
                "Authorization": "Bearer null",
                "X-Forwarded-For": "127.0.0.1",
                "X-Original-URL": mutated.path,
                "X-Role": "admin",
            }
        )
        mutated.headers = headers

        # Sometimes remove Content-Type to trigger parser quirks
        if "Content-Type" in mutated.headers and mutated.method in ("POST", "PUT"):
            mutated.headers.pop("Content-Type", None)

        mutated.risk_potential = "critical"
        return mutated


class LogicMutator(Mutator):
    """Creates variants that target business-logic and IDOR weaknesses."""

    name = "logic"
    description = "Modifies identifiers and parameters to trigger logic flaws and IDOR"

    def apply(self, test: TestCase) -> Optional[TestCase]:
        mutated = test.model_copy(deep=True)
        mutated.tags = list({*mutated.tags, "logic", "idor"})

        if not mutated.description:
            mutated.description = "Business logic / IDOR test"
        else:
            mutated.description += " (logic mutation)"

        payload = dict(mutated.payload)
        mutated_id = False

        for key in list(payload.keys()):
            if any(term in key.lower() for term in ("id", "user", "account", "owner")):
                val = payload[key]
                if isinstance(val, int):
                    payload[key] = 999999
                elif isinstance(val, str):
                    payload[key] = "999999" if val.isdigit() else "other-user-uuid"
                mutated_id = True
                break

        if not mutated_id:
            payload["target_user_id"] = 0
            payload["admin"] = True

        mutated.payload = payload
        mutated.query_params = {"debug": "true", "bypass": "1"}
        mutated.risk_potential = "high"
        return mutated


def get_mutators(enabled: List[str]) -> List[Mutator]:
    """Return instantiated mutators for the given list of names.

    The special value 'all' (or an empty list) returns every mutator.
    Unknown names are silently ignored.
    """
    registry: Dict[str, type[Mutator]] = {
        "injection": InjectionMutator,
        "auth_bypass": AuthBypassMutator,
        "logic": LogicMutator,
    }

    requested = [name.lower().strip() for name in enabled]
    if not requested or "all" in requested:
        return [cls() for cls in registry.values()]

    instances: List[Mutator] = []
    for name in requested:
        if name in registry:
            instances.append(registry[name]())

    # Guarantee at least one mutator so the pipeline never becomes empty
    return instances or [InjectionMutator()]
