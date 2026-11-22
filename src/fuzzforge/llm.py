"""LLM client for generating contextual security test cases.

Uses Ollama to turn an APISpec into a list of intelligent TestCase
objects that understand the purpose of each endpoint.
Now includes security scheme information in prompts.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

import ollama

from .core import APISpec, TestCase


class LLMClient:
    """Client that queries a local Ollama model for security test ideas."""

    def __init__(self, model: str = "llama3.2") -> None:
        """Initialize with the Ollama model to use.

        Args:
            model: Name of the model (must be pulled locally).

        Raises:
            ValueError: If model name is empty.
        """
        if not model or not isinstance(model, str):
            raise ValueError("model must be a non-empty string")
        self.model = model

    def generate_tests(self, spec: APISpec, count: int = 10) -> List[TestCase]:
        """Generate high-signal security tests using the local LLM.

        Args:
            spec: Parsed API specification.
            count: Desired number of test cases.

        Returns:
            List of TestCase objects. Falls back to static tests on error.

        Raises:
            ValueError: On invalid count.
        """
        if count < 1:
            raise ValueError("count must be at least 1")

        prompt = self._build_prompt(spec, count)

        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an expert application security engineer. "
                            "Generate targeted test cases that respect the "
                            "semantic purpose of each endpoint. Output ONLY "
                            "a valid JSON array. Never add explanations."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": 0.4, "top_p": 0.9, "num_predict": 2000},
            )

            content: str = response["message"]["content"]
            raw_list = self._extract_json(content)

            test_cases: List[TestCase] = []
            for item in raw_list[:count]:
                try:
                    test_cases.append(
                        TestCase(
                            endpoint=item.get("endpoint", "GET /unknown"),
                            method=item.get("method", "GET"),
                            path=item.get("path", "/"),
                            payload=item.get("payload", {}),
                            headers=item.get("headers", {}),
                            tags=item.get("tags", ["llm_generated"]),
                            description=item.get(
                                "description", "LLM-generated contextual security test"
                            ),
                            risk_potential=item.get("risk_potential", "medium"),
                            security=item.get("security", {}),
                        )
                    )
                except Exception:  # noqa: PERF203 - continue on single bad item
                    continue

            return test_cases if test_cases else self._fallback_tests(spec, count)

        except (ollama.ResponseError, ollama.RequestError) as exc:
            # Graceful degradation when Ollama is not running or model missing
            print(f"Warning: LLM generation failed ({exc}). Using fallback tests.")
            return self._fallback_tests(spec, count)
        except ImportError as exc:
            raise RuntimeError("ollama package is required") from exc
        except Exception as exc:  # noqa: BLE001
            print(f"Warning: Unexpected LLM error: {exc}. Using fallback tests.")
            return self._fallback_tests(spec, count)

    def _build_prompt(self, spec: APISpec, count: int) -> str:
        """Construct a detailed, self-contained prompt for the LLM."""
        endpoint_lines: List[str] = []
        for ep in spec.endpoints[:8]:
            method = ep.get("method", "GET")
            path = ep.get("path", "/")
            summary = ep.get("summary", "No summary provided")
            endpoint_lines.append(f"  • {method} {path} – {summary}")

        schema_names = list(spec.schemas.keys())[:6]
        schema_line = f"Schemas: {', '.join(schema_names)}" if schema_names else "No schemas defined."

        security_info = ""
        if spec.security_schemes:
            security_info = (
                "\nSecurity Schemes:\n"
                + json.dumps(spec.security_schemes, indent=2)
                + "\nUse these schemes when generating tests. For auth_bypass tests "
                "omit or use invalid credentials. Include a 'security' key when relevant."
            )

        return f"""Analyze the following API and generate {count} high-value security test cases.

API: {spec.title} v{spec.version}
Servers: {', '.join(spec.servers)}
{security_info}

Endpoints:
{chr(10).join(endpoint_lines)}

{schema_line}

Focus on:
• Injection (XSS, SQLi, command injection)
• Authentication / authorization bypass (respecting the defined OAuth2 and apiKey schemes)
• IDOR and broken access control
• Business logic flaws that respect the endpoint's purpose

Return a JSON array of objects. Each object must contain exactly these keys:
- endpoint (string)
- method (string)
- path (string)
- payload (object)
- headers (object)
- tags (array of strings e.g. ["xss", "injection", "auth_bypass"])
- description (string explaining why the test matters)
- risk_potential ("low", "medium", "high", or "critical")
- security (object, optional)

Output ONLY the JSON array. No markdown, no extra text.
"""

    def _extract_json(self, text: str) -> List[Dict[str, Any]]:
        """Extract the first JSON array from LLM output.

        Handles common LLM formatting (code fences, extra text).
        """
        # Try code-fenced JSON first
        fence_match = re.search(r"```(?:json)?\s*(.+?)\s*```", text, re.DOTALL)
        if fence_match:
            candidate = fence_match.group(1).strip()
        else:
            candidate = text.strip()

        # Find anything that looks like a JSON array
        array_match = re.search(r"(\[\s*\{.*?\}\s*\])", candidate, re.DOTALL)
        if not array_match:
            return []

        json_str = array_match.group(1)
        try:
            parsed = json.loads(json_str)
            if isinstance(parsed, list):
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass
        return []

    def _fallback_tests(self, spec: APISpec, count: int) -> List[TestCase]:
        """Return deterministic fallback tests when the LLM cannot be used."""
        tests: List[TestCase] = []
        for i, ep in enumerate(spec.endpoints[:count]):
            path = ep.get("path", f"/api/v1/resource{i+1}")
            method = ep.get("method", "POST")
            tests.append(
                TestCase(
                    endpoint=f"{method} {path}",
                    method=method,
                    path=path,
                    payload={"username": "<script>alert(1)</script>", "id": 9999},
                    headers={"Content-Type": "application/json"},
                    tags=["injection", "xss", "fallback"],
                    description="Fallback test case (LLM unavailable)",
                    risk_potential="medium",
                    security={},  # ensure dict (OpenAPI security can be a list)
                )
            )
        return tests
