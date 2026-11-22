"""Fuzz Forge — AI-powered API fuzzing with local LLMs.

Intelligently generates context-aware security tests (XSS, SQLi, IDOR,
auth bypass, business logic flaws, GraphQL mutation abuse) from OpenAPI
and GraphQL schemas using Ollama. Supports first-class OAuth2, API-key,
and GraphQL SDL parsing with dedicated mutation generation.
"""

from __future__ import annotations

import importlib.metadata
from pathlib import Path
from typing import Any, List, Optional

from .core import FuzzForge, TestCase, TestResult

try:
    __version__ = importlib.metadata.version("fuzz-forge")
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.1.0"

__all__ = ["FuzzForge", "TestCase", "TestResult", "scan"]


def scan(
    spec_path: str,
    model: str = "llama3.2",
    limit: int = 20,
    mutators: Optional[List[str]] = None,
    dry_run: bool = True,
    output_dir: Optional[str] = "fuzz-reports",
    api_key: Optional[str] = None,
    bearer_token: Optional[str] = None,
) -> List[TestResult]:
    """High-level convenience function to scan an OpenAPI or GraphQL spec.

    Creates a FuzzForge instance, loads the spec, generates intelligent
    test cases via the local LLM, executes them (subject to dry_run and
    safety constraints), and writes reports.

    Safe defaults are used: dry_run=True, strict host allow-list, and
    non-destructive mutations only. OAuth2/apiKey credentials are injected
    by the executor unless a test is tagged for auth bypass. GraphQL files
    (.graphql/.gql) are auto-detected and receive mutation-focused tests.

    The generated report.html is fully interactive with request/response
    viewers (formatted JSON/headers) and one-click replay (copy cURL or
    live browser fetch with safety warning).

    Args:
        spec_path: Path to OpenAPI YAML/JSON or GraphQL SDL file.
        model: Ollama model identifier (must be available locally).
        limit: Maximum test cases generated per endpoint.
        mutators: List of mutator names to enable. Pass None for all.
        dry_run: If True, generate tests but do not send HTTP requests.
        output_dir: Directory where HTML/JSON/SARIF reports and curl repro
            files will be written.
        api_key: API key for schemes of type apiKey.
        bearer_token: Token for OAuth2 or Bearer schemes.

    Returns:
        List of executed TestResult objects with risk scoring and
        reproduction steps.

    Raises:
        FileNotFoundError: If spec_path does not exist.
        ValueError: If model is not available or spec is invalid.
    """
    if not Path(spec_path).exists():
        raise FileNotFoundError(f"Spec file not found: {spec_path}")

    if limit < 1:
        raise ValueError("limit must be at least 1")

    forge = FuzzForge(
        model=model,
        mutators=mutators or ["all"],
        dry_run=dry_run,
        output_dir=output_dir,
        api_key=api_key,
        bearer_token=bearer_token,
    )

    forge.from_spec(spec_path)
    tests: List[TestCase] = forge.generate(limit=limit)
    results: List[TestResult] = forge.run(tests)

    if output_dir:
        from .reporter import Reporter

        reporter = Reporter()
        reporter.generate_html(results, output_dir)
        reporter.generate_json(results, output_dir)
        reporter.generate_sarif(results, output_dir)
        reporter.write_repro_files(results, output_dir)

    return results
