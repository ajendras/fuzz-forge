"""Fuzz Forge — AI-powered API fuzzing with local LLMs.

Intelligently generates context-aware security tests (XSS, SQLi, IDOR,
auth bypass, business logic flaws) from OpenAPI specifications using Ollama.
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
) -> List[TestResult]:
    """High-level convenience function to scan an OpenAPI spec.

    Creates a FuzzForge instance, loads the spec, generates intelligent
    test cases via the local LLM, executes them (subject to dry_run and
    safety constraints), and writes reports.

    Safe defaults are used: dry_run=True, strict host allow-list, and
    non-destructive mutations only.

    Args:
        spec_path: Path to OpenAPI YAML or JSON file.
        model: Ollama model identifier (must be available locally).
        limit: Maximum test cases generated per endpoint.
        mutators: List of mutator names to enable. Pass None for all.
        dry_run: If True, generate tests but do not send HTTP requests.
        output_dir: Directory where HTML/JSON reports and curl repro
            files will be written.

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
    )

    forge.from_spec(spec_path)
    tests: List[TestCase] = forge.generate(limit=limit)
    results: List[TestResult] = forge.run(tests)

    if output_dir:
        from .reporter import Reporter

        reporter = Reporter()
        reporter.generate_html(results, output_dir)
        reporter.write_repro_files(results, output_dir)

    return results
