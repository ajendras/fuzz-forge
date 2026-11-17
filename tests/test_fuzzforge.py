"""Tests for Fuzz Forge.

Covers mutators, LLM fallback, core orchestrator, high-level scan, and
ensures CI passes with mocked external dependencies.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from fuzzforge import scan
from fuzzforge.core import APISpec, FuzzForge, TestCase, TestResult
from fuzzforge.llm import LLMClient
from fuzzforge.mutators import InjectionMutator, Mutator, get_mutators
from fuzzforge.parser import OpenAPIParser


# Suppress PytestCollectionWarning for Pydantic models imported in tests
pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestCollectionWarning")


def test_mutator_base():
    """Test that abstract Mutator cannot be instantiated and concrete mutators work."""
    with pytest.raises(TypeError, match="Can't instantiate abstract class Mutator with abstract method apply"):
        Mutator()

    mutator = InjectionMutator()
    assert mutator.name == "injection"
    assert "injection" in mutator.description.lower()

    test = TestCase(
        endpoint="GET /test",
        method="GET",
        path="/test",
        payload={"input": "original"},
    )
    mutated = mutator.apply(test)
    assert mutated is not None
    assert mutated.endpoint == test.endpoint
    assert "injection" in mutated.tags
    assert mutated.risk_potential == "high"
    assert mutated.payload.get("input") == "<script>alert(1)</script>"


def test_llm_client_fallback(mocker):
    """Test LLMClient gracefully falls back when Ollama is unavailable."""
    mocker.patch("fuzzforge.llm.ollama.chat", side_effect=RuntimeError("Ollama unavailable"))

    spec = APISpec(
        title="Test API",
        version="1.0.0",
        endpoints=[
            {"method": "GET", "path": "/health", "summary": "Health check"},
            {"method": "POST", "path": "/users", "summary": "Create user"},
            {"method": "GET", "path": "/pets", "summary": "List pets"},
        ],
        schemas={},
        servers=["http://localhost:8000"],
    )

    client = LLMClient(model="llama3.2")
    tests = client.generate_tests(spec, count=5)

    assert len(tests) == 3
    for t in tests:
        assert "fallback" in t.tags
        assert "LLM unavailable" in t.description
        assert t.risk_potential == "medium"


def test_fuzzforge_from_spec(mocker):
    """Test FuzzForge.from_spec uses the parser correctly."""
    mock_parser_class = mocker.patch("fuzzforge.parser.OpenAPIParser")
    mock_parser = MagicMock()
    mock_parser_class.return_value = mock_parser

    mock_spec = APISpec(
        title="Mocked Petstore",
        endpoints=[{"method": "GET", "path": "/pets"}],
    )
    mock_parser.parse.return_value = mock_spec

    forge = FuzzForge(model="llama3.2", dry_run=True)
    forge.from_spec("examples/petstore.yaml")

    mock_parser_class.assert_called_once()
    mock_parser.parse.assert_called_once_with("examples/petstore.yaml")
    assert forge.spec == mock_spec


def test_fuzzforge_generate(mocker):
    """Test generation pipeline (LLM + mutators) with mocks."""
    mock_llm_class = mocker.patch("fuzzforge.llm.LLMClient")
    mock_llm = MagicMock()
    mock_llm_class.return_value = mock_llm

    base_test = TestCase(
        endpoint="GET /pets",
        method="GET",
        path="/pets",
        payload={"name": "test"},
        tags=["base"],
    )
    mock_llm.generate_tests.return_value = [base_test]

    mock_get_mutators = mocker.patch("fuzzforge.mutators.get_mutators")
    mock_get_mutators.return_value = [InjectionMutator()]

    forge = FuzzForge(model="llama3.2", mutators=["injection"], dry_run=True)
    forge.spec = APISpec(
        title="Petstore",
        endpoints=[{"method": "GET", "path": "/pets"}],
        servers=["http://localhost:8000"],
    )

    tests = forge.generate(limit=5)
    assert len(tests) >= 2
    assert any("injection" in t.tags for t in tests)
    assert any(t.risk_potential == "high" for t in tests)


def test_fuzzforge_run(mocker):
    """Test run pipeline with executor mock and risk scoring."""
    mock_executor_class = mocker.patch("fuzzforge.executor.TestExecutor")
    mock_executor = MagicMock()
    mock_executor_class.return_value = mock_executor

    test_case = TestCase(
        endpoint="GET /pets",
        method="GET",
        path="/pets",
        tags=["injection"],
    )
    mock_result = TestResult(
        test_case=test_case,
        risk_score=4,
        findings=[],
    )
    mock_executor.run_all.return_value = [mock_result]

    forge = FuzzForge(model="llama3.2", dry_run=True)
    forge.spec = APISpec(
        title="Test",
        endpoints=[],
        servers=["http://localhost:8000"],
    )

    results = forge.run([test_case])
    mock_executor_class.assert_called_once()
    assert len(results) == 1
    # risk scoring in FuzzForge.run updates based on tags
    assert results[0].risk_score == 7
    assert len(results[0].findings) > 0


def test_scan_high_level(tmp_path):
    """High-level scan() integration test using real components (dry-run + fallback)."""
    output_dir = tmp_path / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    results = scan(
        spec_path="examples/petstore.yaml",
        model="llama3.2",
        limit=6,
        dry_run=True,
        output_dir=str(output_dir),
    )

    assert len(results) >= 2
    assert all(isinstance(r, TestResult) for r in results)
    assert any(r.risk_score > 4 for r in results)
    assert any("injection" in r.test_case.tags or "fallback" in r.test_case.tags for r in results)

    # Reporter should have written artifacts
    html_files = list(output_dir.glob("*.html"))
    assert len(html_files) > 0 or (output_dir / "report.html").exists()
