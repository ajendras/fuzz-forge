"""Tests for Fuzz Forge core functionality.

Covers scanning pipeline, LLM mocking, mutator transformations,
model validation and error handling.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from fuzzforge import scan
from fuzzforge.core import APISpec, FuzzForge, TestCase, TestResult
from fuzzforge.llm import LLMClient
from fuzzforge.mutators import (
    AuthBypassMutator,
    get_mutators,
    InjectionMutator,
    LogicMutator,
    Mutator,
)


@pytest.fixture
def minimal_spec() -> APISpec:
    """Return a minimal valid APISpec for testing."""
    return APISpec(
        title="Minimal API",
        version="1.0.0",
        endpoints=[
            {"method": "GET", "path": "/health", "summary": "Health check"},
            {"method": "POST", "path": "/pets", "summary": "Create pet"},
        ],
        schemas={},
        servers=["http://localhost:8080"],
    )


@pytest.fixture
def sample_testcase() -> TestCase:
    """Return a representative TestCase."""
    return TestCase(
        id="tc_123",
        endpoint="POST /pets",
        method="POST",
        path="/pets",
        payload={"name": "Fluffy", "age": 3},
        tags=["pet", "create"],
        description="Create a new pet record",
        risk_potential="medium",
    )


def test_testcase_to_curl(sample_testcase: TestCase) -> None:
    """Test curl command generation with query params and headers."""
    curl_cmd = sample_testcase.to_curl(base_url="https://api.example.com")
    assert "curl -X POST 'https://api.example.com/pets'" in curl_cmd
    assert "-d " in curl_cmd


def test_testcase_validation() -> None:
    """Test pydantic validation for TestCase."""
    with pytest.raises(ValidationError):
        TestCase(endpoint=None)  # type: ignore[arg-type]


def test_apispec_validation() -> None:
    """APISpec requires at least one endpoint."""
    with pytest.raises(ValueError, match="at least one endpoint"):
        APISpec(endpoints=[])


def test_mutator_base() -> None:
    """Base class cannot be used directly."""
    with pytest.raises(NotImplementedError):
        Mutator().apply(TestCase(endpoint="GET /test"))


def test_injection_mutator(sample_testcase: TestCase) -> None:
    """InjectionMutator injects XSS payloads and updates metadata."""
    mutator = InjectionMutator()
    mutated = mutator.apply(sample_testcase)
    assert mutated is not None
    assert "injection" in mutated.tags
    assert "xss" in mutated.tags
    assert mutated.risk_potential == "high"
    assert any(
        p in str(mutated.payload) for p in ["<script>", "alert(1)"]
    )


def test_auth_bypass_mutator(sample_testcase: TestCase) -> None:
    """AuthBypassMutator adds common bypass headers."""
    mutator = AuthBypassMutator()
    mutated = mutator.apply(sample_testcase)
    assert mutated is not None
    assert "auth_bypass" in mutated.tags
    assert "Authorization" in mutated.headers
    assert mutated.risk_potential == "critical"


def test_logic_mutator(sample_testcase: TestCase) -> None:
    """LogicMutator targets IDOR and business logic by mutating identifiers."""
    mutator = LogicMutator()
    mutated = mutator.apply(sample_testcase)
    assert mutated is not None
    assert "logic" in mutated.tags
    assert "idor" in mutated.tags
    assert mutated.query_params.get("debug") == "true"


def test_get_mutators() -> None:
    """Registry returns correct mutator instances."""
    assert len(get_mutators(["all"])) == 3
    specific = get_mutators(["injection", "logic"])
    assert len(specific) == 2
    assert isinstance(specific[0], InjectionMutator)
    assert isinstance(specific[1], LogicMutator)
    # fallback to injection when unknown names supplied
    assert isinstance(get_mutators(["unknown"])[0], InjectionMutator)


@patch("fuzzforge.llm.ollama.chat")
def test_llm_client_success(mock_chat: MagicMock, minimal_spec: APISpec) -> None:
    """LLMClient parses JSON response into TestCase objects."""
    mock_json = json.dumps(
        [
            {
                "endpoint": "POST /pets",
                "method": "POST",
                "path": "/pets",
                "payload": {"name": "<script>alert(1)</script>"},
                "headers": {"X-Test": "1"},
                "tags": ["xss", "injection"],
                "description": "XSS in pet name",
                "risk_potential": "high",
            }
        ]
    )
    mock_chat.return_value = {"message": {"content": mock_json}}

    client = LLMClient(model="llama3.2")
    tests = client.generate_tests(minimal_spec, count=5)
    assert len(tests) == 1
    assert tests[0].tags == ["xss", "injection"]
    assert tests[0].risk_potential == "high"


@patch("fuzzforge.llm.ollama.chat")
def test_llm_client_fallback(mock_chat: MagicMock, minimal_spec: APISpec) -> None:
    """Graceful fallback when Ollama is unavailable."""
    mock_chat.side_effect = Exception("Connection refused")
    client = LLMClient(model="llama3.2")
    tests = client.generate_tests(minimal_spec, count=3)
    assert len(tests) == 3
    assert all("fallback" in t.tags for t in tests)


def test_llm_invalid_count(minimal_spec: APISpec) -> None:
    """LLMClient validates count parameter."""
    client = LLMClient()
    with pytest.raises(ValueError, match="count must be at least 1"):
        client.generate_tests(minimal_spec, count=0)


@patch("fuzzforge.core.OpenAPIParser")
def test_fuzzforge_from_spec(mock_parser: MagicMock, minimal_spec: APISpec) -> None:
    """FuzzForge loads spec via parser."""
    mock_parser.return_value.parse.return_value = minimal_spec
    forge = FuzzForge(model="llama3.2", dry_run=True)
    forge.from_spec("examples/petstore.yaml")
    assert forge.spec == minimal_spec


@patch("fuzzforge.core.LLMClient")
def test_fuzzforge_generate(mock_llm_client: MagicMock, minimal_spec: APISpec) -> None:
    """generate() combines LLM output with mutator expansions."""
    mock_llm_client.return_value.generate_tests.return_value = [
        TestCase(
            endpoint="GET /health",
            method="GET",
            path="/health",
            tags=["base"],
        )
    ]
    forge = FuzzForge(model="llama3.2", dry_run=True, mutators=["all"])
    forge.spec = minimal_spec
    tests = forge.generate(limit=10)
    assert len(tests) > 3
    assert any("injection" in t.tags for t in tests)


@patch("fuzzforge.core.TestExecutor")
def test_fuzzforge_run(mock_executor: MagicMock, sample_testcase: TestCase) -> None:
    """run() enriches results with contextual risk scoring."""
    mock_result = TestResult(
        test_case=sample_testcase,
        risk_score=8,
        findings=["Possible injection"],
        status_code=200,
    )
    mock_executor.return_value.run_all.return_value = [mock_result]

    forge = FuzzForge(dry_run=True)
    forge.spec = APISpec(
        title="Test", endpoints=[{"method": "POST", "path": "/pets"}]
    )
    results = forge.run([sample_testcase])
    assert len(results) == 1
    assert results[0].risk_score >= 7


@patch("fuzzforge.__init__.Path.exists")
@patch("fuzzforge.core.FuzzForge")
def test_scan_high_level(mock_forge_cls: MagicMock, mock_exists: MagicMock) -> None:
    """High-level scan() orchestrates the full pipeline."""
    mock_exists.return_value = True
    mock_forge = MagicMock()
    mock_forge_cls.return_value = mock_forge
    mock_forge.generate.return_value = [TestCase(endpoint="GET /test", path="/test")]
    mock_result = TestResult(
        test_case=TestCase(endpoint="GET /test", path="/test"),
        risk_score=6,
    )
    mock_forge.run.return_value = [mock_result]

    with patch("fuzzforge.reporter.Reporter") as mock_reporter_cls:
        mock_reporter = MagicMock()
        mock_reporter_cls.return_value = mock_reporter
        results = scan(
            spec_path="examples/petstore.yaml",
            model="llama3.2",
            limit=5,
            dry_run=True,
            output_dir=None,
        )

    assert len(results) == 1
    assert results[0].risk_score == 6
    mock_forge.from_spec.assert_called_with("examples/petstore.yaml")


def test_scan_input_validation() -> None:
    """scan() validates arguments before proceeding."""
    with patch("pathlib.Path.exists", return_value=True):
        with pytest.raises(ValueError, match="limit must be at least 1"):
            scan(spec_path="dummy.yaml", limit=0)


@patch("fuzzforge.executor.TestExecutor")
def test_dry_run_simulation(mock_executor_cls: MagicMock, minimal_spec: APISpec) -> None:
    """Dry-run mode produces simulated findings."""
    mock_executor = MagicMock()
    mock_executor.run_all.return_value = [
        TestResult(
            test_case=TestCase(
                endpoint="POST /pets", path="/pets", tags=["injection"]
            ),
            risk_score=7,
            findings=["Potential injection vector (dry-run)"],
        )
    ]
    mock_executor_cls.return_value = mock_executor

    forge = FuzzForge(dry_run=True, model="llama3.2")
    forge.spec = minimal_spec
    tests = [TestCase(endpoint="POST /pets", path="/pets", tags=["injection"])]
    results = forge.run(tests)
    assert results[0].risk_score == 7
