"""Test suite for Fuzz Forge.

Covers models, orchestrator, parser, LLM fallback, mutators, executor (dry-run,
auth injection, bypass skipping), scan() helper, and reporter. LLM and HTTP
calls are fully mocked so the suite runs without Ollama or a live server.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from fuzzforge import scan
from fuzzforge.core import APISpec, FuzzForge, TestCase, TestResult
from fuzzforge.executor import TestExecutor
from fuzzforge.llm import LLMClient
from fuzzforge.mutators import (
    AuthBypassMutator,
    InjectionMutator,
    LogicMutator,
    get_mutators,
)
from fuzzforge.parser import OpenAPIParser
from fuzzforge.reporter import Reporter


def test_models_validate() -> None:
    """Pydantic models accept valid data and compute derived properties."""
    spec = APISpec(
        title="Test API",
        endpoints=[{"method": "GET", "path": "/health"}],
    )
    assert spec.title == "Test API"
    assert len(spec.endpoints) == 1

    tc = TestCase(
        endpoint="GET /health",
        method="GET",
        path="/health",
        tags=["test"],
        risk_potential="medium",
    )
    assert tc.endpoint == "GET /health"
    assert tc.to_curl("http://localhost:8000") == "curl -X GET 'http://localhost:8000/health'"

    result = TestResult(test_case=tc, risk_score=7)
    assert result.is_vulnerable is True
    assert result.risk_score == 7


def test_fuzzforge_init_validation() -> None:
    """Constructor enforces safe defaults and rejects bad values."""
    forge = FuzzForge(
        model="llama3.2",
        dry_run=True,
        rate_limit_rps=10.0,
        allowed_hosts=["localhost"],
    )
    assert forge.model == "llama3.2"
    assert forge.dry_run is True
    assert forge.rate_limit_rps == 10.0
    assert "localhost" in forge.allowed_hosts

    with pytest.raises(ValueError):
        FuzzForge(model="")

    with pytest.raises(ValueError):
        FuzzForge(mutators="not-a-list")  # type: ignore[arg-type]


@patch("fuzzforge.core.OpenAPIParser")
def test_from_spec(mock_parser: MagicMock) -> None:
    """from_spec parses a file into an APISpec."""
    mock_spec = APISpec(
        title="Petstore",
        endpoints=[{"method": "GET", "path": "/pets"}],
        security_schemes={"apiKey": {"type": "apiKey"}},
    )
    mock_parser.return_value.parse.return_value = mock_spec

    forge = FuzzForge(dry_run=True)
    forge.from_spec("examples/petstore.yaml")
    assert forge.spec is not None
    assert forge.spec.title == "Petstore"
    assert len(forge.spec.endpoints) == 1


@patch("fuzzforge.core.LLMClient")
def test_generate(mock_llm_class: MagicMock) -> None:
    """generate calls LLM and expands via mutators, deduplicates."""
    mock_client = mock_llm_class.return_value
    mock_client.generate_tests.return_value = [
        TestCase(
            endpoint="GET /pets",
            method="GET",
            path="/pets",
            tags=["base"],
        )
    ]

    forge = FuzzForge(model="llama3.2", mutators=["injection", "logic"], dry_run=True)
    forge.spec = APISpec(endpoints=[{"method": "GET", "path": "/pets"}])
    tests = forge.generate(limit=10)

    assert len(tests) >= 3  # base + two mutators
    tags = {tag for t in tests for tag in t.tags}
    assert "injection" in tags
    assert "logic" in tags


@patch("fuzzforge.core.TestExecutor")
def test_run(mock_executor_class: MagicMock) -> None:
    """run delegates to executor and enriches results with risk scoring."""
    mock_executor = mock_executor_class.return_value
    mock_result = TestResult(
        test_case=TestCase(endpoint="GET /pets", path="/pets", tags=["injection"]),
        risk_score=0,
    )
    mock_executor.run_all.return_value = [mock_result]

    forge = FuzzForge(dry_run=True)
    forge.spec = APISpec(servers=["http://localhost:8000"], security_schemes={})
    results = forge.run([TestCase(endpoint="GET /pets", path="/pets", tags=["injection"])])

    assert len(results) == 1
    assert results[0].risk_score == 7
    assert "Injection vector detected" in results[0].findings


def test_scan_integration(tmp_path: Path) -> None:
    """High-level scan() works end-to-end with mocked LLM."""
    spec_content = """openapi: 3.0.0
info:
  title: Test API
  version: 1.0
paths:
  /test:
    get:
      summary: test endpoint
"""
    spec_file = tmp_path / "test.yaml"
    spec_file.write_text(spec_content)

    fake_json = json.dumps(
        [
            {
                "endpoint": "GET /test",
                "method": "GET",
                "path": "/test",
                "payload": {},
                "headers": {},
                "tags": ["injection"],
                "description": "Test injection",
                "risk_potential": "medium",
                "security": {},
            }
        ]
    )

    with patch("fuzzforge.llm.ollama.chat") as mock_chat:
        mock_chat.return_value = {"message": {"content": fake_json}}

        results = scan(
            spec_path=str(spec_file),
            model="llama3.2",
            limit=5,
            dry_run=True,
            output_dir=str(tmp_path),
        )

    assert len(results) >= 1
    assert any("injection" in r.test_case.tags for r in results)
    assert (tmp_path / "report.html").exists() or (tmp_path / "results.json").exists()


def test_mutators_apply() -> None:
    """Each mutator returns a correctly tagged and mutated copy."""
    base = TestCase(
        endpoint="POST /users",
        method="POST",
        path="/users",
        payload={"username": "alice"},
        tags=["base"],
    )

    injection = InjectionMutator().apply(base)
    assert injection is not None
    assert "injection" in injection.tags
    assert injection.risk_potential == "high"
    assert "<script>alert(1)</script>" in str(injection.payload)

    auth = AuthBypassMutator().apply(base)
    assert auth is not None
    assert "auth_bypass" in auth.tags
    assert auth.risk_potential == "critical"
    assert "INVALID_TOKEN" in str(auth.headers)

    logic = LogicMutator().apply(base)
    assert logic is not None
    assert "logic" in logic.tags
    assert logic.risk_potential == "high"
    assert "target_user_id" in logic.payload or "admin" in str(logic.payload)


def test_get_mutators_registry() -> None:
    """get_mutators returns correct instances for 'all' and explicit lists."""
    all_mut = get_mutators(["all"])
    assert len(all_mut) == 3
    assert any(isinstance(m, InjectionMutator) for m in all_mut)
    assert any(isinstance(m, AuthBypassMutator) for m in all_mut)
    assert any(isinstance(m, LogicMutator) for m in all_mut)

    explicit = get_mutators(["logic"])
    assert len(explicit) == 1
    assert isinstance(explicit[0], LogicMutator)

    # fallback to injection when unknown
    fallback = get_mutators(["unknown"])
    assert len(fallback) == 1
    assert isinstance(fallback[0], InjectionMutator)


def test_parser_petstore() -> None:
    """Parser extracts endpoints, schemas and security schemes from real example."""
    parser = OpenAPIParser()
    spec = parser.parse("examples/petstore.yaml")
    assert isinstance(spec, APISpec)
    assert len(spec.endpoints) > 0
    assert "pet" in str(spec.endpoints).lower() or any(
        "pet" in e.get("summary", "").lower() for e in spec.endpoints
    )
    assert isinstance(spec.security_schemes, dict)


def test_executor_dry_run_and_auth() -> None:
    """Dry-run produces simulated results; auth injection respects bypass tags."""
    schemes = {
        "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        "bearer": {"type": "http", "scheme": "bearer"},
    }

    executor = TestExecutor(
        dry_run=True,
        security_schemes=schemes,
        api_key="secret-key-123",
        bearer_token="eyJ...",
    )

    # Normal test gets credentials
    normal = TestCase(
        endpoint="GET /secure",
        method="GET",
        path="/secure",
        tags=["baseline"],
    )
    results = executor.run_all([normal])
    assert len(results) == 1
    res = results[0]
    assert res.test_case.headers.get("X-API-Key") == "secret-key-123"
    assert "Bearer eyJ" in str(res.test_case.headers.get("Authorization", ""))

    # Auth-bypass test skips credential injection
    bypass = TestCase(
        endpoint="GET /admin",
        method="GET",
        path="/admin",
        tags=["auth_bypass"],
    )
    results = executor.run_all([bypass])
    res = results[0]
    headers_lower = {k.lower(): v for k, v in res.test_case.headers.items()}
    assert "secret-key-123" not in str(headers_lower)
    assert "eyJ" not in str(headers_lower)
    assert res.risk_score == 8


def test_llm_fallback() -> None:
    """LLMClient falls back to deterministic tests when Ollama is unavailable."""
    client = LLMClient(model="llama3.2")
    spec = APISpec(
        title="Test",
        endpoints=[
            {"method": "POST", "path": "/users", "security": [{"apiKey": []}]},
            {"method": "GET", "path": "/pets"},
        ],
    )
    tests = client._fallback_tests(spec, 2)
    assert len(tests) == 2
    assert any("fallback" in t.tags for t in tests)
    assert any("injection" in t.tags for t in tests)


def test_reporter_artifacts(tmp_path: Path) -> None:
    """Reporter writes JSON (and other formats) without error."""
    reporter = Reporter()
    tc = TestCase(endpoint="GET /test", method="GET", path="/test", tags=["test"])
    result = TestResult(test_case=tc, risk_score=5, findings=["ok"])
    results = [result]

    reporter.generate_json(results, str(tmp_path))
    json_file = tmp_path / "results.json"
    assert json_file.exists()
    data = json.loads(json_file.read_text())
    assert len(data) == 1
    assert data[0]["risk_score"] == 5
