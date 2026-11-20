"""Tests for Fuzz Forge.

Covers the full scanning pipeline (scan() and FuzzForge), models, mutators,
LLM fallback paths, auth credential injection, bypass skipping, and
SARIF/reporting integration. Uses mocks to keep tests fast and isolated.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fuzzforge import scan, __version__
from fuzzforge.core import APISpec, TestCase, TestResult, FuzzForge
from fuzzforge.executor import TestExecutor
from fuzzforge.mutators import get_mutators, InjectionMutator, AuthBypassMutator, LogicMutator


def test_version():
    assert __version__ == "0.1.0"


def test_pydantic_models():
    spec = APISpec(
        title="Test Spec",
        version="1.0.0",
        endpoints=[{"method": "GET", "path": "/health", "summary": "Health check"}],
        schemas={"Pet": {}},
        security_schemes={},
        servers=["http://api.example.com"],
    )
    assert spec.title == "Test Spec"
    assert len(spec.endpoints) == 1

    tc = TestCase(
        endpoint="GET /health",
        method="GET",
        path="/health",
        tags=["test"],
        description="test case",
    )
    assert tc.endpoint == "GET /health"
    curl = tc.to_curl()
    assert curl.startswith("curl -X GET")

    res = TestResult(test_case=tc, risk_score=6, findings=["test finding"])
    assert res.is_vulnerable is True
    assert res.risk_score == 6


def test_mutators():
    base_test = TestCase(
        endpoint="POST /users",
        method="POST",
        path="/users",
        payload={"name": "testuser", "email": "test@example.com"},
        description="base test",
    )

    injection = InjectionMutator()
    mutated = injection.apply(base_test)
    assert mutated is not None
    assert "injection" in mutated.tags
    assert mutated.risk_potential == "high"
    assert "injection vector" in mutated.description.lower()

    auth = AuthBypassMutator()
    mutated = auth.apply(base_test.model_copy(deep=True))
    assert "auth_bypass" in mutated.tags
    assert mutated.risk_potential == "critical"

    logic = LogicMutator()
    mutated = logic.apply(base_test.model_copy(deep=True))
    assert "logic" in mutated.tags
    assert mutated.risk_potential == "high"
    assert any(k in str(mutated.payload).lower() for k in ("id", "user", "admin"))


def test_get_mutators():
    assert len(get_mutators(["all"])) == 3
    assert len(get_mutators([])) == 3
    assert len(get_mutators(["injection", "logic"])) == 2
    # unknown falls back to at least InjectionMutator
    assert len(get_mutators(["unknown"])) == 1
    assert get_mutators(["unknown"])[0].name == "injection"


def test_fuzzforge_initialization():
    forge = FuzzForge(
        model="llama3.2",
        mutators=["injection"],
        dry_run=True,
        allowed_hosts=["localhost"],
        api_key="secret",
        bearer_token="token123",
    )
    assert forge.model == "llama3.2"
    assert forge.mutators == ["injection"]
    assert forge.dry_run is True
    assert "localhost" in forge.allowed_hosts
    assert forge.api_key == "secret"
    assert forge.bearer_token == "token123"

    with pytest.raises(ValueError, match="model must be a non-empty string"):
        FuzzForge(model="")


def test_fuzzforge_pipeline(mocker, tmp_path):
    """Full end-to-end pipeline test using mocks (no real Ollama or HTTP)."""
    spec_path = tmp_path / "petstore.yaml"
    spec_path.write_text(
        "openapi: 3.0.0\ninfo:\n  title: Petstore\n  version: 1.0.0\npaths:\n  /pets:\n    get:\n      summary: List pets",
        encoding="utf-8",
    )

    mocker.patch("pathlib.Path.exists", return_value=True)

    mock_spec = APISpec(
        title="Test API",
        version="1.0.0",
        endpoints=[
            {
                "method": "GET",
                "path": "/pets",
                "summary": "List pets",
                "example": {},
                "security": [],
            }
        ],
        schemas={},
        security_schemes={
            "petstore_auth": {
                "type": "oauth2",
            }
        },
        servers=["http://localhost:8000"],
    )

    mock_parser = mocker.Mock()
    mock_parser.parse.return_value = mock_spec
    mocker.patch("fuzzforge.core.OpenAPIParser", return_value=mock_parser)

    base_test = TestCase(
        endpoint="GET /pets",
        method="GET",
        path="/pets",
        payload={"test": "data"},
        tags=["injection"],
        description="LLM generated test for injection",
        risk_potential="medium",
        security={},
    )

    mock_llm_client = mocker.Mock()
    mock_llm_client.generate_tests.return_value = [base_test]
    mocker.patch("fuzzforge.core.LLMClient", return_value=mock_llm_client)

    mock_result = TestResult(
        test_case=base_test,
        executed=False,
        status_code=0,
        risk_score=7,
        findings=["Potential injection vector (dry-run)"],
        repro_curl="curl -X GET 'http://localhost:8000/pets'",
    )

    mock_executor = mocker.Mock()
    mock_executor.run_all.return_value = [mock_result]
    mocker.patch("fuzzforge.core.TestExecutor", return_value=mock_executor)

    mock_reporter = mocker.Mock()
    mocker.patch("fuzzforge.reporter.Reporter", return_value=mock_reporter)

    results = scan(
        spec_path=str(spec_path),
        model="llama3.2",
        limit=5,
        dry_run=True,
        output_dir=str(tmp_path / "fuzz-reports"),
        api_key="test-api-key",
        bearer_token="test-bearer-token",
    )

    assert len(results) == 1
    assert results[0].risk_score == 7
    assert results[0].is_vulnerable is True

    mock_parser.parse.assert_called_once_with(str(spec_path))
    mock_llm_client.generate_tests.assert_called_once()
    mock_executor.run_all.assert_called_once()
    assert mock_reporter.generate_html.called
    assert mock_reporter.generate_json.called
    assert mock_reporter.generate_sarif.called
    assert mock_reporter.write_repro_files.called


def test_executor_auth_injection():
    """Test credential injection for OAuth2/apiKey and skipping for auth_bypass tests."""
    security_schemes = {
        "apiKey": {"type": "apiKey", "name": "X-API-Key", "in": "header"},
        "bearer": {"type": "http", "scheme": "bearer"},
    }

    executor = TestExecutor(
        dry_run=True,
        security_schemes=security_schemes,
        api_key="test-key-123",
        bearer_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
    )

    normal_test = TestCase(
        method="GET",
        path="/secure",
        headers={},
        query_params={},
        tags=["injection"],
    )
    executor._apply_auth(normal_test)  # pylint: disable=protected-access
    assert normal_test.headers.get("X-API-Key") == "test-key-123"
    assert normal_test.headers.get("Authorization") == "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"

    bypass_test = TestCase(
        method="GET",
        path="/admin",
        headers={},
        query_params={},
        tags=["auth_bypass"],
    )
    executor._apply_auth(bypass_test)  # pylint: disable=protected-access
    assert "X-API-Key" not in bypass_test.headers
    assert "Authorization" not in bypass_test.headers


def test_fallback_tests(mocker):
    """Test fallback test generation when LLM is unavailable."""
    mock_spec = APISpec(
        title="Test",
        version="1.0",
        endpoints=[{"method": "GET", "path": "/items", "security": []}],
        schemas={},
        security_schemes={},
        servers=["http://test"],
    )

    forge = FuzzForge(model="llama3.2", dry_run=True)
    forge.spec = mock_spec

    mocker.patch.object(forge.llm_client, "generate_tests", return_value=[])

    tests = forge.generate(limit=3)
    assert len(tests) == 1
    assert tests[0].tags == ["fallback"]
    assert "LLM unavailable" in tests[0].description
