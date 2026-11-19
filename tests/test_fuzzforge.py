"""Test suite for Fuzz Forge.

Covers the full scanning pipeline (scan() and FuzzForge), mocked Ollama
responses, mutator output validation, Pydantic model integrity, error
handling, fallback paths, OAuth2/apiKey parsing, credential injection,
bypass-test skipping, and SARIF output.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from fuzzforge import scan
from fuzzforge.core import APISpec, FuzzForge, TestCase, TestResult
from fuzzforge.mutators import get_mutators, InjectionMutator, AuthBypassMutator, LogicMutator
from fuzzforge.parser import OpenAPIParser
from fuzzforge.reporter import Reporter


def test_testcase_model() -> None:
    """Validate TestCase model and curl generation."""
    tc = TestCase(
        endpoint="GET /test",
        method="GET",
        path="/test",
        tags=["test"],
        description="Test case",
    )
    assert tc.id.startswith("tc_")
    assert "curl -X GET" in tc.to_curl()
    assert tc.risk_potential == "medium"


def test_testresult_vulnerable() -> None:
    """Test is_vulnerable property."""
    tc = TestCase(endpoint="GET /test", path="/test")
    tr = TestResult(test_case=tc, risk_score=7)
    assert tr.is_vulnerable is True

    tr_low = TestResult(test_case=tc, risk_score=3)
    assert tr_low.is_vulnerable is False


def test_mutators() -> None:
    """Test each mutator produces expected output."""
    base = TestCase(
        endpoint="POST /users",
        method="POST",
        path="/users",
        payload={"name": "test"},
        tags=["base"],
        description="Base test",
    )

    injection = InjectionMutator().apply(base.model_copy(deep=True))
    assert injection is not None
    assert "injection" in injection.tags
    assert injection.risk_potential == "high"
    assert "injection vector" in injection.description

    auth = AuthBypassMutator().apply(base.model_copy(deep=True))
    assert auth is not None
    assert "auth_bypass" in auth.tags
    assert auth.risk_potential == "critical"

    logic = LogicMutator().apply(base.model_copy(deep=True))
    assert logic is not None
    assert "logic" in logic.tags
    assert logic.risk_potential == "high"


def test_get_mutators() -> None:
    """Test mutator registry and 'all' selector."""
    all_mutators = get_mutators(["all"])
    assert len(all_mutators) == 3
    names = {m.name for m in all_mutators}
    assert names == {"injection", "auth_bypass", "logic"}

    specific = get_mutators(["injection", "logic"])
    assert len(specific) == 2

    fallback = get_mutators(["unknown"])
    assert len(fallback) == 1
    assert fallback[0].name == "injection"


def test_apispec_validation() -> None:
    """Test APISpec validator."""
    with pytest.raises(ValueError):
        APISpec(endpoints=[])

    spec = APISpec(endpoints=[{"method": "GET", "path": "/test"}])
    assert spec.title == "Untitled API"


def test_parser(tmp_path: Path) -> None:
    """Test OpenAPIParser with a minimal spec."""
    spec_content = {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/pets": {
                "get": {
                    "summary": "List pets",
                    "responses": {"200": {"description": "OK"}},
                }
            }
        },
        "components": {
            "securitySchemes": {
                "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
            }
        },
    }
    spec_file = tmp_path / "test.json"
    spec_file.write_text(json.dumps(spec_content))

    parser = OpenAPIParser()
    spec = parser.parse(str(spec_file))
    assert spec.title == "Test API"
    assert len(spec.endpoints) == 1
    assert "apiKey" in spec.security_schemes


def test_fuzzforge_init_validation() -> None:
    """Test validation in FuzzForge constructor."""
    with pytest.raises(ValueError):
        FuzzForge(model="")

    forge = FuzzForge(model="llama3.2", dry_run=True)
    assert forge.model == "llama3.2"
    assert forge.dry_run is True


@pytest.mark.asyncio
async def test_fuzzforge_pipeline(mocker: Any, tmp_path: Path) -> None:
    """Full pipeline test with mocked LLM and SARIF validation."""
    # Mock LLM response
    mock_test = TestCase(
        endpoint="GET /pets",
        method="GET",
        path="/pets",
        payload={"test": "value"},
        tags=["injection"],
        description="LLM generated test",
        risk_potential="high",
    )
    mocker.patch(
        "fuzzforge.llm.LLMClient.generate_tests",
        return_value=[mock_test],
    )

    spec_content = {
        "openapi": "3.0.0",
        "info": {"title": "Petstore", "version": "1.0"},
        "paths": {"/pets": {"get": {"summary": "List pets"}}},
    }
    spec_file = tmp_path / "petstore.json"
    spec_file.write_text(json.dumps(spec_content))

    forge = FuzzForge(
        model="llama3.2",
        dry_run=True,
        output_dir=str(tmp_path),
        allowed_hosts=["localhost"],
    )
    forge.from_spec(str(spec_file))

    tests = forge.generate(limit=5)
    assert len(tests) >= 1

    results = forge.run(tests)
    assert len(results) >= 1
    assert any(r.risk_score > 0 for r in results)

    # Test reporter with all formats
    reporter = Reporter()
    reporter.generate_html(results, str(tmp_path))
    reporter.generate_json(results, str(tmp_path))
    reporter.generate_sarif(results, str(tmp_path))
    reporter.write_repro_files(results, str(tmp_path))

    assert (tmp_path / "report.html").exists()
    assert (tmp_path / "results.json").exists()
    assert (tmp_path / "results.sarif.json").exists()
    assert any(p.name.startswith("repro_") for p in tmp_path.iterdir())

    # Validate SARIF structure
    with open(tmp_path / "results.sarif.json") as f:
        sarif = json.load(f)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert "tool" in run
    assert len(run["results"]) >= 1


def test_scan_function(mocker: Any, tmp_path: Path) -> None:
    """Test high-level scan() convenience function."""
    spec_content = {
        "openapi": "3.0.0",
        "info": {"title": "Test", "version": "1.0"},
        "paths": {"/test": {"get": {}}},
    }
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(spec_content))

    mocker.patch(
        "fuzzforge.llm.LLMClient.generate_tests",
        return_value=[],
    )

    results = scan(
        spec_path=str(spec_file),
        model="llama3.2",
        limit=3,
        dry_run=True,
        output_dir=str(tmp_path),
    )
    assert isinstance(results, list)


def test_sarif_only_includes_high_risk() -> None:
    """SARIF must omit low-risk results."""
    low = TestResult(
        test_case=TestCase(endpoint="GET /low", path="/low", tags=["low"]),
        risk_score=4,
    )
    high = TestResult(
        test_case=TestCase(endpoint="GET /high", path="/high", tags=["injection"]),
        risk_score=8,
        findings=["Injection found"],
    )

    reporter = Reporter()
    with pytest.raises(OSError):
        # Use a temp dir via context to avoid real FS in this isolated test
        pass
    # Instead test the builder directly
    sarif = reporter._build_sarif([low, high])
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "fuzzforge/injection"
    assert sarif["runs"][0]["results"][0]["level"] == "error"


def test_executor_auth_skip_bypass(mocker: Any) -> None:
    """Auth bypass tests must not receive credentials."""
    from fuzzforge.executor import TestExecutor

    executor = TestExecutor(
        dry_run=True,
        security_schemes={"apiKey": {"type": "apiKey", "name": "X-API-Key"}},
        api_key="secret",
        bearer_token="token123",
    )

    bypass_test = TestCase(
        endpoint="GET /admin",
        path="/admin",
        tags=["auth_bypass"],
        headers={},
    )
    result = executor.run_all([bypass_test])[0]
    # Should not have added Authorization or X-API-Key
    assert "Authorization" not in result.test_case.headers
    assert "X-API-Key" not in result.test_case.headers
