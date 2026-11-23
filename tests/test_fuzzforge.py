"""Tests for Fuzz Forge core functionality.

Covers scanning pipeline, mocked LLM responses, mutator validation,
Pydantic models, error handling, fallback paths, GraphQL support,
OAuth2/apiKey handling, and report generation.
"""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from fuzzforge import scan, FuzzForge
from fuzzforge.core import APISpec, TestCase, TestResult
from fuzzforge.llm import LLMClient
from fuzzforge.mutators import get_mutators, InjectionMutator, AuthBypassMutator
from fuzzforge.executor import TestExecutor
from fuzzforge.reporter import Reporter


def test_llm_fallback_graphql():
    """Test that GraphQL fallback tests are generated correctly (verifies f-string fix)."""
    spec = APISpec(
        title="Test GraphQL API",
        spec_type="graphql",
        endpoints=[{"operation": "mutation", "name": "testMutation", "summary": "Test mut"}],
        schemas={"TestInput": {"type": "object"}},
        servers=["http://localhost:4000"],
    )
    client = LLMClient(model="llama3.2")
    tests = client._fallback_tests(spec, count=3)  # type: ignore[attr-defined]

    assert len(tests) == 3
    for i, test in enumerate(tests, 1):
        assert test.endpoint == f"POST /graphql [mutation {i}]"
        assert test.method == "POST"
        assert test.path == "/graphql"
        assert "graphql" in test.tags
        assert "mutation" in test.tags
        assert "xss" in test.tags
        assert "fallback" in test.tags
        assert test.risk_potential == "high"
        query = test.payload.get("query", "")
        assert f"testMutation{i}" in query
        assert "<script>alert(1)</script>" in query
        assert "mutation {" in query
        assert "input:" in query


def test_get_mutators():
    """Test mutator registry and GraphQL mutator inclusion."""
    muts = get_mutators(["all"])
    assert len(muts) == 4
    names = {m.name for m in muts}
    assert names == {"injection", "auth_bypass", "logic", "graphql_mutation"}

    muts = get_mutators(["injection", "graphql_mutation"])
    assert len(muts) == 2
    assert muts[0].name == "injection"


def test_injection_mutator():
    """Test InjectionMutator behavior."""
    base = TestCase(
        endpoint="POST /api/test",
        method="POST",
        path="/api/test",
        payload={"data": "normal", "id": 123},
        tags=["base"],
        description="Base test",
    )
    mut = InjectionMutator()
    mutated = mut.apply(base)
    assert mutated is not None
    assert "injection" in mutated.tags
    assert "xss" in mutated.tags
    assert mutated.risk_potential == "high"
    assert "<script>alert(1)</script>" in str(mutated.payload)


def test_auth_bypass_mutator():
    """Test AuthBypassMutator with credential skipping."""
    base = TestCase(
        endpoint="GET /admin",
        method="GET",
        path="/admin",
        headers={"Authorization": "Bearer valid"},
        tags=["auth"],
        security={"oauth": {"type": "oauth2"}},
    )
    mut = AuthBypassMutator()
    mutated = mut.apply(base)
    assert mutated is not None
    assert "auth_bypass" in mutated.tags
    assert "INVALID_TOKEN" in mutated.headers.get("Authorization", "")
    assert mutated.risk_potential == "critical"


def test_fuzzforge_fallback_openapi():
    """Test fallback when LLM is unavailable for OpenAPI."""
    spec = APISpec(
        title="Petstore",
        endpoints=[{"method": "GET", "path": "/pets"}],
        spec_type="openapi",
    )
    forge = FuzzForge(model="llama3.2", dry_run=True)
    forge.spec = spec
    tests = forge._generate_fallback_tests(3)  # type: ignore[attr-defined]
    assert len(tests) == 3
    assert all(t.tags == ["fallback"] for t in tests)


@patch("fuzzforge.llm.ollama.chat")
def test_generate_with_mocked_llm(mock_chat):
    """Test full generation path with mocked Ollama response."""
    mock_chat.return_value = {
        "message": {
            "content": json.dumps(
                [
                    {
                        "endpoint": "GET /pets",
                        "method": "GET",
                        "path": "/pets",
                        "payload": {},
                        "headers": {},
                        "tags": ["injection"],
                        "description": "Test injection",
                        "risk_potential": "medium",
                        "security": {},
                    }
                ]
            )
        }
    }
    forge = FuzzForge(model="llama3.2", dry_run=True, mutators=["injection"])
    forge.from_spec("examples/petstore.yaml")
    tests = forge.generate(limit=5)
    assert len(tests) >= 1
    assert any("injection" in t.tags for t in tests)


@patch("fuzzforge.core.LLMClient.generate_tests")
def test_scan_function(mock_generate):
    """Test high-level scan() with fallback (mocks LLM)."""
    mock_generate.return_value = []
    results = scan(
        spec_path="examples/petstore.yaml",
        model="llama3.2",
        limit=5,
        dry_run=True,
        output_dir=None,  # prevent side effects in test
    )
    assert len(results) > 0
    assert any(isinstance(r, TestResult) for r in results)
    assert any(r.risk_score > 0 for r in results)


def test_executor_dry_run_auth():
    """Test executor dry-run with auth injection (skips bypass)."""
    executor = TestExecutor(
        dry_run=True,
        api_key="test-key",
        bearer_token="test-token",
        security_schemes={"apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}},
    )
    test = TestCase(
        endpoint="GET /secure",
        method="GET",
        path="/secure",
        tags=["auth_bypass"],  # should skip injection
    )
    result = executor.run_all([test])[0]
    assert not any("X-API-Key" in str(h) for h in [result.test_case.headers])
    assert result.risk_score > 5


def test_reporter_sarif():
    """Test SARIF output generation."""
    results = [
        TestResult(
            test_case=TestCase(endpoint="GET /test", path="/test"),
            risk_score=7,
            findings=["XSS possible"],
        )
    ]
    reporter = Reporter()
    sarif = reporter.generate_sarif(results, "/tmp")  # returns dict in implementation
    assert isinstance(sarif, dict)
    assert "runs" in sarif


@pytest.mark.asyncio
async def test_executor_rate_limit():
    """Basic async executor test."""
    executor = TestExecutor(dry_run=True, rate_limit_rps=10.0)
    tests = [TestCase(endpoint="GET /1", path="/1"), TestCase(endpoint="GET /2", path="/2")]
    results = await executor._run_all_async(tests)  # type: ignore[attr-defined]
    assert len(results) == 2


def test_pydantic_models():
    """Validate model constraints."""
    with pytest.raises(ValueError):
        TestCase(method="INVALID")
    tc = TestCase(endpoint="GET /ok")
    assert tc.id.startswith("tc_")
    assert not tc.is_vulnerable  # default risk 0


# Additional coverage for parser, GraphQL prompt, HTML report etc.
# is included in the full suite (mocks for Ollama, prance, graphql-core).
