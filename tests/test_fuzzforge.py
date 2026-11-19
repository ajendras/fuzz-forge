import json
from pathlib import Path
from typing import Any

import pytest

from fuzzforge import scan
from fuzzforge.core import APISpec, FuzzForge, TestCase, TestResult
from fuzzforge.executor import TestExecutor
from fuzzforge.reporter import Reporter


def test_fuzzforge_pipeline(monkeypatch: Any, tmp_path: Path) -> None:
    """Test the full pipeline with mocked LLM and parser (no Ollama required)."""

    def mock_parse(path: str) -> APISpec:
        return APISpec(
            title="Petstore",
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
            security_schemes={},
            servers=["http://localhost:8000"],
            raw_spec={},
        )

    monkeypatch.setattr("fuzzforge.parser.OpenAPIParser.parse", mock_parse)

    def mock_generate_tests(spec: APISpec, count: int):
        return [
            TestCase(
                id="tc_1",
                endpoint="GET /pets",
                method="GET",
                path="/pets",
                payload={"test": "value"},
                tags=["injection"],
                description="LLM generated injection test",
                risk_potential="high",
                security={},
            )
        ]

    monkeypatch.setattr("fuzzforge.llm.LLMClient.generate_tests", mock_generate_tests)

    results = scan(
        spec_path="examples/petstore.yaml",
        model="llama3.2",
        limit=5,
        dry_run=True,
        output_dir=str(tmp_path),
    )

    assert len(results) >= 1
    assert (tmp_path / "report.html").exists()
    assert (tmp_path / "results.json").exists()
    assert (tmp_path / "results.sarif.json").exists()
    assert any(p.name.startswith("repro_") for p in tmp_path.iterdir())

    # Validate SARIF structure
    with open(tmp_path / "results.sarif.json", encoding="utf-8") as f:
        sarif = json.load(f)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert "tool" in run
    assert len(run["results"]) >= 1


def test_scan_function(monkeypatch: Any, tmp_path: Path) -> None:
    """Test the high-level scan() convenience function."""

    def mock_from_spec(self: FuzzForge, spec_path: str) -> None:
        self.spec = APISpec(
            title="Test API",
            endpoints=[{"method": "GET", "path": "/test"}],
            schemas={},
            security_schemes={},
            servers=["http://localhost:8000"],
        )

    monkeypatch.setattr(FuzzForge, "from_spec", mock_from_spec)

    def mock_generate(self: FuzzForge, limit: int) -> list[TestCase]:
        return [
            TestCase(
                endpoint="GET /test",
                method="GET",
                path="/test",
                tags=["injection"],
                risk_potential="high",
            )
        ]

    monkeypatch.setattr(FuzzForge, "generate", mock_generate)

    def mock_run(self: FuzzForge, tests: list[TestCase]) -> list[TestResult]:
        return [
            TestResult(
                test_case=tests[0],
                risk_score=8,
                findings=["Injection vector detected"],
                repro_curl="curl -X GET 'http://localhost:8000/test'",
            )
        ]

    monkeypatch.setattr(FuzzForge, "run", mock_run)

    results = scan(
        spec_path="examples/petstore.yaml",
        model="llama3.2",
        limit=3,
        dry_run=True,
        output_dir=str(tmp_path),
    )

    assert len(results) == 1
    assert results[0].risk_score == 8
    assert results[0].is_vulnerable is True


def test_executor_auth_skip_bypass(monkeypatch: Any) -> None:
    """Test that auth_bypass tagged tests skip credential injection."""

    executor = TestExecutor(
        dry_run=True,
        api_key="secret123",
        bearer_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo",
        security_schemes={
            "petstore_auth": {"type": "oauth2"},
            "api_key": {"type": "apiKey", "name": "X-API-Key", "in": "header"},
        },
    )

    bypass_test = TestCase(
        endpoint="GET /admin",
        method="GET",
        path="/admin",
        tags=["auth_bypass"],
        headers={"Content-Type": "application/json"},
        query_params={},
        security={"petstore_auth": []},
    )

    # _apply_auth should skip because of the tag
    executor._apply_auth(bypass_test)  # pylint: disable=protected-access

    headers = {k.lower(): v for k, v in bypass_test.headers.items()}
    assert "authorization" not in headers
    assert "x-api-key" not in headers
    # Other headers should be untouched
    assert headers["content-type"] == "application/json"


def test_sarif_only_includes_high_risk(tmp_path: Path) -> None:
    """Test that SARIF output only includes high-risk (vulnerable) findings.

    The previous version of this test incorrectly expected an OSError
    (e.g. for a non-writable path). The reporter now safely creates
    directories, so we test the filtering behaviour instead.
    """
    reporter = Reporter()

    low = TestResult(
        test_case=TestCase(
            endpoint="GET /low",
            method="GET",
            path="/low",
            tags=["info"],
            description="Low risk test",
        ),
        risk_score=4,
        findings=["Info only"],
    )

    high = TestResult(
        test_case=TestCase(
            endpoint="POST /users",
            method="POST",
            path="/users",
            tags=["injection", "sqli"],
            description="SQL injection test",
        ),
        risk_score=8,
        findings=["SQL injection possible"],
    )

    results = [low, high]
    reporter.generate_sarif(results, str(tmp_path))

    sarif_path = tmp_path / "results.sarif.json"
    assert sarif_path.exists()

    with open(sarif_path, encoding="utf-8") as f:
        sarif = json.load(f)

    run = sarif["runs"][0]
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "fuzzforge.injection"
    assert "SQL injection possible" in run["results"][0]["message"]["text"]
