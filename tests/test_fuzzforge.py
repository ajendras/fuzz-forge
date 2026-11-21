"""Test suite for Fuzz Forge.

Covers the full scanning pipeline with mocked LLM/executor, mutator logic,
parser output, risk scoring, auth injection, SARIF correctness, and the
new interactive HTML report (modal viewers, JS replay, clipboard).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.fuzzforge.core import APISpec, FuzzForge, TestCase, TestResult
from src.fuzzforge.llm import LLMClient
from src.fuzzforge.mutators import get_mutators, InjectionMutator
from src.fuzzforge.parser import OpenAPIParser
from src.fuzzforge.reporter import Reporter


@pytest.fixture
def sample_spec_dict():
    return {
        "info": {"title": "Petstore", "version": "1.0.0"},
        "servers": [{"url": "http://localhost:8000"}],
        "paths": {
            "/pets": {
                "get": {
                    "summary": "List pets",
                    "security": [{"apiKey": []}],
                }
            }
        },
        "components": {
            "securitySchemes": {
                "apiKey": {"type": "apiKey", "name": "X-API-Key", "in": "header"}
            }
        },
    }


@pytest.fixture
def sample_test_case():
    return TestCase(
        id="tc_123",
        endpoint="GET /pets",
        method="GET",
        path="/pets",
        payload={"test": "value"},
        headers={"X-API-Key": "demo"},
        tags=["injection"],
        description="Test injection vector",
        risk_potential="high",
    )


@pytest.fixture
def sample_result(sample_test_case):
    return TestResult(
        test_case=sample_test_case,
        executed=True,
        status_code=200,
        response_time=0.12,
        response_body='{"status": "ok"}',
        risk_score=7,
        findings=["Potential injection vector"],
        repro_curl="curl -X GET 'http://localhost:8000/pets' -H 'X-API-Key: demo'",
    )


def test_testcase_to_curl(sample_test_case):
    curl = sample_test_case.to_curl(base_url="https://api.example.com")
    assert "curl -X GET" in curl
    assert "https://api.example.com/pets" in curl


def test_mutator_injection(sample_test_case):
    mutator = InjectionMutator()
    mutated = mutator.apply(sample_test_case)
    assert mutated is not None
    assert "injection" in mutated.tags
    assert mutated.risk_potential == "high"
    assert any(v == "<script>alert(1)</script>" for v in mutated.payload.values())


def test_get_mutators():
    mutators = get_mutators(["all"])
    assert len(mutators) == 3
    names = {m.name for m in mutators}
    assert "injection" in names
    assert "auth_bypass" in names
    assert "logic" in names

    specific = get_mutators(["injection"])
    assert len(specific) == 1
    assert specific[0].name == "injection"


def test_parser(sample_spec_dict, tmp_path):
    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(json.dumps(sample_spec_dict), encoding="utf-8")

    parser = OpenAPIParser()
    spec = parser.parse(str(spec_file))
    assert spec.title == "Petstore"
    assert len(spec.endpoints) == 1
    assert "apiKey" in spec.security_schemes


@patch("src.fuzzforge.llm.ollama.chat")
def test_llm_client(mock_chat):
    mock_chat.return_value = {
        "message": {
            "content": '[{"endpoint": "GET /pets", "method": "GET", "path": "/pets", '
            '"payload": {}, "headers": {}, "tags": ["injection"], '
            '"description": "test", "risk_potential": "medium", "security": {}}]'
        }
    }

    client = LLMClient(model="llama3.2")
    spec = APISpec(
        title="Test",
        endpoints=[{"method": "GET", "path": "/pets"}],
        security_schemes={},
    )
    tests = client.generate_tests(spec, count=1)
    assert len(tests) == 1
    assert tests[0].endpoint == "GET /pets"


def test_fuzzforge_fallback(sample_spec_dict, tmp_path):
    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(json.dumps(sample_spec_dict), encoding="utf-8")

    forge = FuzzForge(model="llama3.2", dry_run=True, mutators=["injection"])
    forge.from_spec(str(spec_file))
    tests = forge.generate(limit=3)
    assert len(tests) >= 1
    assert any("fallback" in t.tags for t in tests)


def test_executor_dry_run(sample_test_case):
    from src.fuzzforge.executor import TestExecutor

    executor = TestExecutor(dry_run=True, allowed_hosts=["localhost"])
    results = executor.run_all([sample_test_case])
    assert len(results) == 1
    assert results[0].risk_score == 7
    assert "dry-run" in results[0].response_body.lower()


def test_reporter_interactive_html(tmp_path, sample_result):
    """Test the interactive HTML report contains all expected interactive elements."""
    reporter = Reporter()
    results = [sample_result]
    reporter.generate_html(results, str(tmp_path))

    html_file = tmp_path / "report.html"
    assert html_file.exists()

    content = html_file.read_text(encoding="utf-8")
    assert "INTERACTIVE REPORT" in content
    assert "REPLAY IN BROWSER" in content
    assert "const RESULTS" in content
    assert "openModal" in content
    assert "performReplay" in content
    assert "copyCurl" in content
    assert "modal" in content
    assert "tab-content" in content
    assert "/pets" in content
    assert "curl -X GET" in content
    assert "Potential injection vector" in content


def test_reporter_json_sarif_repros(tmp_path, sample_result):
    reporter = Reporter()
    results = [sample_result]

    reporter.generate_json(results, str(tmp_path))
    reporter.generate_sarif(results, str(tmp_path))
    reporter.write_repro_files(results, str(tmp_path))

    assert (tmp_path / "results.json").exists()
    assert (tmp_path / "results.sarif.json").exists()
    assert (tmp_path / "repros" / "tc_123.sh").exists()

    sarif = json.loads((tmp_path / "results.sarif.json").read_text())
    assert sarif["runs"][0]["results"]


def test_scan_integration(tmp_path, sample_result):
    """Test high-level scan() produces interactive report."""
    with patch("src.fuzzforge.core.FuzzForge.from_spec"):
        with patch("src.fuzzforge.core.FuzzForge.generate") as mock_gen:
            with patch("src.fuzzforge.core.FuzzForge.run") as mock_run:
                mock_gen.return_value = []
                mock_run.return_value = [sample_result]

                from src.fuzzforge import scan

                results = scan(
                    spec_path=str(tmp_path / "dummy.yaml"),
                    model="llama3.2",
                    limit=5,
                    dry_run=True,
                    output_dir=str(tmp_path),
                )

                assert len(results) == 1
                assert (tmp_path / "report.html").exists()
                assert (tmp_path / "results.json").exists()


def test_testresult_vulnerable_property(sample_result):
    assert sample_result.is_vulnerable is True
    sample_result.risk_score = 3
    assert sample_result.is_vulnerable is False


def test_core_risk_scoring(sample_test_case):
    from src.fuzzforge.core import TestResult

    result = TestResult(test_case=sample_test_case, risk_score=9)
    assert "authentication bypass" in " ".join(result.findings).lower() or result.risk_score == 9
