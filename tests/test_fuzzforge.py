import asyncio
import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from fuzzforge.core import FuzzForge, TestCase, TestResult
from fuzzforge.executor import TestExecutor
from fuzzforge.llm import LLMClient
from fuzzforge.mutators import get_mutators


@pytest.fixture
def mock_ollama():
    with patch("fuzzforge.llm.ollama") as mock_ollama:
        mock_ollama.chat.return_value = {
            "message": {
                "content": json.dumps(
                    [
                        {
                            "endpoint": "GET /pets",
                            "method": "GET",
                            "path": "/pets",
                            "payload": {},
                            "headers": {},
                            "tags": ["test"],
                            "description": "Test endpoint",
                            "risk_potential": "medium",
                            "security": {},
                        }
                    ]
                )
            }
        }
        yield mock_ollama


@pytest.fixture
def sample_spec(tmp_path):
    spec = tmp_path / "petstore.yaml"
    spec.write_text(
        """
openapi: 3.0.0
info:
  title: Petstore
  version: 1.0.0
paths:
  /pets:
    get:
      summary: List pets
      responses:
        '200':
          description: OK
"""
    )
    return str(spec)


def test_fuzzforge_init():
    forge = FuzzForge(model="llama3.2", dry_run=True, auto_detect_rate_limits=True)
    assert forge.model == "llama3.2"
    assert forge.dry_run is True
    assert forge.auto_detect_rate_limits is True
    assert forge.rate_limit_rps == 5.0


def test_scan_function(sample_spec, mock_ollama):
    results = FuzzForge.scan(spec_path=sample_spec, limit=1, dry_run=True)
    assert len(results) >= 1
    assert isinstance(results[0], TestResult)


@pytest.mark.asyncio
async def test_executor_dry_run():
    executor = TestExecutor(dry_run=True, auto_detect_rate_limits=True)
    test = TestCase(
        endpoint="GET /test",
        method="GET",
        path="/test",
        tags=["injection"],
    )
    results = await executor._run_all_async([test])
    assert len(results) == 1
    assert results[0].risk_score == 7
    assert "dry-run" in results[0].response_body


@pytest.mark.asyncio
async def test_executor_rate_limit_backoff():
    executor = TestExecutor(
        dry_run=False,
        rate_limit_rps=100.0,
        auto_detect_rate_limits=True,
    )
    test = TestCase(endpoint="GET /test", method="GET", path="/test")

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.text = "ok"
    mock_response.headers = httpx.Headers({"Retry-After": "1.5"})

    mock_client = AsyncMock()
    mock_client.request.return_value = mock_response

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            result = await executor._execute_single(test)

    assert result.status_code == 200
    # At least one call with backoff from Retry-After
    mock_sleep.assert_called()
    calls = [call.args[0] for call in mock_sleep.call_args_list]
    assert any(d > 1.0 for d in calls)


@pytest.mark.asyncio
async def test_executor_rate_limit_headers_xratelimit():
    executor = TestExecutor(
        dry_run=False,
        rate_limit_rps=100.0,
        auto_detect_rate_limits=True,
    )
    test = TestCase(endpoint="GET /test", method="GET", path="/test")

    now = time.time()
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.text = "ok"
    mock_response.headers = httpx.Headers(
        {
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": str(now + 3),
        }
    )

    mock_client = AsyncMock()
    mock_client.request.return_value = mock_response

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await executor._execute_single(test)

    # Should have triggered backoff near the reset time
    mock_sleep.assert_called()
    calls = [call.args[0] for call in mock_sleep.call_args_list if call.args]
    assert any(2.0 < d < 5.0 for d in calls)


@pytest.mark.asyncio
async def test_executor_no_auto_detect():
    executor = TestExecutor(
        dry_run=False,
        rate_limit_rps=100.0,
        auto_detect_rate_limits=False,
    )
    test = TestCase(endpoint="GET /test", method="GET", path="/test")

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.text = "ok"
    mock_response.headers = httpx.Headers({"Retry-After": "10"})

    mock_client = AsyncMock()
    mock_client.request.return_value = mock_response

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await executor._execute_single(test)

    # Only the tiny RPS delay should be used (no 10s backoff)
    calls = [call.args[0] for call in mock_sleep.call_args_list if call.args]
    assert all(d < 1.0 for d in calls)


def test_update_rate_limits_from_headers():
    executor = TestExecutor(auto_detect_rate_limits=True)
    headers = httpx.Headers(
        {
            "Retry-After": "5",
            "RateLimit-Remaining": "2",
            "RateLimit-Reset": "1726000000",
        }
    )
    executor._update_rate_limits_from_headers(headers)
    assert executor._retry_after == 5.0
    assert executor._rate_limit_remaining == 2
    assert executor._rate_limit_reset is not None


def test_mutators():
    mutators = get_mutators(["all"])
    assert len(mutators) == 4
    assert any(m.name == "injection" for m in mutators)
    assert any(m.name == "graphql_mutation" for m in mutators)


def test_fallback_tests():
    forge = FuzzForge(dry_run=True)
    forge.spec = MagicMock()
    forge.spec.spec_type = "graphql"
    forge.spec.endpoints = []
    tests = forge._generate_fallback_tests(3)
    assert len(tests) == 3
    assert all("graphql" in t.tags for t in tests)


@pytest.mark.asyncio
async def test_executor_allowed_host():
    executor = TestExecutor(
        dry_run=False,
        allowed_hosts=["example.com"],
        auto_detect_rate_limits=True,
    )
    test = TestCase(endpoint="GET /test", method="GET", path="https://evil.com/test")
    result = await executor._execute_single(test)
    assert "Host not in allowlist" in result.error
