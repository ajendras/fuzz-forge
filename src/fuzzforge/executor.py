"""Test execution engine for Fuzz Forge.

Handles dry-run simulation, async HTTP requests via httpx, rate limiting,
host allowlisting, and produces TestResult objects with risk heuristics.
"""

from __future__ import annotations

import asyncio
import time
from typing import List, Optional
from urllib.parse import urlparse

import httpx

from .core import TestCase, TestResult


class TestExecutor:
    """Executes test cases against the target API with safety controls."""

    def __init__(
        self,
        dry_run: bool = True,
        rate_limit_rps: float = 5.0,
        allowed_hosts: Optional[List[str]] = None,
        base_url: Optional[str] = None,
    ) -> None:
        """Initialize executor with safety parameters.

        Args:
            dry_run: If True, no real HTTP requests are performed.
            rate_limit_rps: Maximum requests per second.
            allowed_hosts: List of permitted hostnames.
            base_url: Default base URL for relative paths.

        Raises:
            ValueError: For invalid rate limit values.
        """
        if rate_limit_rps < 0.1:
            raise ValueError("rate_limit_rps must be at least 0.1")

        self.dry_run = dry_run
        self.rate_limit_rps = float(rate_limit_rps)
        self.allowed_hosts = [h.lower() for h in (allowed_hosts or ["localhost", "127.0.0.1", "example.com"])]
        self.base_url = base_url or "http://localhost:8000"
        self._semaphore = asyncio.Semaphore(5)  # max concurrent requests
        self._lock = asyncio.Lock()
        self._last_request_time: float = 0.0

    def run_all(self, tests: List[TestCase]) -> List[TestResult]:
        """Synchronous entrypoint that runs all tests (uses asyncio under the hood)."""
        if not tests:
            return []

        return asyncio.run(self._run_all_async(tests))

    async def _run_all_async(self, tests: List[TestCase]) -> List[TestResult]:
        """Async implementation of test execution with controlled concurrency."""
        tasks = [self._execute_single(test) for test in tests]
        results: List[TestResult] = await asyncio.gather(*tasks, return_exceptions=False)
        return results

    async def _execute_single(self, test: TestCase) -> TestResult:
        """Execute a single test case, respecting all safety rules."""
        result = TestResult(
            test_case=test,
            repro_curl=test.to_curl(self.base_url),
        )

        # Determine full URL
        if test.path.startswith(("http://", "https://")):
            full_url = test.path
        else:
            base = self.base_url.rstrip("/")
            full_url = f"{base}{test.path if test.path.startswith('/') else '/' + test.path}"

        # Host allowlist check
        if not self._is_allowed_host(full_url):
            result.error = f"Host not in allowlist: {urlparse(full_url).hostname}"
            result.executed = False
            return result

        if self.dry_run:
            result.executed = False
            result.status_code = 0
            result.response_body = "[DRY RUN] No request was sent to the target."
            result.response_time = 0.01
            # Simulate some findings based on tags
            tags_lower = [tag.lower() for tag in test.tags]
            if any(t in tags_lower for t in ("injection", "xss", "sqli")):
                result.risk_score = 7
                result.findings = ["Potential injection vector (dry-run)"]
            elif any(t in tags_lower for t in ("auth_bypass", "auth", "bypass")):
                result.risk_score = 8
                result.findings = ["Possible auth bypass (dry-run)"]
            elif any(t in tags_lower for t in ("logic", "idor")):
                result.risk_score = 6
                result.findings = ["Potential logic flaw (dry-run)"]
            else:
                result.risk_score = 4
                result.findings = ["Test case generated"]
            return result

        # Real execution with rate limiting
        async with self._lock:
            now = time.time()
            delay = (1.0 / self.rate_limit_rps) - (now - self._last_request_time)
            if delay > 0:
                await asyncio.sleep(delay)
            self._last_request_time = time.time()

        async with self._semaphore:
            try:
                timeout = httpx.Timeout(10.0, connect=5.0)
                async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                    start_time = time.time()

                    # Prepare request args
                    req_kwargs = {
                        "method": test.method,
                        "url": full_url,
                        "headers": dict(test.headers) if test.headers else None,
                        "params": dict(test.query_params) if test.query_params else None,
                    }
                    if test.payload and test.method in ("POST", "PUT", "PATCH"):
                        req_kwargs["json"] = dict(test.payload)

                    response = await client.request(**req_kwargs)  # type: ignore[arg-type]

                    result.executed = True
                    result.status_code = response.status_code
                    result.response_time = round(time.time() - start_time, 3)
                    result.response_body = response.text[:1000]  # limit size for storage

                    # Basic risk scoring based on response
                    if response.status_code >= 500:
                        result.risk_score = 9
                        result.findings.append(f"Server error ({response.status_code})")
                    elif response.status_code >= 400:
                        result.risk_score = 6
                        result.findings.append(f"Client error ({response.status_code})")
                    elif "error" in response.text.lower() or "exception" in response.text.lower():
                        result.risk_score = max(result.risk_score, 5)
                        result.findings.append("Possible error disclosure")

            except httpx.RequestError as exc:
                result.error = f"Request error: {str(exc)}"
                result.risk_score = 3
            except Exception as exc:  # noqa: BLE001
                result.error = str(exc)
                result.risk_score = 2

        return result

    def _is_allowed_host(self, url: str) -> bool:
        """Check if the target hostname is permitted."""
        if self.dry_run:
            return True
        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "localhost").lower()
            for allowed in self.allowed_hosts:
                if allowed in hostname or hostname.endswith(allowed) or hostname == allowed:
                    return True
            return False
        except Exception:  # noqa: BLE001
            return False
