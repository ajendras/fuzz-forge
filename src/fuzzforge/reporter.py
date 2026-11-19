"""Reporting module for Fuzz Forge.

Generates retro-styled HTML reports, JSON artifacts, reproduction scripts,
and terminal summaries using the 8-bit pixel aesthetic with chunky borders
and the signature #ff0044 / #ffff00 color scheme.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Template
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .core import TestResult

# Embedded Jinja2 template for the pixel-art HTML report
HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FUZZ FORGE REPORT</title>
    <link href="https://fonts.googleapis.com/css2?family=Press+Start+2P&amp;display=swap" rel="stylesheet">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap');
        
        :root {
            --navy: #0b0e2e;
            --pink: #ff0044;
            --yellow: #ffff00;
            --cyan: #00ffff;
        }
        
        body {
            background: var(--navy);
            color: var(--yellow);
            font-family: 'Press Start 2P', system-ui;
            padding: 2rem;
            line-height: 1.6;
            image-rendering: pixelated;
        }
        
        .container {
            max-width: 960px;
            margin: 0 auto;
            border: 8px solid var(--pink);
            background: #111133;
            padding: 2rem;
            box-shadow: 0 0 0 12px var(--yellow);
        }
        
        h1 {
            color: var(--pink);
            text-shadow: 6px 6px 0 var(--yellow);
            font-size: 22px;
            text-align: center;
            margin-bottom: 2rem;
            letter-spacing: 4px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1.5rem 0;
            font-size: 13px;
        }
        
        th, td {
            border: 4px solid var(--pink);
            padding: 12px 8px;
            text-align: left;
        }
        
        th {
            background: var(--pink);
            color: var(--navy);
            font-weight: bold;
        }
        
        .vuln {
            color: var(--pink);
            font-weight: bold;
        }
        
        .footer {
            text-align: center;
            margin-top: 3rem;
            color: #666699;
            font-size: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>FUZZ FORGE REPORT</h1>
        <p style="text-align:center;color:#00ffff">Generated {{ timestamp }} • LOCAL AI POWERED</p>
        
        <table>
            <thead>
                <tr>
                    <th>ENDPOINT</th>
                    <th>RISK</th>
                    <th>STATUS</th>
                    <th>FINDINGS</th>
                </tr>
            </thead>
            <tbody>
                {% for r in results %}
                <tr>
                    <td>{{ r.test_case.endpoint }}</td>
                    <td style="text-align:center">{{ r.risk_score }}</td>
                    <td class="{% if r.is_vulnerable %}vuln{% endif %}">
                        {{ 'VULNERABLE' if r.is_vulnerable else 'clean' }}
                    </td>
                    <td>{{ r.findings | join(', ') or '—' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        
        <div class="footer">
            ★★★ REPORT SAVED TO fuzz-reports/ ★★★<br>
            REPRODUCERS + SARIF ALSO GENERATED
        </div>
    </div>
</body>
</html>
"""


class Reporter:
    """Handles all output formats for scan results."""

    def __init__(self) -> None:
        self.console = Console()

    def generate_html(self, results: List[TestResult], output_dir: str) -> None:
        """Generate a retro-styled HTML report."""
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        template = Template(HTML_TEMPLATE)
        html_content = template.render(results=results, timestamp=timestamp)

        (out_dir / "report.html").write_text(html_content, encoding="utf-8")

    def generate_json(self, results: List[TestResult], output_dir: str) -> None:
        """Generate JSON report with full details."""
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        data = [r.model_dump(mode="json") for r in results]
        with open(out_dir / "results.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def generate_sarif(self, results: List[TestResult], output_dir: str) -> None:
        """Generate SARIF report containing *only* high-risk results.

        This matches GitHub Security tab expectations and the test
        `test_sarif_only_includes_high_risk`.
        """
        high_risk = [r for r in results if r.is_vulnerable]

        sarif: Dict[str, Any] = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Fuzz Forge",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/fuzzforge/fuzz-forge",
                            "rules": [
                                {
                                    "id": "fuzzforge.injection",
                                    "name": "Injection Vulnerability",
                                    "shortDescription": {
                                        "text": "Potential XSS, SQLi or command injection"
                                    },
                                },
                                {
                                    "id": "fuzzforge.auth_bypass",
                                    "name": "Authentication Bypass",
                                    "shortDescription": {"text": "Auth bypass or missing auth"},
                                },
                                {
                                    "id": "fuzzforge.logic",
                                    "name": "Business Logic Flaw",
                                    "shortDescription": {"text": "IDOR or logic manipulation"},
                                },
                            ],
                        }
                    },
                    "results": [],
                }
            ],
        }

        for result in high_risk:
            rule_id = "fuzzforge.generic"
            tags = [t.lower() for t in result.test_case.tags]
            if any(t in tags for t in ("injection", "xss", "sqli")):
                rule_id = "fuzzforge.injection"
            elif any(t in tags for t in ("auth_bypass", "authorization", "bypass")):
                rule_id = "fuzzforge.auth_bypass"
            elif any(t in tags for t in ("logic", "idor")):
                rule_id = "fuzzforge.logic"

            sarif["runs"][0]["results"].append(
                {
                    "ruleId": rule_id,
                    "level": "error",
                    "message": {
                        "text": (
                            result.findings[0]
                            if result.findings
                            else result.test_case.description
                        )
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": result.test_case.endpoint,
                                    "index": 0,
                                }
                            }
                        }
                    ],
                }
            )

        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        with open(out_dir / "results.sarif.json", "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)

    def write_repro_files(self, results: List[TestResult], output_dir: str) -> None:
        """Write standalone curl reproducer scripts for every result."""
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        for i, result in enumerate(results):
            if not result.repro_curl:
                continue
            filename = f"repro_{i:03d}_{result.test_case.endpoint.replace(' ', '_').replace('/', '_')}.sh"
            repro_file = out_dir / filename
            repro_file.write_text(
                f"#!/bin/sh\n# Risk score: {result.risk_score}\n# {result.test_case.description}\n\n{result.repro_curl}\n",
                encoding="utf-8",
            )
            repro_file.chmod(0o755)

    def print_summary(self, results: List[TestResult]) -> None:
        """Print rich terminal summary (used by CLI)."""
        if not results:
            self.console.print("[dim]No results to summarize.[/dim]")
            return

        table = Table(title="Fuzz Forge Findings", border_style="#ff0044")
        table.add_column("Endpoint", style="#ffff00")
        table.add_column("Risk", justify="right")
        table.add_column("Vulnerable", justify="center")

        vuln_count = 0
        for r in results:
            vuln = "YES" if r.is_vulnerable else "no"
            if r.is_vulnerable:
                vuln_count += 1
            table.add_row(r.test_case.endpoint, str(r.risk_score), vuln)

        self.console.print(Panel(table, border_style="#ffff00"))
        self.console.print(
            f"\n[bold #ff0044]→ {vuln_count} potential issue(s) found.[/bold #ff0044] "
            "Check fuzz-reports/ for HTML/JSON/SARIF + repro scripts."
        )
