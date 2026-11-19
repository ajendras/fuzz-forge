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
            image-rendering: pixelated;
            padding: 20px;
            line-height: 1.5;
        }
        
        .container {
            max-width: 960px;
            margin: 0 auto;
            border: 8px solid var(--pink);
            background: #111;
            padding: 20px;
            box-shadow: 0 0 0 8px #000;
        }
        
        h1 {
            color: var(--pink);
            text-align: center;
            text-shadow: 4px 4px 0 #000;
            font-size: 18px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        th, td {
            border: 4px solid var(--pink);
            padding: 12px;
            text-align: left;
            font-size: 12px;
        }
        
        th {
            background: var(--pink);
            color: var(--yellow);
        }
        
        .vulnerable {
            background: #330000;
            color: #ffaa00;
        }
        
        .scan-header {
            border: 6px solid var(--yellow);
            padding: 15px;
            text-align: center;
            margin-bottom: 20px;
            background: #1a1a1a;
        }
        
        pre {
            background: #000;
            padding: 8px;
            font-size: 10px;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="scan-header">
            <h1>FUZZ FORGE v0.1.0</h1>
            <p>RETRO SECURITY SCAN REPORT</p>
            <p>{{ timestamp }}</p>
        </div>
        
        <h1 style="color:#00ffff">FINDINGS ({{ results|length }})</h1>
        
        <table>
            <tr>
                <th>ENDPOINT</th>
                <th>RISK</th>
                <th>TAGS</th>
                <th>REPRO</th>
            </tr>
            {% for r in results %}
            <tr {% if r.is_vulnerable %}class="vulnerable"{% endif %}>
                <td>{{ r.test_case.endpoint }}</td>
                <td>{{ r.risk_score }}</td>
                <td>{{ r.test_case.tags|join(', ') or '—' }}</td>
                <td><pre>{{ r.repro_curl }}</pre></td>
            </tr>
            {% endfor %}
        </table>
        
        <div style="margin-top:40px; text-align:center; color:#00ffff; font-size:10px;">
            MADE WITH ❤️ FOR 8-BIT SECURITY<br>
            SARIF ALSO GENERATED FOR GITHUB INTEGRATION
        </div>
    </div>
</body>
</html>
"""


class Reporter:
    """Generates multiple report formats including HTML, JSON, SARIF and reproduction scripts."""

    def __init__(self) -> None:
        self.console = Console(highlight=False)

    def generate_html(self, results: List[TestResult], output_dir: str = "fuzz-reports") -> None:
        """Generate retro-styled HTML report."""
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        template = Template(HTML_TEMPLATE)
        html_content = template.render(
            results=results,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        (out_dir / "report.html").write_text(html_content, encoding="utf-8")
        self.console.print(f"[bold #ffff00]HTML report[/bold #ffff00] → [bold]{out_dir}/report.html[/bold]")

    def generate_json(self, results: List[TestResult], output_dir: str = "fuzz-reports") -> None:
        """Write full results as JSON for further processing or replay."""
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        data = [result.model_dump(mode="json") for result in results]
        (out_dir / "results.json").write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )
        self.console.print(f"[bold #ffff00]JSON results[/bold #ffff00] → [bold]{out_dir}/results.json[/bold]")

    def generate_sarif(self, results: List[TestResult], output_dir: str = "fuzz-reports") -> None:
        """Generate SARIF 2.1.0 output for direct upload to GitHub Security tab / Code Scanning.

        Only includes findings with risk_score > 5. The file is named results.sarif.json
        and follows the official schema.
        """
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        sarif_data = self._build_sarif(results)
        sarif_path = out_dir / "results.sarif.json"
        sarif_path.write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")

        self.console.print(f"[bold #ffff00]SARIF report[/bold #ffff00] → [bold]{sarif_path}[/bold]")

    def _build_sarif(self, results: List[TestResult]) -> Dict[str, Any]:
        """Build a valid SARIF document from test results.

        Only high-signal results (risk_score > 5) are included.
        """
        sarif_results: List[Dict[str, Any]] = []
        rules_seen: Dict[str, Dict[str, Any]] = {}

        for result in results:
            if result.risk_score <= 5:
                continue

            # Determine primary tag for rule ID
            primary_tag = "generic"
            for tag in result.test_case.tags:
                if tag in ("injection", "xss", "sqli", "auth_bypass", "logic", "idor"):
                    primary_tag = tag
                    break

            rule_id = f"fuzzforge/{primary_tag}"

            if rule_id not in rules_seen:
                rules_seen[rule_id] = {
                    "id": rule_id,
                    "name": f"FuzzForge {primary_tag.title()}",
                    "shortDescription": {
                        "text": f"Potential {primary_tag} vulnerability detected by AI fuzzing"
                    },
                    "fullDescription": {
                        "text": "Fuzz Forge uses local LLMs to generate contextual security tests. "
                        "This finding indicates a test case that may expose a security issue."
                    },
                    "help": {
                        "text": "Review the repro curl command and validate the endpoint behavior. "
                        "Consider implementing stricter validation or authorization checks."
                    },
                    "properties": {
                        "tags": ["security", "fuzzing", "ai-generated"],
                        "precision": "medium",
                        "security-severity": str(result.risk_score * 10),  # 0-100 scale
                    },
                }

            # Map risk to SARIF level
            if result.risk_score >= 8:
                level = "error"
            elif result.risk_score >= 6:
                level = "warning"
            else:
                level = "note"

            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {
                        "text": f"{result.test_case.description} (risk={result.risk_score})",
                        "markdown": f"**{result.test_case.endpoint}**\n\n"
                        f"{result.test_case.description}\n\n"
                        f"**Repro:** `{result.repro_curl}`",
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "uri": result.test_case.path.lstrip("/"),
                                "uriBaseId": "API",
                            },
                            "message": {"text": result.test_case.endpoint},
                        }
                    ],
                    "properties": {
                        "riskScore": result.risk_score,
                        "tags": result.test_case.tags,
                        "reproCurl": result.repro_curl,
                        "statusCode": result.status_code,
                    },
                }
            )

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Fuzz Forge",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/fuzzforge/fuzz-forge",
                            "rules": list(rules_seen.values()),
                        }
                    },
                    "results": sarif_results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "toolExecutionNotifications": [],
                        }
                    ],
                }
            ],
        }

    def write_repro_files(self, results: List[TestResult], output_dir: str = "fuzz-reports") -> None:
        """Write executable curl repro scripts for each finding."""
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        for result in [r for r in results if r.is_vulnerable]:
            curl_cmd = result.repro_curl or result.test_case.to_curl()
            repro_path = out_dir / f"repro_{result.test_case.id}.sh"
            repro_path.write_text(f"#!/bin/sh\n{curl_cmd}\n", encoding="utf-8")
