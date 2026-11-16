"""Reporting module for Fuzz Forge.

Generates retro-styled HTML reports, JSON artifacts, reproduction scripts,
and terminal summaries using the 8-bit pixel aesthetic with chunky borders
and the signature #ff0044 / #ffff00 color scheme.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, List

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
            color: #aaffaa;
            font-family: 'Courier New', monospace;
            padding: 20px;
            line-height: 1.4;
            image-rendering: pixelated;
        }
        
        h1, h2 {
            font-family: 'Press Start 2P', system-ui;
            color: var(--yellow);
            text-shadow: 4px 4px 0 var(--pink);
            image-rendering: pixelated;
        }
        
        .header {
            border: 8px solid var(--pink);
            background: #1a1a4e;
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: 0 0 0 8px #ffff00;
            text-align: center;
        }
        
        .panel {
            border: 6px solid var(--yellow);
            background: #111133;
            padding: 15px;
            margin-bottom: 25px;
            box-shadow: 8px 8px 0 #ff0044;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: #0a0a2a;
        }
        
        th, td {
            border: 3px solid var(--pink);
            padding: 12px 8px;
            text-align: left;
            font-size: 0.85rem;
        }
        
        th {
            background: var(--pink);
            color: var(--yellow);
            font-family: 'Press Start 2P', sans-serif;
            font-size: 0.7rem;
        }
        
        tr:nth-child(even) {
            background: #1c1c4a;
        }
        
        .risk-high {
            color: #ff0044;
            font-weight: bold;
        }
        
        .risk-med {
            color: #ffff00;
        }
        
        .tag {
            display: inline-block;
            background: #220033;
            color: var(--yellow);
            padding: 3px 10px;
            margin: 2px;
            font-size: 0.65rem;
            border: 2px solid var(--yellow);
            font-family: 'Press Start 2P', sans-serif;
        }
        
        pre {
            background: #000022;
            border: 4px solid var(--cyan);
            padding: 15px;
            overflow-x: auto;
            font-size: 0.75rem;
            color: #aaffff;
            white-space: pre-wrap;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            font-size: 0.6rem;
            color: #666699;
        }
        
        .scanline {
            position: relative;
        }
        
        .scanline::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(
                to bottom,
                transparent 50%,
                rgba(255, 0, 68, 0.07) 50%
            );
            background-size: 100% 6px;
            pointer-events: none;
            animation: scan 4s linear infinite;
        }
        
        @keyframes scan {
            0% { background-position: 0 0; }
            100% { background-position: 0 600px; }
        }
        
        button {
            font-family: 'Press Start 2P', sans-serif;
            background: #ffff00;
            color: #000044;
            border: 4px solid #ff0044;
            padding: 10px 20px;
            cursor: pointer;
            box-shadow: 4px 4px 0 #ff0044;
            margin: 10px;
        }
        
        button:active {
            transform: translate(3px, 3px);
            box-shadow: 1px 1px 0 #ff0044;
        }
    </style>
</head>
<body>
    <div class="header scanline">
        <h1 style="font-size: 2.4rem; margin: 10px 0 5px; letter-spacing: 6px;">FUZZ FORGE</h1>
        <div style="color: #ff0044; font-size: 1.1rem; letter-spacing: 6px;">8-BIT LLM SECURITY SCANNER</div>
        <div style="color: #00ffcc; margin-top: 18px; font-size: 0.85rem;">
            REPORT GENERATED {{ generated_at }} • MODEL: {{ model }}
        </div>
    </div>

    <div class="panel">
        <h2 style="font-size: 1.1rem; margin-top:0;">MISSION STATS</h2>
        <p><strong>TOTAL TESTS:</strong> {{ total }} &nbsp;&nbsp; 
           <strong>POTENTIAL VULNS:</strong> <span class="risk-high">{{ vulnerable }}</span></p>
        <p><strong>SAFE DEFAULTS ENFORCED:</strong> Dry-run mode, host allowlist, rate-limited execution.</p>
    </div>

    <div class="panel">
        <h2 style="font-size: 1.1rem;">FINDINGS</h2>
        <table>
            <thead>
                <tr>
                    <th>ENDPOINT</th>
                    <th>RISK</th>
                    <th>TAGS</th>
                    <th>STATUS</th>
                    <th>FINDINGS</th>
                </tr>
            </thead>
            <tbody>
                {% for result in results %}
                {% set tc = result.test_case %}
                <tr>
                    <td style="font-family: 'Press Start 2P', sans-serif; font-size: 0.75rem; max-width: 220px;">{{ tc.endpoint }}</td>
                    <td>
                        <span class="{% if result.risk_score > 6 %}risk-high{% else %}risk-med{% endif %}">
                            {{ result.risk_score }}/10
                        </span>
                    </td>
                    <td>
                        {% for tag in tc.tags %}
                        <span class="tag">{{ tag }}</span>
                        {% endfor %}
                    </td>
                    <td>{{ result.status_code or 'DRY' }}</td>
                    <td style="max-width: 260px;">{{ result.findings | join(', ') or '—' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <div class="panel">
        <h2 style="font-size: 1.1rem;">REPRODUCTION CURLS</h2>
        {% for result in results %}
        {% set tc = result.test_case %}
        <div style="margin-bottom: 40px; border: 4px solid #ffff00; padding: 4px;">
            <div style="background:#220022; padding:10px 14px; border-bottom:4px solid #ff0044; font-family:'Press Start 2P'; color:#ff0044; font-size:0.8rem;">
                {{ tc.endpoint }} — {{ tc.description }}
            </div>
            <pre>$ {{ result.repro_curl }}</pre>
            {% if result.response_body %}
            <details style="margin: 8px 12px;">
                <summary style="cursor:pointer; color:#ffff00; font-size:0.8rem; font-family:'Press Start 2P';">RESPONSE PREVIEW</summary>
                <pre style="margin-top:8px; font-size:0.7rem;">{{ result.response_body[:420] }}{% if result.response_body|length > 420 %}...{% endif %}</pre>
            </details>
            {% endif %}
        </div>
        {% endfor %}
    </div>

    <div class="footer">
        <p>✦ FUZZ FORGE v{{ version }} ✦ PRIVATE • LOCAL LLM • NO DATA LEFT BEHIND ✦</p>
        <p style="margin-top:15px;">
            <button onclick="copyAllCurls()">COPY ALL CURLS</button>
        </p>
    </div>

    <script>
        function copyAllCurls() {
            let curls = '';
            document.querySelectorAll('pre').forEach(pre => {
                const text = pre.textContent || '';
                if (text.includes('curl')) curls += text + '\\n\\n---\\n\\n';
            });
            navigator.clipboard.writeText(curls.trim()).then(() => {
                const btns = document.querySelectorAll('button');
                for (let b of btns) {
                    const orig = b.textContent;
                    b.textContent = 'COPIED!';
                    setTimeout(() => b.textContent = orig, 1800);
                }
            });
        }
    </script>
</body>
</html>
"""


console = Console()


class Reporter:
    """Generates rich reports in HTML, JSON and reproduction scripts."""

    def generate_html(self, results: List[TestResult], out_path: str) -> None:
        """Generate a retro 8-bit styled HTML report and accompanying JSON.

        Args:
            results: List of test results to report on.
            out_path: Directory where report files will be saved.
        """
        if not isinstance(out_path, str):
            raise ValueError("out_path must be a string directory path")

        out_dir = Path(out_path)
        out_dir.mkdir(parents=True, exist_ok=True)

        # Write JSON report (full fidelity)
        json_data = [result.model_dump(mode="json") for result in results]
        (out_dir / "results.json").write_text(
            json.dumps(json_data, indent=2, default=str), encoding="utf-8"
        )

        # Render HTML
        template = Template(HTML_TEMPLATE)
        html_content = template.render(
            results=json_data,
            total=len(results),
            vulnerable=sum(1 for r in results if r.risk_score > 5),
            version="0.1.0",
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            model="llama3.2",
        )

        (out_dir / "report.html").write_text(html_content, encoding="utf-8")

    def print_summary(self, results: List[TestResult]) -> None:
        """Print a rich terminal summary of the scan results."""
        if not results:
            console.print("[yellow]No results to summarize.[/yellow]")
            return

        vulnerable = sum(1 for r in results if r.is_vulnerable)
        high_risk = sum(1 for r in results if r.risk_score >= 7)

        console.print(Panel(
            f"[bold #ffff00]SCAN SUMMARY[/bold #ffff00]\n"
            f"Tests executed : [bold]{len(results)}[/bold]\n"
            f"High risk      : [bold #ff0044]{high_risk}[/bold #ff0044]\n"
            f"Potential bugs : [bold]{vulnerable}[/bold]",
            title="Fuzz Forge",
            border_style="#ff0044",
            padding=(1, 3),
        ))

        table = Table(
            title="Top Findings",
            border_style="#ff0044",
            title_style="bold #ffff00",
            show_lines=True,
        )
        table.add_column("Endpoint", style="#ffff00", no_wrap=True)
        table.add_column("Risk", justify="center")
        table.add_column("Tags", style="bright_blue")
        table.add_column("Finding", style="#aaffdd")

        displayed = 0
        for result in results:
            if displayed >= 7:
                break
            tc = result.test_case
            risk_style = "bold #ff0044" if result.risk_score > 6 else "bold #ffff00"
            risk_text = f"[{risk_style}]{result.risk_score}[/{risk_style}]"
            tags = ", ".join(tc.tags[:3]) or "—"
            finding = (result.findings[0] if result.findings else tc.description)[:38]
            table.add_row(tc.endpoint, risk_text, tags, finding)
            displayed += 1

        if displayed == 0:
            table.add_row("—", "—", "—", "No findings (dry-run mode)")

        console.print(table)

    def write_repro_files(self, results: List[TestResult], out_path: str) -> None:
        """Write standalone reproduction shell scripts for each test case.

        Args:
            results: Test results containing the test cases.
            out_path: Output directory for the .sh files.
        """
        if not isinstance(out_path, str):
            raise ValueError("out_path must be a string directory path")

        out_dir = Path(out_path)
        out_dir.mkdir(parents=True, exist_ok=True)

        for result in results:
            tc = result.test_case
            repro_path = out_dir / f"repro_{tc.id}.sh"

            curl_cmd = result.repro_curl or tc.to_curl()

            content = f"""#!/usr/bin/env bash
# Fuzz Forge Reproduction Script
# Test ID   : {tc.id}
# Endpoint  : {tc.endpoint}
# Description: {tc.description}
# Risk Score: {result.risk_score}
# Tags      : {', '.join(tc.tags)}
# Generated : {datetime.now().isoformat()}

set -euo pipefail

{curl_cmd}

echo ""
echo "=== RESPONSE ==="
echo "Check the output above. Re-run this script to reproduce."
"""
            repro_path.write_text(content, encoding="utf-8")
            repro_path.chmod(0o755)

        # Write a convenience runner
        runner = out_dir / "run_all_repros.sh"
        runner.write_text("""#!/usr/bin/env bash
# Fuzz Forge — Run all reproduction scripts
echo "========================================"
echo "   FUZZ FORGE REPRODUCTION SUITE"
echo "========================================"
echo ""

for f in repro_*.sh; do
    if [[ -x "$f" ]]; then
        echo "▶ Running $f ..."
        bash "$f"
        echo "----------------------------------------"
        echo ""
    fi
done

echo "All reproductions completed."
""", encoding="utf-8")
        runner.chmod(0o755)
