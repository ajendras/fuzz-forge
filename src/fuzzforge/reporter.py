"""Reporting module for Fuzz Forge.

Generates retro-styled HTML reports, JSON artifacts, reproduction scripts,
and terminal summaries using the 8-bit pixel aesthetic with chunky borders
and the signature #ff0044 / #ffff00 color scheme.

The HTML report is fully interactive: modal with tabbed request/response
viewers (formatted JSON, headers, cURL) and one-click replay (clipboard
copy or live browser fetch with safety warning).
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

# Embedded Jinja2 template for the pixel-art interactive HTML report
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <link href="https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap" rel="stylesheet">
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
            margin: 0;
            padding: 20px;
            line-height: 1.4;
            image-rendering: pixelated;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        header {
            border: 8px solid var(--pink);
            padding: 20px;
            text-align: center;
            background: #111;
            margin-bottom: 30px;
        }
        
        h1 {
            color: var(--pink);
            text-shadow: 4px 4px 0 var(--yellow);
            font-size: 28px;
            margin: 0;
        }
        
        .stats {
            display: flex;
            justify-content: space-around;
            margin-bottom: 30px;
            border: 4px solid var(--cyan);
            padding: 15px;
            background: rgba(0, 255, 255, 0.1);
            font-size: 13px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            border: 6px solid var(--pink);
            background: #0a0a1f;
            font-size: 12px;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border: 3px solid var(--yellow);
        }
        
        th {
            background: var(--pink);
            color: var(--navy);
        }
        
        tr:hover {
            background: rgba(255, 0, 68, 0.3);
            cursor: pointer;
        }
        
        .risk-high { 
            color: var(--pink); 
            font-weight: bold; 
        }
        
        .risk-med { 
            color: var(--yellow); 
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 100;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(11, 14, 46, 0.95);
            font-family: 'Press Start 2P', system-ui;
        }
        
        .modal-content {
            background: #111133;
            margin: 5% auto;
            padding: 20px;
            border: 8px solid var(--yellow);
            width: 80%;
            max-width: 900px;
            max-height: 80vh;
            overflow-y: auto;
            box-shadow: 0 0 0 8px var(--pink);
        }
        
        .close {
            color: var(--pink);
            float: right;
            font-size: 32px;
            font-weight: bold;
            cursor: pointer;
            line-height: 20px;
        }
        
        .tabs {
            display: flex;
            border-bottom: 4px solid var(--pink);
            margin-bottom: 20px;
        }
        
        .tab {
            padding: 12px 24px;
            margin-right: 6px;
            cursor: pointer;
            border: 4px solid var(--yellow);
            background: var(--navy);
            font-size: 11px;
        }
        
        .tab.active {
            background: var(--pink);
            color: var(--yellow);
            border-color: var(--cyan);
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        pre {
            background: #000;
            padding: 15px;
            border: 4px solid var(--cyan);
            overflow: auto;
            font-size: 11px;
            color: #0f0;
            white-space: pre-wrap;
            word-break: break-all;
        }
        
        button {
            font-family: 'Press Start 2P', system-ui;
            background: var(--pink);
            color: var(--yellow);
            border: 4px solid var(--yellow);
            padding: 10px 18px;
            cursor: pointer;
            margin: 5px 5px 15px 0;
            font-size: 11px;
        }
        
        button:hover {
            background: var(--yellow);
            color: var(--pink);
        }
        
        .warning {
            color: var(--pink);
            background: #220000;
            border: 4px dashed var(--pink);
            padding: 15px;
            font-size: 10px;
            margin-bottom: 15px;
        }
        
        .status {
            padding: 5px 12px;
            border: 3px solid var(--yellow);
            display: inline-block;
        }
        
        code {
            color: #0f0;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{{ title }}</h1>
            <p style="color:#00ffff; margin-top:10px;">GENERATED {{ generated_at }} • LOCAL AI POWERED • INTERACTIVE</p>
        </header>
        
        <div class="stats">
            <div><strong>TOTAL TESTS:</strong> {{ results|length }}</div>
            <div><strong>VULNERABILITIES:</strong> <span style="color:#ff0044">{{ total_vulns }}</span></div>
            <div><strong>REPORT TYPE:</strong> INTERACTIVE HTML</div>
        </div>
        
        <h2 style="color:#ff0044; border-bottom:4px solid #ffff00; padding-bottom:10px;">TEST CASES • CLICK ROW TO INSPECT</h2>
        
        <table id="results-table">
            <thead>
                <tr>
                    <th>ENDPOINT</th>
                    <th>METHOD</th>
                    <th>RISK</th>
                    <th>STATUS</th>
                    <th>TAGS</th>
                </tr>
            </thead>
            <tbody>
            {% for result in results %}
            {% set i = loop.index0 %}
            <tr onclick="openModal({{ i }})">
                <td>{{ result.test_case.endpoint }}</td>
                <td>{{ result.test_case.method }}</td>
                <td class="{% if result.risk_score > 6 %}risk-high{% else %}risk-med{% endif %}">{{ result.risk_score }}/10</td>
                <td>{{ result.status_code or 'DRY' }}</td>
                <td>{{ result.test_case.tags|join(', ') if result.test_case.tags else '—' }}</td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
        
        <div style="margin-top:30px; text-align:center; font-size:10px; color:#00ffff;">
            CLICK ANY ROW TO OPEN VIEWER • ONE-CLICK REPLAY AVAILABLE IN MODAL
        </div>
    </div>

    <!-- Modal -->
    <div id="modal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal()">&times;</span>
            <h2 id="modal-title" style="color:#ffff00; margin-top:0;"></h2>
            <div id="modal-description" style="color:#aaa; font-size:11px; margin-bottom:20px;"></div>
            
            <div class="tabs">
                <div class="tab active" onclick="switchTab(0)">REQUEST</div>
                <div class="tab" onclick="switchTab(1)">RESPONSE</div>
                <div class="tab" onclick="switchTab(2)">REPLAY</div>
            </div>
            
            <div id="tab-request" class="tab-content active">
                <h3 style="color:#00ffff">REQUEST DETAILS</h3>
                <button onclick="copyCurl()">📋 COPY cURL</button>
                <div id="curl-command" style="margin:15px 0; font-size:10px; background:#000; padding:10px; border:2px solid #00ffff;"></div>
                
                <h4 style="color:#00ffff">Headers</h4>
                <pre id="request-headers"></pre>
                
                <h4 style="color:#00ffff">Payload</h4>
                <pre id="request-payload"></pre>
            </div>
            
            <div id="tab-response" class="tab-content">
                <h3 style="color:#00ffff">RESPONSE DETAILS</h3>
                <div id="response-status" style="margin-bottom:15px;"></div>
                <h4 style="color:#00ffff">Body</h4>
                <pre id="response-body" style="max-height:320px;"></pre>
            </div>
            
            <div id="tab-replay" class="tab-content">
                <h3 style="color:#00ffff">ONE-CLICK REPLAY</h3>
                <div class="warning">
                    ⚠️ WARNING: This will send a real HTTP request to the target from your browser.<br>
                    Only use against test/staging environments you control.<br>
                    CORS errors may occur — the cURL button is always safe.
                </div>
                <button onclick="copyCurl()" style="background:#ffff00;color:#000">📋 COPY cURL TO CLIPBOARD</button>
                <button onclick="performReplay()" style="background:#00ff88;color:#000">▶️ REPLAY IN BROWSER</button>
                <div id="replay-result" style="margin-top:20px; min-height:120px;"></div>
            </div>
            
            <div style="text-align:center; margin-top:30px; font-size:10px; color:#666;">
                Fuzz Forge Interactive Report • Powered by local LLM • Press Start 2P aesthetic
            </div>
        </div>
    </div>

    <script>
        const RESULTS = {{ results | tojson }};
        const BASE_URL = "{{ base_url }}";
        let currentResultIndex = 0;
        
        function openModal(index) {
            currentResultIndex = index;
            const result = RESULTS[index];
            const tc = result.test_case || {};
            
            document.getElementById('modal').style.display = 'block';
            document.getElementById('modal-title').textContent = tc.endpoint || tc.path || 'Unknown Endpoint';
            document.getElementById('modal-description').textContent = tc.description || 'No description provided.';
            
            renderRequest(tc, result.repro_curl || '');
            renderResponse(result);
            
            document.querySelectorAll('.tab').forEach((t, i) => {
                t.classList.toggle('active', i === 0);
            });
            document.querySelectorAll('.tab-content').forEach((c, i) => {
                c.classList.toggle('active', i === 0);
            });
            
            document.getElementById('replay-result').innerHTML = '';
        }
        
        function closeModal() {
            document.getElementById('modal').style.display = 'none';
            document.getElementById('replay-result').innerHTML = '';
        }
        
        function switchTab(tabIndex) {
            document.querySelectorAll('.tab').forEach((tab, i) => {
                tab.classList.toggle('active', i === tabIndex);
            });
            document.querySelectorAll('.tab-content').forEach((content, i) => {
                content.classList.toggle('active', i === tabIndex);
            });
        }
        
        function renderRequest(tc, reproCurl) {
            const curlBox = document.getElementById('curl-command');
            curlBox.innerHTML = '<strong style="color:#ffff00">cURL REPRO:</strong><br><code style="color:#0f0">' + 
                               (reproCurl || 'curl -X ' + tc.method + ' "' + BASE_URL + tc.path + '"') + '</code>';
            
            let headersText = '{\n';
            const headers = tc.headers || {};
            for (let [k, v] of Object.entries(headers)) {
                headersText += `  "${k}": "${v}",\n`;
            }
            headersText += '}';
            document.getElementById('request-headers').textContent = headersText;
            
            const payloadText = JSON.stringify(tc.payload || {}, null, 2);
            document.getElementById('request-payload').textContent = payloadText;
        }
        
        function renderResponse(result) {
            const statusEl = document.getElementById('response-status');
            let html = `Status: <span class="status" style="color:${result.risk_score > 5 ? '#ff0044' : '#00ff88'}">` +
                      `${result.status_code || 'DRY-RUN'}</span>`;
            if (result.response_time) {
                html += ` &nbsp; | &nbsp; Time: ${result.response_time}s`;
            }
            if (result.findings && result.findings.length > 0) {
                html += `<br><span style="color:#ffaa00">Findings: ${result.findings.join(', ')}</span>`;
            }
            statusEl.innerHTML = html;
            
            let bodyText = result.response_body || '[NO RESPONSE BODY CAPTURED]';
            if (bodyText.length > 800) {
                bodyText = bodyText.substring(0, 800) + '\n... (truncated in report)';
            }
            document.getElementById('response-body').textContent = bodyText;
        }
        
        function copyCurl() {
            const result = RESULTS[currentResultIndex];
            const curlText = result.repro_curl || '';
            if (!curlText) {
                alert("No cURL command available for this test.");
                return;
            }
            navigator.clipboard.writeText(curlText).then(() => {
                const btns = document.querySelectorAll('button');
                for (let btn of btns) {
                    if (btn.textContent.includes('COPY')) {
                        const original = btn.textContent;
                        btn.textContent = '✅ COPIED!';
                        setTimeout(() => { btn.textContent = original; }, 1800);
                        break;
                    }
                }
            }).catch(() => {
                alert("Clipboard copy failed.");
            });
        }
        
        async function performReplay() {
            const result = RESULTS[currentResultIndex];
            const tc = result.test_case || {};
            const replayDiv = document.getElementById('replay-result');
            replayDiv.innerHTML = '<p style="color:#ffff00">SENDING REQUEST...</p>';
            
            let url = tc.path || '/';
            if (!url.startsWith('http')) {
                url = BASE_URL.replace(/\/$/, '') + (url.startsWith('/') ? url : '/' + url);
            }
            
            const options = {
                method: tc.method || 'GET',
                headers: {...(tc.headers || {})},
                credentials: 'omit'
            };
            
            const query = tc.query_params || {};
            if (Object.keys(query).length > 0) {
                const qs = new URLSearchParams(query).toString();
                url += (url.includes('?') ? '&' : '?') + qs;
            }
            
            if (tc.payload && ['POST', 'PUT', 'PATCH'].indexOf(options.method) !== -1) {
                options.body = JSON.stringify(tc.payload);
                if (!options.headers['Content-Type']) {
                    options.headers['Content-Type'] = 'application/json';
                }
            }
            
            try {
                const start = Date.now();
                const res = await fetch(url, options);
                const duration = ((Date.now() - start) / 1000).toFixed(2);
                let respText = await res.text();
                if (respText.length > 450) {
                    respText = respText.substring(0, 450) + '...';
                }
                
                replayDiv.innerHTML = `
                    <div style="border:4px solid #00ff88; padding:12px; background:#001100;">
                        <strong style="color:#00ff88">REPLAY SUCCESS (LIVE)</strong><br>
                        Status: ${res.status} | Time: ${duration}s<br><br>
                        <strong style="color:#ffff00">Response Body:</strong><br>
                        <pre style="background:#000;color:#0f0;font-size:10px;max-height:180px;">${respText}</pre>
                    </div>
                `;
            } catch (err) {
                replayDiv.innerHTML = `
                    <div style="border:4px solid #ff0044; padding:12px; background:#220000; color:#ff0044">
                        REPLAY FAILED<br>
                        ${err.message}<br><br>
                        (Common causes: CORS policy, network, or the target blocks browser requests.<br>
                        Use the COPY cURL button instead.)
                    </div>
                `;
            }
        }
        
        document.addEventListener('keydown', function(e) {
            if (e.key === "Escape") {
                const modal = document.getElementById('modal');
                if (modal.style.display === 'block') {
                    closeModal();
                }
            }
        });
        
        console.log('%cFuzz Forge Interactive Report ready. Click any row for request/response viewers and replay.', 
                   'color:#ffff00; font-family:monospace; font-size:10px');
    </script>
</body>
</html>
"""

class Reporter:
    """Reporter that produces retro-styled interactive HTML, JSON, SARIF and repro files."""

    def __init__(self) -> None:
        self.console = Console(highlight=False)

    def generate_html(self, results: List[TestResult], output_dir: str = "fuzz-reports") -> None:
        """Generate fully interactive HTML report with request/response viewers and one-click replay.

        The report uses a pixel-art retro aesthetic, includes a clickable table that opens
        a modal with three tabs (Request, Response, Replay), formatted JSON, copy-to-clipboard,
        and a browser fetch replay button (with explicit safety warning).
        """
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        report_file = out_path / "report.html"

        context = {
            "title": "FUZZ FORGE // INTERACTIVE REPORT",
            "results": [r.model_dump() for r in results],
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_vulns": sum(1 for r in results if r.is_vulnerable),
            "base_url": "http://localhost:8000",
        }

        template = Template(HTML_TEMPLATE)
        html_content = template.render(**context)
        report_file.write_text(html_content, encoding="utf-8")

        self.console.print(
            f"[bold #ffff00]Interactive HTML report[/bold #ffff00] → [bold]{report_file}[/bold]",
            style="#00ffff",
        )

    def generate_json(self, results: List[TestResult], output_dir: str = "fuzz-reports") -> None:
        """Generate machine-readable JSON report of all TestResults."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        data = [r.model_dump() for r in results]
        (out_path / "results.json").write_text(
            json.dumps(data, indent=2, default=str), encoding="utf-8"
        )

    def generate_sarif(self, results: List[TestResult], output_dir: str = "fuzz-reports") -> None:
        """Generate SARIF report for GitHub Security tab integration."""
        sarif: Dict[str, Any] = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.4.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Fuzz Forge",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/fuzzforge/fuzz-forge",
                        }
                    },
                    "results": [],
                }
            ],
        }

        for result in results:
            if result.is_vulnerable:
                sarif["runs"][0]["results"].append(
                    {
                        "ruleId": f"FUZZ-{result.risk_score}",
                        "level": "error" if result.risk_score > 7 else "warning",
                        "message": {"text": " ".join(result.findings or ["Potential vulnerability"])},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": result.test_case.path}
                                }
                            }
                        ],
                    }
                )

        out_path = Path(output_dir)
        (out_path / "results.sarif.json").write_text(
            json.dumps(sarif, indent=2), encoding="utf-8"
        )

    def write_repro_files(self, results: List[TestResult], output_dir: str = "fuzz-reports") -> None:
        """Write one .sh file per test containing a ready-to-run curl command."""
        repro_dir = Path(output_dir) / "repros"
        repro_dir.mkdir(parents=True, exist_ok=True)

        for result in results:
            if result.repro_curl:
                filename = f"{result.test_case.id}.sh"
                (repro_dir / filename).write_text(
                    f"#!/bin/bash\n# {result.test_case.description}\n{result.repro_curl}\n",
                    encoding="utf-8",
                )

    def print_summary(self, results: List[TestResult]) -> None:
        """Print a rich terminal summary of findings."""
        if not results:
            self.console.print("No results to summarize.", style="dim")
            return

        table = Table(title="Top Findings", border_style="#ff0044", title_style="bold #ffff00")
        table.add_column("Endpoint", style="#ffff00")
        table.add_column("Risk", justify="center")
        table.add_column("Findings", style="bright_blue")

        for result in results[:6]:
            findings = ", ".join(result.findings) or "—"
            table.add_row(
                result.test_case.endpoint,
                f"{result.risk_score}/10",
                findings,
            )

        self.console.print(table)

        vulnerable = sum(1 for r in results if r.is_vulnerable)
        if vulnerable > 0:
            self.console.print(
                Panel(
                    f"[bold #ff0044]⚠ {vulnerable} POTENTIAL VULNERABILITIES DETECTED[/bold #ff0044]\n"
                    "Review fuzz-reports/report.html for full interactive details.",
                    border_style="#ff0044",
                )
            )
