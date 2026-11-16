"""Command-line interface for Fuzz Forge.

Uses Typer + Rich for a retro 8-bit style terminal experience with chunky
borders, bright primary colours (#ff0044, #ffff00), and clear feedback.
"""

from pathlib import Path
from typing import Annotated, List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from fuzzforge import __version__, scan

app = typer.Typer(
    name="fuzzforge",
    help="Fuzz Forge — 8-bit AI API fuzzing with local LLMs",
    rich_markup_mode="rich",
    add_completion=True,
    no_args_is_help=True,
)

console = Console(highlight=False)


def _print_banner() -> None:
    """Render a chunky pixel-art style banner using Rich."""
    banner = Text()
    banner.append("╔", style="bold #ff0044")
    banner.append("═" * 56, style="bold #ff0044")
    banner.append("╗\n", style="bold #ff0044")

    banner.append("║", style="bold #ff0044")
    banner.append("                    FUZZ FORGE                     ".center(56), style="bold #ffff00")
    banner.append("║\n", style="bold #ff0044")

    banner.append("║", style="bold #ff0044")
    banner.append("       8-BIT LLM POWERED API SECURITY SCANNER       ".center(56), style="#ff0044")
    banner.append("║\n", style="bold #ff0044")

    banner.append("║", style="bold #ff0044")
    banner.append(f"                     v{__version__}                        ".center(56), style="bold #ffff00")
    banner.append("║\n", style="bold #ff0044")

    banner.append("╚", style="bold #ff0044")
    banner.append("═" * 56, style="bold #ff0044")
    banner.append("╝", style="bold #ff0044")

    console.print(banner)
    console.print(
        "Private • Contextual • High-signal fuzzing for real bugs\n",
        style="dim italic",
        justify="center",
    )


@app.command("scan")
def cli_scan(
    spec: Annotated[
        Path,
        typer.Argument(
            exists=True,
            dir_okay=False,
            readable=True,
            help="Path to OpenAPI YAML or JSON specification",
        ),
    ],
    model: Annotated[
        str,
        typer.Option("--model", "-m", help="Ollama model to use (must be pulled)"),
    ] = "llama3.2",
    limit: Annotated[
        int,
        typer.Option("--limit", "-l", min=1, help="Maximum tests per endpoint"),
    ] = 20,
    mutators: Annotated[
        Optional[str],
        typer.Option("--mutators", "-M", help="Comma-separated mutators (or 'all')"),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run/--execute",
            help="Generate tests only (safe default)",
        ),
    ] = True,
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Directory for reports and repro files"),
    ] = None,
) -> None:
    """Parse an OpenAPI spec, generate LLM-driven security tests, and run them.

    Uses safe defaults: dry-run mode, host allow-list, and non-destructive
    mutations. All HTTP traffic respects rate limits.
    """
    _print_banner()

    console.print(
        f"📡 Loading OpenAPI spec: [bold]{spec}[/bold]",
        style="#ffff00",
    )
    console.print(f"🧠 Model          : [bold]{model}[/bold]", style="#ff0044")
    console.print(f"🎯 Limit          : [bold]{limit}[/bold]", style="#ff0044")
    console.print(f"🛡️  Dry run        : [bold]{dry_run}[/bold]", style="#ff0044")

    mutator_list: Optional[List[str]] = None
    if mutators:
        mutator_list = [m.strip() for m in mutators.split(",")]

    output_dir = str(output) if output else "fuzz-reports"

    try:
        results = scan(
            spec_path=str(spec),
            model=model,
            limit=limit,
            mutators=mutator_list,
            dry_run=dry_run,
            output_dir=output_dir,
        )

        console.print("\n", style="bold #ffff00")
        console.print(Panel.fit(
            f"[bold #ffff00]SCAN COMPLETE[/bold #ffff00]\n"
            f"• Generated [bold]{len(results)}[/bold] intelligent test cases\n"
            f"• Reports written to [bold]{output_dir}[/bold]",
            border_style="#ff0044",
            padding=(1, 4),
        ))

        # Summary table
        table = Table(
            title="Top Findings",
            border_style="#ff0044",
            title_style="bold #ffff00",
            show_lines=True,
        )
        table.add_column("Endpoint", style="#ffff00", no_wrap=True)
        table.add_column("Risk", justify="center")
        table.add_column("Tags", style="bright_blue")

        # Display first 6 results (real data supplied by core)
        displayed = 0
        for result in results:
            if displayed >= 6:
                break
            risk = getattr(result, "risk_score", "MED")
            tags = ", ".join(getattr(result, "tags", ["unknown"])) or "—"
            endpoint = f"{getattr(result, 'endpoint', '—')}"
            table.add_row(endpoint, risk, tags)
            displayed += 1

        if displayed == 0:
            table.add_row("—", "—", "No results (dry-run or empty spec)")

        console.print(table)

        console.print(
            "\n💡 Tip: Run with --execute to send real requests. "
            "Use --help for more options.",
            style="dim",
        )

    except Exception as exc:  # pylint: disable=broad-except
        console.print(f"\n[bold red]ERROR:[/bold red] {exc}", style="#ff0044")
        raise typer.Exit(1) from exc


@app.command("init")
def cli_init(
    spec: Annotated[
        Path,
        typer.Argument(
            exists=True,
            dir_okay=False,
            readable=True,
            help="OpenAPI spec to base configuration on",
        ),
    ],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Path for generated config file"),
    ] = Path("fuzzforge.toml"),
) -> None:
    """Generate a ready-to-edit fuzzforge.toml configuration file.

    The config includes safe defaults, your chosen model, rate limits,
    and an allow-list for hosts.
    """
    _print_banner()

    console.print("🔧 Initializing project configuration...", style="#ffff00")

    config_content = f'''# Fuzz Forge Configuration
# Generated from: {spec.name}

model = "{model}"
limit = 20
dry_run = true
rate_limit_rps = 5
allowed_hosts = ["localhost", "127.0.0.1", "example.com"]

enabled_mutators = [
    "injection",
    "auth_bypass",
    "logic",
]

[reporting]
output_dir = "fuzz-reports"
formats = ["html", "json"]
include_curl = true
'''

    output.write_text(config_content, encoding="utf-8")

    console.print(Panel(
        f"[bold #ffff00]✓ Created[/bold #ffff00] [bold]{output}[/bold]\n\n"
        "Next steps:\n"
        "  1. Edit fuzzforge.toml (model, hosts, mutators)\n"
        f"  2. [bold]fuzzforge scan {spec} --dry-run=false[/bold]",
        title="Configuration ready",
        border_style="#ffff00",
        padding=(1, 2),
    ))

    console.print(
        "Pull the model if needed: [bold]ollama pull llama3.2[/bold]",
        style="dim",
    )


if __name__ == "__main__":
    app()
