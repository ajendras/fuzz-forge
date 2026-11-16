#!/usr/bin/env python3
"""Basic runnable demo of Fuzz Forge.

Scans a minimal Petstore-like API spec using the local LLM (or fallback)
and prints a summary of generated security tests.
"""

from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from fuzzforge import scan

console = Console()


def main() -> None:
    """Run a self-contained demo scan against a temporary Petstore spec."""
    console.print(Panel.fit(
        "[bold #ffff00]FUZZ FORGE BASIC EXAMPLE[/bold #ffff00]",
        border_style="#ff0044",
    ))

    # Create a temporary petstore spec for the demo (no external files required)
    spec_content = """openapi: 3.0.3
info:
  title: Petstore
  version: 1.0.0
paths:
  /pets:
    get:
      summary: List all pets
      operationId: listPets
    post:
      summary: Create a pet
      operationId: createPet
  /pets/{petId}:
    get:
      summary: Info for a specific pet
      operationId: showPetById
"""

    spec_path = Path("examples") / "petstore.yaml"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text(spec_content, encoding="utf-8")

    console.print(f"📄 Using spec: [bold]{spec_path}[/bold]", style="#ffff00")
    console.print("🧠 Model          : [bold]llama3.2[/bold]", style="#ff0044")
    console.print("🛡️  Dry run        : [bold]True[/bold] (safe demo)", style="#ff0044")

    try:
        results = scan(
            spec_path=str(spec_path),
            model="llama3.2",
            limit=8,
            dry_run=True,
            output_dir="fuzz-reports-demo",
        )

        console.print(Panel(
            f"[bold #ffff00]SCAN COMPLETE[/bold #ffff00]\n"
            f"Generated [bold]{len(results)}[/bold] contextual test cases\n"
            f"Reports available in [bold]fuzz-reports-demo[/bold]",
            border_style="#ff0044",
        ))

        console.print("\n[bold #ffff00]Top Findings:[/bold #ffff00]")
        for result in results[:5]:
            tc = result.test_case
            console.print(
                f"• [bold]{tc.endpoint}[/bold]  risk=[bold]{result.risk_score}[/bold]  "
                f"tags={tc.tags}",
                style="#ff0044",
            )
            if result.findings:
                console.print(f"   → {result.findings[0]}", style="dim")

    except Exception as exc:  # pylint: disable=broad-except
        console.print(f"[red]Demo failed: {exc}[/red]")
        console.print("Make sure Ollama is running or the model is available.")
    finally:
        if spec_path.exists():
            spec_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
