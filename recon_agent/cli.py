"""CLI entrypoint for recon-agent."""
import click
import sys
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from .pipeline import run_pipeline
from .triage import triage_with_llm
from .report import generate_report

console = Console()


@click.command()
@click.option("--scope", "-s", required=True, help="Target domain (e.g. example.com)")
@click.option("--output", "-o", default=None, help="Output file path (.md). Defaults to stdout.")
@click.option("--severity", default="medium,high,critical", help="Nuclei severity filter")
@click.option("--provider", default="ollama", type=click.Choice(["ollama", "groq"]), help="LLM provider for triage")
@click.option("--model", default="llama3", help="Model name (for Ollama)")
@click.option("--no-triage", is_flag=True, default=False, help="Skip AI triage, dump raw findings")
def main(scope: str, output: str | None, severity: str, provider: str, model: str, no_triage: bool):
    """
    recon-agent — AI-powered bug bounty recon.

    From scope to prioritized findings in one command.

    Example:

        recon-agent --scope example.com --output report.md
    """
    console.print(f"\n[bold cyan]recon-agent[/bold cyan] targeting [bold]{scope}[/bold]\n")

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        t1 = progress.add_task("Running Subfinder...", total=None)
        t2 = progress.add_task("Running Httpx...", total=None, visible=False)
        t3 = progress.add_task("Running Nuclei...", total=None, visible=False)
        t4 = progress.add_task("AI triage...", total=None, visible=False)

        result = run_pipeline(scope, severity)
        progress.update(t1, description=f"[green]Subfinder: {len(result.subdomains)} subdomains", completed=True)

        progress.update(t2, visible=True)
        progress.update(t2, description=f"[green]Httpx: {len(result.live_hosts)} live hosts", completed=True)

        progress.update(t3, visible=True)
        progress.update(t3, description=f"[green]Nuclei: {len(result.findings)} raw findings", completed=True)

        if no_triage:
            triaged = result.findings
        else:
            progress.update(t4, visible=True)
            triaged = triage_with_llm(result.findings, provider=provider, model=model)
            progress.update(t4, description=f"[green]Triage: {len(triaged)} real findings", completed=True)

    if result.errors:
        for err in result.errors:
            console.print(f"[yellow]Warning: {err}[/yellow]")

    console.print(f"\n[bold]Results:[/bold] {len(result.subdomains)} subdomains → {len(result.live_hosts)} live → [bold red]{len(triaged)} findings[/bold red]\n")

    report = generate_report(scope, result.subdomains, result.live_hosts, triaged)

    if output:
        Path(output).write_text(report, encoding="utf-8")
        console.print(f"[green]Report saved: {output}[/green]")
    else:
        print(report)


if __name__ == "__main__":
    main()
