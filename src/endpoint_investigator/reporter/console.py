from rich.console import Console
from rich.panel import Panel

from endpoint_investigator.evidence.models import Finding

SEVERITY_COLORS = {"info": "cyan", "low": "green", "medium": "yellow", "high": "red"}


def render_findings(findings: list[Finding], console: Console | None = None) -> None:
    console = console or Console()

    if not findings:
        console.print("[green]nenhum achado nessa coleta[/green]")
        return

    for finding in findings:
        color = SEVERITY_COLORS.get(finding.severity, "white")
        title = (
            f"[{color}]{finding.severity.upper()}[/{color}] {finding.rule} "
            f"(confianca: {finding.confidence})"
        )
        body = (
            f"[bold]evidencia:[/bold] {finding.evidence}\n\n"
            f"[bold]interpretacao:[/bold] {finding.interpretation}\n\n"
            f"[bold]hipotese:[/bold] {finding.hypothesis}\n\n"
            f"[bold]evidencia ausente:[/bold] {finding.missing_evidence}"
        )
        console.print(Panel(body, title=title, border_style=color, title_align="left"))
