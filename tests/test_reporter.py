from rich.console import Console

from endpoint_investigator.evidence.models import Finding
from endpoint_investigator.reporter.console import render_findings


def test_render_findings_sem_achados():
    console = Console(record=True, width=100)

    render_findings([], console=console)

    assert "nenhum achado" in console.export_text()


def test_render_findings_mostra_campos_do_achado():
    finding = Finding(
        rule="regra_teste",
        severity="high",
        confidence="high",
        evidence="evidencia x",
        interpretation="interpretacao y",
        hypothesis="hipotese z",
        missing_evidence="falta w",
    )
    console = Console(record=True, width=100)

    render_findings([finding], console=console)

    output = console.export_text()
    assert "regra_teste" in output
    assert "evidencia x" in output
    assert "interpretacao y" in output
    assert "hipotese z" in output
    assert "falta w" in output
    assert "HIGH" in output
