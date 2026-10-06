from datetime import datetime, timezone

from endpoint_investigator.evidence.models import Finding
from endpoint_investigator.normalizer.models import FileResource, Service
from endpoint_investigator.normalizer.snapshot import Snapshot

WRITE_BIT = 0o2  # bit de escrita dentro de um digito octal (dono, grupo ou outros)

KNOWN_ELEVATION_TOOLS = {"/usr/bin/sudo", "/bin/su", "/usr/bin/su", "/usr/bin/pkexec"}


def _digit(mode: str, position: int) -> int:
    return int(mode[position], 8)


def _is_world_writable(mode: str) -> bool:
    return _digit(mode, -1) & WRITE_BIT != 0


def _is_group_writable(mode: str) -> bool:
    return _digit(mode, -2) & WRITE_BIT != 0


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _fmt(when: datetime) -> str:
    return when.strftime("%d/%m/%Y %H:%M:%S")


def _short(text: str, limit: int = 100) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _timeline(snapshot: Snapshot, service: Service, perm: FileResource) -> tuple[str, bool]:
    """Cruza o mtime do arquivo com os logs do servico.

    Devolve a frase pra evidencia e se os logs mostram o servico ativo depois da
    ultima alteracao do arquivo (o que sugere que ele ja rodou a versao atual).
    """
    events = snapshot.events_of_service(service)
    if not events:
        return "Nao foram encontrados logs desse servico.", False

    last = events[-1]
    text = (
        f"Logs do servico: {len(events)} registro(s), o ultimo em {_fmt(last.timestamp)} "
        f"({last.program}: {_short(last.message)})."
    )
    modified = _parse_time(perm.mtime)
    if modified is None:
        return text, False
    if modified <= last.timestamp:
        return (
            f"{text} O arquivo foi modificado pela ultima vez em {_fmt(modified)}, antes desse "
            "ultimo registro: o servico teve atividade depois da alteracao.",
            True,
        )
    return (
        f"{text} O arquivo foi modificado em {_fmt(modified)}, depois do ultimo registro do "
        "servico: a alteracao ainda nao aparece como executada.",
        False,
    )


def _writable_finding(
    snapshot: Snapshot,
    service: Service,
    path: str,
    perm: FileResource,
    *,
    scope: str,
    severity: str,
    confidence: str,
) -> Finding:
    timeline, active_after_change = _timeline(snapshot, service, perm)
    if active_after_change:
        gap = (
            "Os logs mostram atividade do servico depois da ultima alteracao, mas nao mostram "
            "quem alterou o arquivo nem o que mudou. "
        )
    else:
        gap = (
            "Nao ha confirmacao de que o arquivo foi de fato alterado por um usuario sem "
            "privilegio, nem de execucao logo depois de uma alteracao suspeita. "
        )

    return Finding(
        rule="servico_privilegiado_arquivo_gravavel",
        severity=severity,
        confidence=confidence,
        evidence=(
            f"Servico {service.name} roda como root e executa {path}, "
            f"que tem permissao {perm.mode} (dono {perm.owner}:{perm.group}). {timeline}"
        ),
        interpretation=f"O arquivo usado pelo servico privilegiado pode ser alterado por {scope}.",
        hypothesis=(
            "Se algum desses usuarios alterar o arquivo, o conteudo passa a rodar com "
            "privilegio de root na proxima vez que o servico executar."
        ),
        missing_evidence=(
            f"{gap}Precisaria de auditoria de escrita (ex: auditd), historico de hash, ou a "
            f"lista de membros do grupo {perm.group} pra saber quem realmente tem acesso."
        ),
    )


def find_privileged_service_writable_file(snapshot: Snapshot) -> list[Finding]:
    """Regra: servico root que executa um arquivo que outros usuarios conseguem alterar.

    Arquivo gravavel por qualquer um (world-writable) e o caso mais grave e mais certo.
    Gravavel so pelo grupo e mais fraco: a gente nao sabe quem esta nesse grupo, entao
    severidade e confianca ficam mais baixas.
    """
    findings: list[Finding] = []
    for service in snapshot.services:
        if service.user != "root":
            continue
        for path in snapshot.files_of_service(service):
            perm = snapshot.permission(path)
            if perm is None:
                continue
            if _is_world_writable(perm.mode):
                findings.append(
                    _writable_finding(
                        snapshot, service, path, perm,
                        scope="qualquer usuario do sistema",
                        severity="high",
                        confidence="high",
                    )
                )
            elif _is_group_writable(perm.mode):
                findings.append(
                    _writable_finding(
                        snapshot, service, path, perm,
                        scope=f"usuarios do grupo {perm.group}",
                        severity="medium",
                        confidence="low",
                    )
                )
    return findings


def find_privilege_escalation_in_tree(snapshot: Snapshot) -> list[Finding]:
    """Regra: processo root com pai rodando como usuario sem privilegio.

    Se o processo (ou o pai dele) usa um mecanismo de elevacao conhecido (sudo/su/pkexec), e
    o caminho esperado: severidade baixa, confianca alta de que e legitimo. Sem um mecanismo
    conhecido, a subida de privilegio e incomum: severidade alta, confianca baixa sobre
    a intencao (a gente so sabe que aconteceu, nao o motivo).

    Checamos tanto o processo quanto o pai porque o sudo de verdade normalmente faz fork:
    o processo sudo original fica com o pai (ainda como usuario comum), e quem vira root e
    o filho, ja rodando o comando final (sem "sudo" no proprio executavel dele). Isso foi
    descoberto rodando contra uma VM Linux de verdade, nao aparecia nos dados sinteticos.
    """
    findings: list[Finding] = []
    for process in snapshot.processes:
        parent = snapshot.parent_of(process)
        if parent is None or process.user != "root" or parent.user == "root":
            continue

        elevation_tool = process.executable if process.executable in KNOWN_ELEVATION_TOOLS else None
        if elevation_tool is None and parent.executable in KNOWN_ELEVATION_TOOLS:
            elevation_tool = parent.executable

        if elevation_tool is not None:
            severity, confidence = "low", "high"
            interpretation = (
                f"O processo (ou o pai dele) usa {elevation_tool}, um mecanismo padrao de "
                "elevacao de privilegio. E o caminho esperado pra um usuario comum rodar algo como root."
            )
        else:
            severity, confidence = "high", "low"
            interpretation = (
                "O processo passou a rodar como root sem vir de um mecanismo de elevacao "
                "conhecido (sudo/su/pkexec). Isso e incomum e merece mais atencao."
            )

        events = sorted(
            snapshot.events_of_pid(parent.pid) + snapshot.events_of_pid(process.pid),
            key=lambda e: e.timestamp,
        )
        if events:
            lines = " | ".join(
                f"{_fmt(e.timestamp)} {e.program}[{e.pid}]: {_short(e.message)}" for e in events[:3]
            )
            logs_evidence = f" Logs desses processos: {lines}."
            missing = (
                "Falta confirmar se o usuario tinha autorizacao pra essa elevacao (ex: entrada "
                "no sudoers). Os logs citados na evidencia registram o evento, mas nao provam "
                "que ele foi autorizado."
            )
        else:
            logs_evidence = " Nenhum log encontrado pra esses processos."
            missing = (
                "Falta confirmar se o usuario tinha autorizacao pra essa elevacao (ex: "
                "entrada no sudoers) e o log de autenticacao correspondente."
            )

        findings.append(
            Finding(
                rule="processo_root_com_pai_nao_privilegiado",
                severity=severity,
                confidence=confidence,
                evidence=(
                    f"Processo {process.pid} ({process.cmd}) roda como root, mas o pai "
                    f"{parent.pid} ({parent.cmd}) roda como {parent.user}.{logs_evidence}"
                ),
                interpretation=interpretation,
                hypothesis=(
                    "O processo pode ter sido iniciado por um mecanismo legitimo de elevacao "
                    "configurado no sistema, ou representar uma escalada indevida caso o "
                    "usuario nao tivesse permissao pra isso."
                ),
                missing_evidence=missing,
            )
        )
    return findings


def run_all(snapshot: Snapshot) -> list[Finding]:
    return [
        *find_privileged_service_writable_file(snapshot),
        *find_privilege_escalation_in_tree(snapshot),
    ]
