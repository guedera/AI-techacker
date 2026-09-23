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


def _writable_finding(
    service: Service, path: str, perm: FileResource, *, scope: str, severity: str, confidence: str
) -> Finding:
    return Finding(
        rule="servico_privilegiado_arquivo_gravavel",
        severity=severity,
        confidence=confidence,
        evidence=(
            f"Servico {service.name} roda como root e executa {path}, "
            f"que tem permissao {perm.mode} (dono {perm.owner}:{perm.group})."
        ),
        interpretation=f"O arquivo usado pelo servico privilegiado pode ser alterado por {scope}.",
        hypothesis=(
            "Se algum desses usuarios alterar o arquivo, o conteudo passa a rodar com "
            "privilegio de root na proxima vez que o servico executar."
        ),
        missing_evidence=(
            "Nao ha confirmacao de que o arquivo foi de fato alterado por um usuario sem "
            "privilegio, nem de execucao logo depois de uma alteracao suspeita. Precisaria de "
            "auditoria de escrita (ex: auditd), historico de hash, ou a lista de membros do "
            f"grupo {perm.group} pra saber quem realmente tem acesso."
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
                        service, path, perm,
                        scope="qualquer usuario do sistema",
                        severity="high",
                        confidence="high",
                    )
                )
            elif _is_group_writable(perm.mode):
                findings.append(
                    _writable_finding(
                        service, path, perm,
                        scope=f"usuarios do grupo {perm.group}",
                        severity="medium",
                        confidence="low",
                    )
                )
    return findings


def find_privilege_escalation_in_tree(snapshot: Snapshot) -> list[Finding]:
    """Regra: processo root com pai rodando como usuario sem privilegio.

    Se o processo usa um mecanismo de elevacao conhecido (sudo/su/pkexec), e o caminho
    esperado: severidade baixa, confianca alta de que e legitimo. Sem um mecanismo
    conhecido, a subida de privilegio e incomum: severidade alta, confianca baixa sobre
    a intencao (a gente so sabe que aconteceu, nao o motivo).
    """
    findings: list[Finding] = []
    for process in snapshot.processes:
        parent = snapshot.parent_of(process)
        if parent is None or process.user != "root" or parent.user == "root":
            continue

        if process.executable in KNOWN_ELEVATION_TOOLS:
            severity, confidence = "low", "high"
            interpretation = (
                f"O processo usa {process.executable}, um mecanismo padrao de elevacao de "
                "privilegio. E o caminho esperado pra um usuario comum rodar algo como root."
            )
        else:
            severity, confidence = "high", "low"
            interpretation = (
                "O processo passou a rodar como root sem vir de um mecanismo de elevacao "
                "conhecido (sudo/su/pkexec). Isso e incomum e merece mais atencao."
            )

        findings.append(
            Finding(
                rule="processo_root_com_pai_nao_privilegiado",
                severity=severity,
                confidence=confidence,
                evidence=(
                    f"Processo {process.pid} ({process.cmd}) roda como root, mas o pai "
                    f"{parent.pid} ({parent.cmd}) roda como {parent.user}."
                ),
                interpretation=interpretation,
                hypothesis=(
                    "O processo pode ter sido iniciado por um mecanismo legitimo de elevacao "
                    "configurado no sistema, ou representar uma escalada indevida caso o "
                    "usuario nao tivesse permissao pra isso."
                ),
                missing_evidence=(
                    "Falta confirmar se o usuario tinha autorizacao pra essa elevacao (ex: "
                    "entrada no sudoers) e o log de autenticacao correspondente."
                ),
            )
        )
    return findings


def run_all(snapshot: Snapshot) -> list[Finding]:
    return [
        *find_privileged_service_writable_file(snapshot),
        *find_privilege_escalation_in_tree(snapshot),
    ]
