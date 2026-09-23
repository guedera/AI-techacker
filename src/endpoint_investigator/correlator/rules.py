from endpoint_investigator.evidence.models import Finding
from endpoint_investigator.normalizer.snapshot import Snapshot

WORLD_WRITE_BIT = 0o2


def _is_world_writable(mode: str) -> bool:
    return int(mode[-1], 8) & WORLD_WRITE_BIT != 0


def find_privileged_service_writable_file(snapshot: Snapshot) -> list[Finding]:
    """Regra: servico root que executa um arquivo com escrita liberada pra qualquer usuario."""
    findings: list[Finding] = []
    for service in snapshot.services:
        if service.user != "root":
            continue
        for path in snapshot.files_of_service(service):
            perm = snapshot.permission(path)
            if perm is None or not _is_world_writable(perm.mode):
                continue
            findings.append(
                Finding(
                    rule="servico_privilegiado_arquivo_gravavel",
                    severity="high",
                    evidence=(
                        f"Servico {service.name} roda como root e executa {path}, "
                        f"que tem permissao {perm.mode} (dono {perm.owner}:{perm.group})."
                    ),
                    interpretation=(
                        "O arquivo usado pelo servico privilegiado pode ser alterado por "
                        "qualquer usuario do sistema, ja que tem escrita liberada pra outros."
                    ),
                    hypothesis=(
                        "Um usuario sem privilegio poderia alterar esse arquivo e ter o "
                        "conteudo executado com privilegio de root na proxima rodada do servico."
                    ),
                    missing_evidence=(
                        "Nao ha confirmacao de que o arquivo foi de fato alterado por algum "
                        "usuario nao privilegiado, nem de execucao logo depois de uma alteracao "
                        "suspeita. Precisaria de auditoria de escrita (ex: auditd) ou historico de hash."
                    ),
                )
            )
    return findings


def find_privilege_escalation_in_tree(snapshot: Snapshot) -> list[Finding]:
    """Regra: processo root com pai rodando como usuario sem privilegio."""
    findings: list[Finding] = []
    for process in snapshot.processes:
        parent = snapshot.parent_of(process)
        if parent is None:
            continue
        if process.user == "root" and parent.user != "root":
            findings.append(
                Finding(
                    rule="processo_root_com_pai_nao_privilegiado",
                    severity="medium",
                    evidence=(
                        f"Processo {process.pid} ({process.cmd}) roda como root, mas o pai "
                        f"{parent.pid} ({parent.cmd}) roda como {parent.user}."
                    ),
                    interpretation=(
                        "Uma mudanca de privilegio de usuario comum pra root na cadeia "
                        "pai-filho pode vir de um mecanismo de elevacao (sudo, su, setuid) "
                        "ou, dependendo do caso, de um escalonamento indevido."
                    ),
                    hypothesis=(
                        "O processo pode ter sido iniciado por um mecanismo legitimo de "
                        "elevacao configurado no sistema, ou representar uma escalada indevida "
                        "caso o usuario nao tivesse permissao pra isso."
                    ),
                    missing_evidence=(
                        "Falta confirmar se o usuario tinha autorizacao pra essa elevacao "
                        "(ex: entrada no sudoers) e o log de autenticacao correspondente."
                    ),
                )
            )
    return findings


def run_all(snapshot: Snapshot) -> list[Finding]:
    return [
        *find_privileged_service_writable_file(snapshot),
        *find_privilege_escalation_in_tree(snapshot),
    ]
