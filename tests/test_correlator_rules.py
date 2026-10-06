from datetime import datetime, timedelta, timezone

from endpoint_investigator.correlator.rules import (
    find_privilege_escalation_in_tree,
    find_privileged_service_writable_file,
    run_all,
)
from endpoint_investigator.normalizer.models import FileResource, LogEvent, Process, Service
from endpoint_investigator.normalizer.snapshot import Snapshot


def _process(pid: int, ppid: int, user: str, cmd: str) -> Process:
    parts = cmd.split()
    return Process(
        pid=pid,
        ppid=ppid,
        user=user,
        state="S",
        cmd=cmd,
        executable=parts[0],
        args=parts[1:],
        source="dataset",
    )


def test_regra_servico_root_com_arquivo_world_writable_dispara():
    processes = [_process(2417, 1, "root", "/bin/bash /opt/backup/backup.sh")]
    services = [
        Service(
            name="backup-agent.service",
            active="running",
            user="root",
            exec_start="/bin/bash /opt/backup/backup.sh",
            source="dataset",
        )
    ]
    permissions = [
        FileResource(
            path="/opt/backup/backup.sh", type="file", owner="root", group="root", mode="0777", source="dataset"
        )
    ]
    snapshot = Snapshot(processes=processes, permissions=permissions, services=services)

    findings = find_privileged_service_writable_file(snapshot)

    assert len(findings) == 1
    assert findings[0].rule == "servico_privilegiado_arquivo_gravavel"
    assert findings[0].severity == "high"
    assert findings[0].confidence == "high"


def test_regra_servico_root_com_arquivo_gravavel_so_pelo_grupo_e_menos_grave():
    processes = [_process(2417, 1, "root", "/bin/bash /opt/backup/backup.sh")]
    services = [
        Service(
            name="backup-agent.service",
            active="running",
            user="root",
            exec_start="/bin/bash /opt/backup/backup.sh",
            source="dataset",
        )
    ]
    permissions = [
        FileResource(
            path="/opt/backup/backup.sh", type="file", owner="root", group="backup", mode="0770", source="dataset"
        )
    ]
    snapshot = Snapshot(processes=processes, permissions=permissions, services=services)

    findings = find_privileged_service_writable_file(snapshot)

    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].confidence == "low"


def test_regra_servico_root_com_arquivo_restrito_nao_dispara():
    processes = [_process(2417, 1, "root", "/bin/bash /opt/backup/backup.sh")]
    services = [
        Service(
            name="backup-agent.service",
            active="running",
            user="root",
            exec_start="/bin/bash /opt/backup/backup.sh",
            source="dataset",
        )
    ]
    permissions = [
        FileResource(
            path="/opt/backup/backup.sh", type="file", owner="root", group="root", mode="0700", source="dataset"
        )
    ]
    snapshot = Snapshot(processes=processes, permissions=permissions, services=services)

    assert find_privileged_service_writable_file(snapshot) == []


def test_regra_servico_nao_privilegiado_nao_dispara():
    processes = [_process(744, 733, "www-data", "/usr/sbin/apache2 -k start")]
    services = [
        Service(
            name="apache2.service",
            active="running",
            user="www-data",
            exec_start="/usr/sbin/apache2 -k start",
            source="dataset",
        )
    ]
    permissions = [
        FileResource(
            path="/usr/sbin/apache2", type="file", owner="root", group="root", mode="0777", source="dataset"
        )
    ]
    snapshot = Snapshot(processes=processes, permissions=permissions, services=services)

    assert find_privileged_service_writable_file(snapshot) == []


def test_regra_escalonamento_de_privilegio_dispara():
    processes = [
        _process(1212, 612, "aluno", "/bin/bash"),
        _process(5000, 1212, "root", "/usr/bin/sudo /bin/whoami"),
    ]
    snapshot = Snapshot(processes=processes, permissions=[], services=[])

    findings = find_privilege_escalation_in_tree(snapshot)

    assert len(findings) == 1
    assert findings[0].rule == "processo_root_com_pai_nao_privilegiado"
    assert findings[0].severity == "low"  # sudo e o caminho esperado
    assert findings[0].confidence == "high"


def test_regra_escalonamento_reconhece_sudo_no_pai_via_fork():
    # padrao real do sudo: ele faz fork, o pai fica como usuario comum e o
    # filho ja e o comando final rodando como root (sem "sudo" no proprio executavel)
    processes = [
        _process(9004, 1212, "aluno", "/usr/bin/sudo /home/aluno/uv run algo"),
        _process(9005, 9004, "root", "/home/aluno/.local/bin/uv run algo"),
    ]
    snapshot = Snapshot(processes=processes, permissions=[], services=[])

    findings = find_privilege_escalation_in_tree(snapshot)

    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert findings[0].confidence == "high"


def test_regra_escalonamento_sem_ferramenta_conhecida_e_mais_grave():
    processes = [
        _process(1212, 612, "aluno", "/bin/bash"),
        _process(5000, 1212, "root", "/opt/estranho/binario"),
    ]
    snapshot = Snapshot(processes=processes, permissions=[], services=[])

    findings = find_privilege_escalation_in_tree(snapshot)

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].confidence == "low"  # a gente nao sabe o motivo, so que e incomum


def test_regra_escalonamento_nao_dispara_em_drop_de_privilegio_normal():
    # root soltando uma sessao de usuario comum (sshd -> shell do aluno) e o caminho normal
    processes = [
        _process(612, 1, "root", "/usr/sbin/sshd -D"),
        _process(1212, 612, "aluno", "/bin/bash"),
    ]
    snapshot = Snapshot(processes=processes, permissions=[], services=[])

    assert find_privilege_escalation_in_tree(snapshot) == []


def test_run_all_junta_as_duas_regras():
    processes = [
        _process(1, 0, "root", "/sbin/init"),
        _process(2417, 1, "root", "/bin/bash /opt/backup/backup.sh"),
        _process(5000, 2417, "aluno", "/bin/bash"),
        _process(5001, 5000, "root", "/usr/bin/sudo /bin/id"),
    ]
    services = [
        Service(
            name="backup-agent.service",
            active="running",
            user="root",
            exec_start="/bin/bash /opt/backup/backup.sh",
            source="dataset",
        )
    ]
    permissions = [
        FileResource(
            path="/opt/backup/backup.sh", type="file", owner="root", group="root", mode="0777", source="dataset"
        )
    ]
    snapshot = Snapshot(processes=processes, permissions=permissions, services=services)

    rules_fired = {f.rule for f in run_all(snapshot)}

    assert rules_fired == {
        "servico_privilegiado_arquivo_gravavel",
        "processo_root_com_pai_nao_privilegiado",
    }


def test_regra_servico_root_dispara_com_exe_resolvido_pra_usr_bin():
    # na Kali real o cmd diz /bin/bash, mas o /proc/<pid>/exe resolve pra /usr/bin/bash
    process = Process(
        pid=2417,
        ppid=1,
        user="root",
        state="S",
        cmd="/bin/bash /opt/demo/backup.sh",
        executable="/usr/bin/bash",
        args=["/opt/demo/backup.sh"],
        source="real",
    )
    service = Service(
        name="demo-backup.service",
        active="active",
        user="root",
        exec_start="/bin/bash /opt/demo/backup.sh",
        source="real",
    )
    permission = FileResource(
        path="/opt/demo/backup.sh", type="file", owner="root", group="root", mode="0777", source="real"
    )
    snapshot = Snapshot(processes=[process], permissions=[permission], services=[service])

    findings = find_privileged_service_writable_file(snapshot)

    assert len(findings) == 1
    assert findings[0].severity == "high"


BRT = timezone(timedelta(hours=-3))


def _log(when: datetime, program: str, pid: int | None, message: str) -> LogEvent:
    return LogEvent(timestamp=when, program=program, pid=pid, message=message, source="dataset")


def _backup_snapshot(mtime: str, logs: list[LogEvent]) -> Snapshot:
    process = _process(2417, 1, "root", "/bin/bash /opt/backup/backup.sh")
    service = Service(
        name="backup-agent.service",
        active="running",
        user="root",
        exec_start="/bin/bash /opt/backup/backup.sh",
        source="dataset",
    )
    permission = FileResource(
        path="/opt/backup/backup.sh",
        type="file",
        owner="root",
        group="root",
        mode="0777",
        mtime=mtime,
        source="dataset",
    )
    return Snapshot(processes=[process], permissions=[permission], services=[service], logs=logs)


def test_regra1_linha_do_tempo_arquivo_alterado_antes_da_atividade_do_servico():
    logs = [_log(datetime(2026, 9, 14, 9, 2, 5, tzinfo=BRT), "backup-agent", 2417, "backup completed")]
    snapshot = _backup_snapshot("2026-09-13T08:59:00-03:00", logs)

    finding = find_privileged_service_writable_file(snapshot)[0]

    assert "antes desse ultimo registro" in finding.evidence
    assert "14/09/2026 09:02:05" in finding.evidence
    assert "atividade do servico depois da ultima alteracao" in finding.missing_evidence
    assert "quem alterou o arquivo" in finding.missing_evidence


def test_regra1_linha_do_tempo_arquivo_alterado_depois_da_atividade_do_servico():
    logs = [_log(datetime(2026, 9, 14, 9, 2, 5, tzinfo=BRT), "backup-agent", 2417, "backup completed")]
    snapshot = _backup_snapshot("2026-09-15T10:00:00-03:00", logs)

    finding = find_privileged_service_writable_file(snapshot)[0]

    assert "depois do ultimo registro do servico" in finding.evidence
    assert "Nao ha confirmacao de que o arquivo foi de fato alterado" in finding.missing_evidence


def test_regra1_sem_logs_diz_que_nao_encontrou_e_mantem_o_achado():
    snapshot = _backup_snapshot("2026-09-13T08:59:00-03:00", [])

    findings = find_privileged_service_writable_file(snapshot)

    assert len(findings) == 1
    assert "Nao foram encontrados logs desse servico" in findings[0].evidence
    assert findings[0].severity == "high"  # logs reforcam a evidencia, nao mudam a gravidade


def test_regra2_anexa_logs_do_processo_pai_na_evidencia():
    processes = [
        _process(1212, 612, "aluno", "/bin/bash"),
        _process(9004, 1212, "aluno", "/usr/bin/sudo /bin/id"),
        _process(9005, 9004, "root", "/bin/id"),
    ]
    logs = [_log(datetime(2026, 10, 5, 16, 2, 11, tzinfo=BRT), "sudo", 9004, "aluno : COMMAND=/bin/id")]
    snapshot = Snapshot(processes=processes, permissions=[], services=[], logs=logs)

    finding = find_privilege_escalation_in_tree(snapshot)[0]

    assert "Logs desses processos" in finding.evidence
    assert "sudo[9004]: aluno : COMMAND=/bin/id" in finding.evidence
    assert "nao provam que ele foi autorizado" in finding.missing_evidence


def test_regra2_sem_logs_avisa_que_nao_encontrou():
    processes = [
        _process(1212, 612, "aluno", "/bin/bash"),
        _process(5000, 1212, "root", "/opt/estranho/binario"),
    ]
    snapshot = Snapshot(processes=processes, permissions=[], services=[])

    finding = find_privilege_escalation_in_tree(snapshot)[0]

    assert "Nenhum log encontrado" in finding.evidence
    assert "log de autenticacao correspondente" in finding.missing_evidence
