from endpoint_investigator.correlator.rules import (
    find_privilege_escalation_in_tree,
    find_privileged_service_writable_file,
    run_all,
)
from endpoint_investigator.normalizer.models import FileResource, Process, Service
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
