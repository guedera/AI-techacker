from pathlib import Path

from endpoint_investigator.collectors.permission_dataset import DatasetPermissionCollector
from endpoint_investigator.collectors.process_dataset import DatasetProcessCollector
from endpoint_investigator.collectors.service_dataset import DatasetServiceCollector
from endpoint_investigator.normalizer.snapshot import Snapshot

FIXTURES = Path(__file__).parent / "fixtures"


def _load_snapshot() -> Snapshot:
    processes = DatasetProcessCollector(FIXTURES / "snapshot_processes.csv").collect()
    permissions = DatasetPermissionCollector(FIXTURES / "snapshot_permissions.csv").collect()
    services = DatasetServiceCollector(FIXTURES / "snapshot_services.txt").collect()
    return Snapshot(processes=processes, permissions=permissions, services=services)


def test_parent_and_children():
    snapshot = _load_snapshot()
    sshd = snapshot.process(612)
    init = snapshot.process(1)

    assert snapshot.parent_of(sshd).pid == 1
    assert {p.pid for p in snapshot.children_of(init)} == {612, 2417}


def test_process_for_service():
    snapshot = _load_snapshot()
    backup_service = next(s for s in snapshot.services if s.name == "backup-agent.service")

    process = snapshot.process_for_service(backup_service)

    assert process is not None
    assert process.pid == 2417


def test_process_for_service_sem_match():
    snapshot = _load_snapshot()
    fake_service = next(s for s in snapshot.services if s.name == "ssh.service").model_copy(
        update={"exec_start": "/nao/existe"}
    )

    assert snapshot.process_for_service(fake_service) is None


def test_paths_of_interest_segue_o_interpretador():
    snapshot = _load_snapshot()
    backup_process = snapshot.process(2417)

    assert snapshot.paths_of_interest(backup_process) == ["/bin/bash", "/opt/backup/backup.sh"]


def test_paths_of_interest_sem_interpretador():
    snapshot = _load_snapshot()
    sshd = snapshot.process(612)

    assert snapshot.paths_of_interest(sshd) == ["/usr/sbin/sshd"]


def test_files_of_service_e_permission_lookup():
    snapshot = _load_snapshot()
    backup_service = next(s for s in snapshot.services if s.name == "backup-agent.service")

    files = snapshot.files_of_service(backup_service)
    script_permission = snapshot.permission("/opt/backup/backup.sh")

    assert "/opt/backup/backup.sh" in files
    assert script_permission.mode == "0777"
