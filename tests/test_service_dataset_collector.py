from pathlib import Path

from endpoint_investigator.collectors.service_dataset import DatasetServiceCollector

FIXTURE = Path(__file__).parent / "fixtures" / "services_sample.txt"


def test_dataset_collector_parses_services():
    services = DatasetServiceCollector(FIXTURE).collect()

    assert len(services) == 2
    by_name = {s.name: s for s in services}

    ssh = by_name["ssh.service"]
    assert ssh.active == "running"
    assert ssh.user == "root"
    assert ssh.exec_start == "/usr/sbin/sshd -D"
    assert ssh.source == "dataset"

    backup = by_name["backup-agent.service"]
    assert backup.exec_start == "/bin/bash /opt/backup/backup.sh"
