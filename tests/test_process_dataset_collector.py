from pathlib import Path
from endpoint_investigator.collectors.process_dataset import DatasetProcessCollector

FIXTURE = Path(__file__).parent / "fixtures" / "processes_sample.csv"

def test_dataset_collector_parses_rows():
    processes = DatasetProcessCollector(FIXTURE).collect()

    assert len(processes) == 3
    by_pid = {p.pid: p for p in processes}

    init = by_pid[1]
    assert init.ppid == 0
    assert init.user == "root"
    assert init.source == "dataset"
    assert init.executable == "/sbin/init"

    sshd = by_pid[612]
    assert sshd.executable == "/usr/sbin/sshd"
    assert sshd.args == ["-D"]

    apache = by_pid[733]
    assert apache.args == ["-k", "start"]
    assert apache.user == "www-data"
