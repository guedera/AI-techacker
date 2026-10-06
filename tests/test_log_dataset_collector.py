from pathlib import Path

from endpoint_investigator.collectors.log_dataset import DatasetLogCollector

FIXTURE = Path(__file__).parent / "fixtures" / "journal_sample.log"


def test_dataset_collector_parses_log_lines_and_skips_broken_ones():
    events = DatasetLogCollector(FIXTURE).collect()

    assert len(events) == 4  # a linha quebrada fica de fora

    first = events[0]
    assert first.program == "systemd"
    assert first.pid == 1
    assert first.message.startswith("Started ssh.service")
    assert first.source == "dataset"
    assert (first.timestamp.year, first.timestamp.month, first.timestamp.day) == (2026, 9, 14)
    assert first.timestamp.utcoffset().total_seconds() == -3 * 3600


def test_dataset_collector_reads_pid_of_the_service_logs():
    events = DatasetLogCollector(FIXTURE).collect()

    backup_events = [e for e in events if e.program == "backup-agent"]

    assert [e.pid for e in backup_events] == [2417, 2417]
    assert backup_events[0].message == "backup job started"
