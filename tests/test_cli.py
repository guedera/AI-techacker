import shutil
from pathlib import Path

from endpoint_investigator.cli import load_snapshot_from_dataset

FIXTURES = Path(__file__).parent / "fixtures"


def _copy_dataset(dest: Path, *, with_journal: bool) -> None:
    shutil.copy(FIXTURES / "snapshot_processes.csv", dest / "processes.csv")
    shutil.copy(FIXTURES / "snapshot_permissions.csv", dest / "permissions.csv")
    shutil.copy(FIXTURES / "snapshot_services.txt", dest / "services.txt")
    if with_journal:
        shutil.copy(FIXTURES / "journal_sample.log", dest / "journal.log")


def test_load_snapshot_from_dataset_reads_the_journal(tmp_path):
    _copy_dataset(tmp_path, with_journal=True)

    snapshot = load_snapshot_from_dataset(tmp_path)

    assert len(snapshot.logs) == 4


def test_load_snapshot_from_dataset_works_without_a_journal(tmp_path):
    _copy_dataset(tmp_path, with_journal=False)

    snapshot = load_snapshot_from_dataset(tmp_path)

    assert snapshot.logs == []
    assert len(snapshot.processes) == 3
