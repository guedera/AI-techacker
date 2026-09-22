import csv
import shlex
from pathlib import Path

from endpoint_investigator.collectors.base import ProcessCollector
from endpoint_investigator.normalizer.models import Process


class DatasetProcessCollector(ProcessCollector):
    """Le um snapshot de processos a partir do processes.csv gerado por generate_dataset.py."""

    def __init__(self, csv_path: Path) -> None:
        self._csv_path = csv_path

    def collect(self) -> list[Process]:
        processes: list[Process] = []
        with self._csv_path.open(newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                processes.append(self._to_process(row))
        return processes

    @staticmethod
    def _to_process(row: dict[str, str]) -> Process:
        cmd = row["cmd"]
        try:
            parts = shlex.split(cmd) if cmd else []
        except ValueError:
            parts = cmd.split()

        return Process(
            pid=int(row["pid"]),
            ppid=int(row["ppid"]),
            user=row["user"],
            state=row["stat"],
            cmd=cmd,
            executable=parts[0] if parts else None,
            args=parts[1:],
            timestamp=row.get("timestamp"),
            source="dataset",
        )
