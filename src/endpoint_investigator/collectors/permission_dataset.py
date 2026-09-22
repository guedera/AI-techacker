import csv
from collections.abc import Iterable
from pathlib import Path

from endpoint_investigator.collectors.base import PermissionCollector
from endpoint_investigator.normalizer.models import FileResource


class DatasetPermissionCollector(PermissionCollector):
    """Le permissoes a partir do permissions.csv que o generate_dataset.py cria."""

    def __init__(self, csv_path: Path) -> None:
        self._csv_path = csv_path

    def collect(self, paths: Iterable[str] | None = None) -> list[FileResource]:
        wanted = set(paths) if paths is not None else None

        resources: list[FileResource] = []
        with self._csv_path.open(newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                if wanted is not None and row["path"] not in wanted:
                    continue
                resources.append(
                    FileResource(
                        path=row["path"],
                        type=row["type"],
                        owner=row["owner"],
                        group=row["group"],
                        mode=row["mode"],
                        mtime=row.get("mtime"),
                        source="dataset",
                    )
                )
        return resources
