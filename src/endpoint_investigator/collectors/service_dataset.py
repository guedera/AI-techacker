from pathlib import Path

from endpoint_investigator.collectors.base import ServiceCollector
from endpoint_investigator.normalizer.models import Service


class DatasetServiceCollector(ServiceCollector):
    """Le servicos a partir do services.txt que o generate_dataset.py cria."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def collect(self) -> list[Service]:
        lines = self._path.read_text().splitlines()[1:]  # pula a linha de cabecalho

        services: list[Service] = []
        for line in lines:
            if not line.strip():
                continue
            name, active, user, exec_start = line.split(maxsplit=3)
            services.append(
                Service(name=name, active=active, user=user, exec_start=exec_start, source="dataset")
            )
        return services
