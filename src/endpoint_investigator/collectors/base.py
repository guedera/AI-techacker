from abc import ABC, abstractmethod

from endpoint_investigator.normalizer.models import Process


class ProcessCollector(ABC):
    """Interface comum para coleta de processos, independente da fonte (sistema real ou dataset)."""

    @abstractmethod
    def collect(self) -> list[Process]:
        ...
