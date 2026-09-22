from abc import ABC, abstractmethod
from collections.abc import Iterable

from endpoint_investigator.normalizer.models import FileResource, Process, Service


class ProcessCollector(ABC):
    """Interface comum pra coletar processos, seja do sistema real ou de um dataset."""

    @abstractmethod
    def collect(self) -> list[Process]:
        ...


class PermissionCollector(ABC):
    """Interface comum pra coletar permissoes de arquivo/diretorio.

    A coleta e sempre guiada por contexto (paths que vieram de processos ou
    servicos ja identificados), nunca uma varredura indiscriminada no filesystem.
    """

    @abstractmethod
    def collect(self, paths: Iterable[str] | None = None) -> list[FileResource]:
        ...


class ServiceCollector(ABC):
    """Interface comum pra coletar servicos, seja do systemd real ou de um dataset."""

    @abstractmethod
    def collect(self) -> list[Service]:
        ...
