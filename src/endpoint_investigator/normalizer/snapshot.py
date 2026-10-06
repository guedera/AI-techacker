from dataclasses import dataclass, field
from pathlib import Path

from endpoint_investigator.normalizer.models import FileResource, LogEvent, Process, Service

# quando o executavel de um processo e um desses, o arquivo que interessa de
# verdade pra analise de permissao esta nos argumentos, nao no executavel
INTERPRETER_NAMES = {"bash", "sh", "dash", "zsh"}


def _is_interpreter(executable: str | None) -> bool:
    # compara so o nome: no Linux real o /proc/<pid>/exe resolve pra /usr/bin/bash
    # (ou /usr/bin/dash, /usr/bin/python3.13...), nao pro /bin/bash que aparece no cmd
    if not executable:
        return False
    name = Path(executable).name
    return name in INTERPRETER_NAMES or name.startswith("python")


def resource_paths(process: Process) -> list[str]:
    """Executavel do processo, mais o script que ele roda quando o executavel e um interpretador.

    Fica fora da classe Snapshot de proposito: pra montar um snapshot do sistema real a gente
    precisa saber quais paths pedir pro collector de permissao antes de ter as permissoes ainda.
    """
    paths = [process.executable] if process.executable else []
    if _is_interpreter(process.executable):
        paths.extend(a for a in process.args if a.startswith("/"))
    return paths


@dataclass
class Snapshot:
    """Junta processos, permissoes e servicos de uma coleta e da uns lookups prontos entre eles."""

    processes: list[Process]
    permissions: list[FileResource]
    services: list[Service]
    logs: list[LogEvent] = field(default_factory=list)
    _process_by_pid: dict[int, Process] = field(init=False, repr=False)
    _permission_by_path: dict[str, FileResource] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._process_by_pid = {p.pid: p for p in self.processes}
        self._permission_by_path = {r.path: r for r in self.permissions}

    def process(self, pid: int) -> Process | None:
        return self._process_by_pid.get(pid)

    def parent_of(self, process: Process) -> Process | None:
        return self._process_by_pid.get(process.ppid)

    def children_of(self, process: Process) -> list[Process]:
        return [p for p in self.processes if p.ppid == process.pid]

    def permission(self, path: str) -> FileResource | None:
        return self._permission_by_path.get(path)

    def paths_of_interest(self, process: Process) -> list[str]:
        return resource_paths(process)

    def process_for_service(self, service: Service) -> Process | None:
        for process in self.processes:
            if process.cmd == service.exec_start:
                return process
        return None

    def files_of_service(self, service: Service) -> list[str]:
        process = self.process_for_service(service)
        return self.paths_of_interest(process) if process else []

    def events_of_pid(self, pid: int) -> list[LogEvent]:
        return sorted((e for e in self.logs if e.pid == pid), key=lambda e: e.timestamp)

    def events_of_service(self, service: Service) -> list[LogEvent]:
        """Logs que citam o servico: pelo nome do programa, pelo nome da unit ou pelo PID dele."""
        unit = service.name.removesuffix(".service")
        process = self.process_for_service(service)
        pid = process.pid if process else None
        related = (
            e
            for e in self.logs
            if e.program == unit or service.name in e.message or (pid is not None and e.pid == pid)
        )
        return sorted(related, key=lambda e: e.timestamp)
