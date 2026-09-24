from dataclasses import dataclass, field

from endpoint_investigator.normalizer.models import FileResource, Process, Service

# quando o executavel de um processo e um desses, o arquivo que interessa de
# verdade pra analise de permissao esta nos argumentos, nao no executavel
INTERPRETERS = {"/bin/bash", "/bin/sh", "/usr/bin/python3", "/usr/bin/python"}


def resource_paths(process: Process) -> list[str]:
    """Executavel do processo, mais o script que ele roda quando o executavel e um interpretador.

    Fica fora da classe Snapshot de proposito: pra montar um snapshot do sistema real a gente
    precisa saber quais paths pedir pro collector de permissao antes de ter as permissoes ainda.
    """
    paths = [process.executable] if process.executable else []
    if process.executable in INTERPRETERS:
        paths.extend(a for a in process.args if a.startswith("/"))
    return paths


@dataclass
class Snapshot:
    """Junta processos, permissoes e servicos de uma coleta e da uns lookups prontos entre eles."""

    processes: list[Process]
    permissions: list[FileResource]
    services: list[Service]
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
