import os
import pwd
from pathlib import Path

from endpoint_investigator.collectors.base import ProcessCollector
from endpoint_investigator.normalizer.models import Process


class ProcCollector(ProcessCollector):
    """Le os processos rodando no sistema real, direto do /proc."""

    def __init__(self, proc_root: Path = Path("/proc")) -> None:
        self._proc_root = proc_root

    def collect(self) -> list[Process]:
        processes: list[Process] = []
        for entry in self._proc_root.iterdir():
            if not entry.name.isdigit():
                continue
            process = self._read_process(entry)
            if process is not None:
                processes.append(process)
        return processes

    def _read_process(self, pid_dir: Path) -> Process | None:
        try:
            uid, gid = self._parse_ids(pid_dir / "status")
            comm, state, ppid = self._parse_stat(pid_dir / "stat")
            cmdline_raw = (pid_dir / "cmdline").read_bytes()
        except (FileNotFoundError, PermissionError):
            # o processo pode ter morrido entre o iterdir() e a leitura, ou a gente nao tem permissao
            return None

        argv = [a for a in cmdline_raw.decode(errors="replace").split("\x00") if a]
        args = argv[1:]  # argv[0] e o executavel, nao conta como argumento

        try:
            user = pwd.getpwuid(uid).pw_name if uid is not None else "?"
        except KeyError:
            user = str(uid)

        try:
            executable = os.readlink(pid_dir / "exe")
        except (FileNotFoundError, PermissionError):
            executable = None

        return Process(
            pid=int(pid_dir.name),
            ppid=ppid,
            user=user,
            uid=uid,
            gid=gid,
            state=state,
            cmd=" ".join(argv) if argv else comm,
            executable=executable,
            args=args,
            source="real",
        )

    @staticmethod
    def _parse_ids(status_path: Path) -> tuple[int | None, int | None]:
        uid = gid = None
        for line in status_path.read_text().splitlines():
            if line.startswith("Uid:"):
                uid = int(line.split()[1])
            elif line.startswith("Gid:"):
                gid = int(line.split()[1])
        return uid, gid

    @staticmethod
    def _parse_stat(stat_path: Path) -> tuple[str, str, int]:
        # formato do /proc/<pid>/stat e "pid (comm) state ppid ...".
        # comm pode ter espaco/parenteses dentro, entao cortamos pelo ultimo ")"
        raw = stat_path.read_text()
        comm_start = raw.index("(")
        comm_end = raw.rindex(")")
        comm = raw[comm_start + 1 : comm_end]
        rest = raw[comm_end + 1 :].split()
        state, ppid = rest[0], int(rest[1])
        return comm, state, ppid
