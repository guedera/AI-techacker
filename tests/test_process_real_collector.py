import os
from pathlib import Path
from endpoint_investigator.collectors.process_real import ProcCollector

def _write_fake_process(
    proc_root: Path, pid: int, ppid: int, comm: str, uid: int, cmdline: list[str]
) -> None:
    pid_dir = proc_root / str(pid)
    pid_dir.mkdir(parents=True)
    (pid_dir / "status").write_text(
        f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
    )
    # Campos apos o comm nao usados pelo parser sao preenchidos com zeros.
    (pid_dir / "stat").write_text(f"{pid} ({comm}) S {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
    cmdline_bytes = ("\x00".join(cmdline) + "\x00").encode() if cmdline else b""
    (pid_dir / "cmdline").write_bytes(cmdline_bytes)
    os.symlink(cmdline[0] if cmdline else f"/bin/{comm}", pid_dir / "exe")


def test_proc_collector_reads_fake_proc(tmp_path):
    proc_root = tmp_path / "proc"
    proc_root.mkdir()
    _write_fake_process(proc_root, pid=1, ppid=0, comm="init", uid=0, cmdline=["/sbin/init"])
    _write_fake_process(
        proc_root, pid=612, ppid=1, comm="sshd", uid=0, cmdline=["/usr/sbin/sshd", "-D"]
    )
    (proc_root / "self").mkdir()  # entrada nao numerica deve ser ignorada

    processes = ProcCollector(proc_root=proc_root).collect()

    assert len(processes) == 2
    by_pid = {p.pid: p for p in processes}

    init = by_pid[1]
    assert init.ppid == 0
    assert init.user == "root"
    assert init.executable == "/sbin/init"
    assert init.source == "real"

    sshd = by_pid[612]
    assert sshd.args == ["-D"]
    assert sshd.state == "S"


def test_proc_collector_skips_process_that_disappears(tmp_path):
    proc_root = tmp_path / "proc"
    proc_root.mkdir()
    # Diretorio com nome de PID mas sem os arquivos internos, simulando um
    # processo que terminou entre o iterdir() e a leitura dos detalhes.
    (proc_root / "9999").mkdir()

    processes = ProcCollector(proc_root=proc_root).collect()

    assert processes == []
