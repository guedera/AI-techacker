import subprocess
from collections.abc import Callable

from endpoint_investigator.collectors.base import ServiceCollector
from endpoint_investigator.normalizer.models import Service


def _run(args: list[str]) -> str:
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout


class SystemdCollector(ServiceCollector):
    """Le servicos do systemd no sistema real, via systemctl.

    O runner e injetavel pra dar pra testar a logica de parsing sem precisar
    de um systemd de verdade rodando.
    """

    def __init__(self, runner: Callable[[list[str]], str] = _run) -> None:
        self._runner = runner

    def collect(self) -> list[Service]:
        services: list[Service] = []
        for unit in self._list_units():
            service = self._describe(unit)
            if service is not None:
                services.append(service)
        return services

    def _list_units(self) -> list[str]:
        raw = self._runner(
            ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain"]
        )
        return [line.split()[0] for line in raw.splitlines() if line.strip()]

    def _describe(self, unit: str) -> Service | None:
        try:
            active = self._runner(["systemctl", "show", unit, "-p", "ActiveState", "--value"]).strip()
            user = self._runner(["systemctl", "show", unit, "-p", "User", "--value"]).strip()
            unit_file = self._runner(["systemctl", "cat", unit])
        except subprocess.CalledProcessError:
            # unidade apareceu no list-units mas o systemctl nao consegue detalhar ela
            # (ex: unit "not-found"). Melhor pular do que derrubar a coleta inteira.
            return None
        return Service(
            name=unit,
            active=active,
            user=user or "root",  # sem User= no unit file, o systemd roda como root
            exec_start=self._parse_exec_start(unit_file),
            source="real",
        )

    @staticmethod
    def _parse_exec_start(unit_file: str) -> str:
        for line in unit_file.splitlines():
            if line.strip().startswith("ExecStart="):
                return line.split("=", 1)[1].strip()
        return ""
