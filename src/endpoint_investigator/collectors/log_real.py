import subprocess
from collections.abc import Callable
from datetime import datetime, timezone

from endpoint_investigator.collectors.base import LogCollector
from endpoint_investigator.collectors.log_line import split_program_message
from endpoint_investigator.normalizer.models import LogEvent


def _run(args: list[str]) -> str:
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout


class JournalCollector(LogCollector):
    """Le os ultimos eventos do journal do systemd (journalctl) do boot atual.

    Se nao tiver journalctl ou der erro, devolve lista vazia: os logs so reforcam a
    evidencia, a investigacao segue sem eles.
    """

    def __init__(self, runner: Callable[[list[str]], str] = _run, limit: int = 20000) -> None:
        self._runner = runner
        self._limit = limit

    def collect(self) -> list[LogEvent]:
        try:
            # -b: so o boot atual, porque PIDs se repetem entre boots
            raw = self._runner(
                ["journalctl", "-b", "-o", "short-iso", "--no-pager", "-n", str(self._limit)]
            )
        except (subprocess.CalledProcessError, OSError):
            return []

        events: list[LogEvent] = []
        for line in raw.splitlines():
            event = self._to_event(line)
            if event is not None:
                events.append(event)
        return events

    @staticmethod
    def _to_event(line: str) -> LogEvent | None:
        # formato: "2026-10-05T16:02:11-0300 kaliguedes sudo[20590]: guedes : TTY=pts/0 ..."
        parts = line.split(maxsplit=2)
        if len(parts) < 3:
            return None
        raw_time, _host, rest = parts

        parsed = split_program_message(rest)
        if parsed is None:
            return None
        try:
            when = datetime.fromisoformat(raw_time)
        except ValueError:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)

        program, pid, message = parsed
        return LogEvent(timestamp=when, program=program, pid=pid, message=message, source="real")
