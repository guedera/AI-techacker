from datetime import datetime, timedelta, timezone
from pathlib import Path

from endpoint_investigator.collectors.base import LogCollector
from endpoint_investigator.collectors.log_line import split_program_message
from endpoint_investigator.normalizer.models import LogEvent

# o journal.log do gerador nao traz ano, e o gerador fixa o inicio em 2026-09-14.
# Os outros arquivos do dataset marcam as horas com -03:00, entao usamos o mesmo aqui.
DATASET_YEAR = 2026
DATASET_TZ = timezone(timedelta(hours=-3))


class DatasetLogCollector(LogCollector):
    """Le os eventos do journal.log que o generate_dataset.py cria."""

    def __init__(self, path: Path, year: int = DATASET_YEAR) -> None:
        self._path = path
        self._year = year

    def collect(self) -> list[LogEvent]:
        events: list[LogEvent] = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            event = self._to_event(line)
            if event is not None:
                events.append(event)
        return events

    def _to_event(self, line: str) -> LogEvent | None:
        # formato: "Sep 14 09:02:03 srv-app-01 backup-agent[2417]: backup job started"
        parts = line.split(maxsplit=4)
        if len(parts) < 5:
            return None
        month, day, clock, _host, rest = parts

        parsed = split_program_message(rest)
        if parsed is None:
            return None
        try:
            when = datetime.strptime(f"{self._year} {month} {day} {clock}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None

        program, pid, message = parsed
        return LogEvent(
            timestamp=when.replace(tzinfo=DATASET_TZ),
            program=program,
            pid=pid,
            message=message,
            source="dataset",
        )
