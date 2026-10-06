import subprocess

from endpoint_investigator.collectors.log_real import JournalCollector

JOURNAL_OUTPUT = (
    "-- Boot abc123 --\n"
    "2026-10-05T16:02:11-0300 kaliguedes sudo[20590]: guedes : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/id\n"
    "2026-10-05T16:02:12-0300 kaliguedes systemd[1]: Started demo-backup.service - Servico de teste.\n"
)


def test_journal_collector_parses_short_iso_lines():
    events = JournalCollector(runner=lambda args: JOURNAL_OUTPUT).collect()

    assert len(events) == 2  # a linha "-- Boot --" fica de fora

    sudo_event = events[0]
    assert sudo_event.program == "sudo"
    assert sudo_event.pid == 20590
    assert sudo_event.message.startswith("guedes : TTY=pts/0")
    assert sudo_event.source == "real"
    assert sudo_event.timestamp.utcoffset().total_seconds() == -3 * 3600


def test_journal_collector_asks_only_for_current_boot():
    seen: list[list[str]] = []

    def runner(args: list[str]) -> str:
        seen.append(args)
        return ""

    JournalCollector(runner=runner).collect()

    assert seen[0][0] == "journalctl"
    assert "-b" in seen[0]  # PIDs se repetem entre boots, entao so o boot atual


def test_journal_collector_returns_empty_when_journalctl_fails():
    def failing(args: list[str]) -> str:
        raise subprocess.CalledProcessError(1, args)

    assert JournalCollector(runner=failing).collect() == []


def test_journal_collector_returns_empty_when_journalctl_is_missing():
    def missing(args: list[str]) -> str:
        raise FileNotFoundError("journalctl")

    assert JournalCollector(runner=missing).collect() == []
