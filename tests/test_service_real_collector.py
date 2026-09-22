from endpoint_investigator.collectors.service_real import SystemdCollector

LIST_UNITS_CMD = ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain"]


def _fake_runner(responses: dict[tuple, str]):
    def runner(args: list[str]) -> str:
        return responses[tuple(args)]

    return runner


def test_systemd_collector_describes_running_service_as_root():
    responses = {
        tuple(LIST_UNITS_CMD): "ssh.service loaded active running OpenSSH server\n",
        ("systemctl", "show", "ssh.service", "-p", "ActiveState", "--value"): "active\n",
        ("systemctl", "show", "ssh.service", "-p", "User", "--value"): "\n",
        ("systemctl", "cat", "ssh.service"): (
            "# /lib/systemd/system/ssh.service\n[Service]\nExecStart=/usr/sbin/sshd -D\n"
        ),
    }

    services = SystemdCollector(runner=_fake_runner(responses)).collect()

    assert len(services) == 1
    service = services[0]
    assert service.name == "ssh.service"
    assert service.active == "active"
    assert service.user == "root"  # User= vazio no unit file cai pra root
    assert service.exec_start == "/usr/sbin/sshd -D"
    assert service.source == "real"


def test_systemd_collector_reads_explicit_user():
    responses = {
        tuple(LIST_UNITS_CMD): "backup-agent.service loaded active running Internal Backup Agent\n",
        ("systemctl", "show", "backup-agent.service", "-p", "ActiveState", "--value"): "active\n",
        ("systemctl", "show", "backup-agent.service", "-p", "User", "--value"): "backup\n",
        ("systemctl", "cat", "backup-agent.service"): (
            "[Service]\nExecStart=/bin/bash /opt/backup/backup.sh\n"
        ),
    }

    services = SystemdCollector(runner=_fake_runner(responses)).collect()

    assert services[0].user == "backup"
    assert services[0].exec_start == "/bin/bash /opt/backup/backup.sh"
