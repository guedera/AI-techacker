import argparse
from pathlib import Path

from endpoint_investigator.collectors.permission_dataset import DatasetPermissionCollector
from endpoint_investigator.collectors.permission_real import FsPermissionCollector
from endpoint_investigator.collectors.process_dataset import DatasetProcessCollector
from endpoint_investigator.collectors.process_real import ProcCollector
from endpoint_investigator.collectors.service_dataset import DatasetServiceCollector
from endpoint_investigator.collectors.service_real import SystemdCollector
from endpoint_investigator.correlator.rules import run_all
from endpoint_investigator.normalizer.snapshot import Snapshot, resource_paths
from endpoint_investigator.reporter.console import render_findings


def load_snapshot_from_dataset(dataset_dir: Path) -> Snapshot:
    return Snapshot(
        processes=DatasetProcessCollector(dataset_dir / "processes.csv").collect(),
        permissions=DatasetPermissionCollector(dataset_dir / "permissions.csv").collect(),
        services=DatasetServiceCollector(dataset_dir / "services.txt").collect(),
    )


def load_snapshot_from_real_system() -> Snapshot:
    processes = ProcCollector().collect()
    services = SystemdCollector().collect()

    paths = {path for process in processes for path in resource_paths(process)}
    permissions = FsPermissionCollector().collect(paths=paths) if paths else []

    return Snapshot(processes=processes, permissions=permissions, services=services)


def main() -> None:
    parser = argparse.ArgumentParser(description="Roda a correlacao do Endpoint Investigator")
    parser.add_argument(
        "dataset",
        type=Path,
        nargs="?",
        default=None,
        help=(
            "pasta com processes.csv, permissions.csv e services.txt. "
            "Se nao passar nada, coleta do sistema real (precisa ser Linux, de preferencia com sudo)."
        ),
    )
    args = parser.parse_args()

    snapshot = (
        load_snapshot_from_dataset(args.dataset) if args.dataset else load_snapshot_from_real_system()
    )
    findings = run_all(snapshot)
    render_findings(findings)


if __name__ == "__main__":
    main()
