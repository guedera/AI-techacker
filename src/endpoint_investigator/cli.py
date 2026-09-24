import argparse
from pathlib import Path

from endpoint_investigator.collectors.permission_dataset import DatasetPermissionCollector
from endpoint_investigator.collectors.process_dataset import DatasetProcessCollector
from endpoint_investigator.collectors.service_dataset import DatasetServiceCollector
from endpoint_investigator.correlator.rules import run_all
from endpoint_investigator.normalizer.snapshot import Snapshot
from endpoint_investigator.reporter.console import render_findings


def load_snapshot_from_dataset(dataset_dir: Path) -> Snapshot:
    return Snapshot(
        processes=DatasetProcessCollector(dataset_dir / "processes.csv").collect(),
        permissions=DatasetPermissionCollector(dataset_dir / "permissions.csv").collect(),
        services=DatasetServiceCollector(dataset_dir / "services.txt").collect(),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Roda a correlacao do Endpoint Investigator sobre um dataset")
    parser.add_argument("dataset", type=Path, help="pasta com processes.csv, permissions.csv e services.txt")
    args = parser.parse_args()

    snapshot = load_snapshot_from_dataset(args.dataset)
    findings = run_all(snapshot)
    render_findings(findings)


if __name__ == "__main__":
    main()
