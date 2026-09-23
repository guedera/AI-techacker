import argparse
from pathlib import Path

from endpoint_investigator.collectors.permission_dataset import DatasetPermissionCollector
from endpoint_investigator.collectors.process_dataset import DatasetProcessCollector
from endpoint_investigator.collectors.service_dataset import DatasetServiceCollector
from endpoint_investigator.correlator.rules import run_all
from endpoint_investigator.normalizer.snapshot import Snapshot


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

    if not findings:
        print("nenhum achado nessa coleta")
        return

    for finding in findings:
        print(f"[{finding.severity.upper()} / confianca {finding.confidence}] {finding.rule}")
        print(f"  evidencia: {finding.evidence}")
        print(f"  interpretacao: {finding.interpretation}")
        print(f"  hipotese: {finding.hypothesis}")
        print(f"  evidencia ausente: {finding.missing_evidence}")
        print()


if __name__ == "__main__":
    main()
