from pathlib import Path

from endpoint_investigator.collectors.permission_dataset import DatasetPermissionCollector

FIXTURE = Path(__file__).parent / "fixtures" / "permissions_sample.csv"


def test_dataset_collector_returns_all_rows_when_no_filter():
    resources = DatasetPermissionCollector(FIXTURE).collect()

    assert len(resources) == 3
    assert {r.path for r in resources} == {
        "/opt/app",
        "/opt/app/check.py",
        "/opt/reports/report.sh",
    }


def test_dataset_collector_filters_by_paths():
    resources = DatasetPermissionCollector(FIXTURE).collect(paths=["/opt/reports/report.sh"])

    assert len(resources) == 1
    report = resources[0]
    assert report.mode == "0777"
    assert report.owner == "root"
    assert report.type == "file"
    assert report.source == "dataset"
