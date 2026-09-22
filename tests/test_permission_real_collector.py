import os
import pwd

import pytest

from endpoint_investigator.collectors.permission_real import FsPermissionCollector


def _current_user() -> str:
    return pwd.getpwuid(os.getuid()).pw_name


def test_fs_collector_reads_known_files(tmp_path):
    script = tmp_path / "report.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    os.chmod(script, 0o777)

    directory = tmp_path / "opt"
    directory.mkdir()
    os.chmod(directory, 0o755)

    resources = FsPermissionCollector().collect(paths=[str(script), str(directory)])
    by_path = {r.path: r for r in resources}

    assert by_path[str(script)].mode == "0777"
    assert by_path[str(script)].type == "file"
    assert by_path[str(script)].owner == _current_user()
    assert by_path[str(script)].source == "real"

    assert by_path[str(directory)].type == "directory"
    assert by_path[str(directory)].mode == "0755"


def test_fs_collector_skips_missing_path(tmp_path):
    resources = FsPermissionCollector().collect(paths=[str(tmp_path / "nope.sh")])

    assert resources == []


def test_fs_collector_requires_context_paths():
    with pytest.raises(ValueError):
        FsPermissionCollector().collect()

    with pytest.raises(ValueError):
        FsPermissionCollector().collect(paths=[])
