import grp
import pwd
import stat
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from endpoint_investigator.collectors.base import PermissionCollector
from endpoint_investigator.normalizer.models import FileResource


class FsPermissionCollector(PermissionCollector):
    """Le permissoes de arquivos/diretorios do sistema real (via os.stat).

    Precisa receber uma lista de paths de interesse: a analise de permissao
    tem que ser guiada por contexto (executaveis de processo/servico ja
    identificados), nunca uma varredura indiscriminada do filesystem.
    """

    def collect(self, paths: Iterable[str] | None = None) -> list[FileResource]:
        paths = list(paths) if paths is not None else []
        if not paths:
            raise ValueError(
                "FsPermissionCollector precisa de paths de interesse; a analise "
                "de permissao tem que ser guiada por contexto, nao uma varredura "
                "indiscriminada do filesystem."
            )

        resources: list[FileResource] = []
        for raw_path in paths:
            resource = self._read_resource(Path(raw_path))
            if resource is not None:
                resources.append(resource)
        return resources

    def _read_resource(self, path: Path) -> FileResource | None:
        try:
            st = path.stat()
        except (FileNotFoundError, PermissionError):
            return None

        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            owner = str(st.st_uid)
        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            group = str(st.st_gid)

        return FileResource(
            path=str(path),
            type="directory" if stat.S_ISDIR(st.st_mode) else "file",
            owner=owner,
            group=group,
            mode=format(st.st_mode & 0o7777, "04o"),
            mtime=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
            source="real",
        )
