from typing import Literal

from pydantic import BaseModel


class Process(BaseModel):
    pid: int
    ppid: int
    user: str
    uid: int | None = None
    gid: int | None = None
    state: str
    cmd: str
    executable: str | None = None
    args: list[str] = []
    timestamp: str | None = None
    source: Literal["real", "dataset"]


class FileResource(BaseModel):
    path: str
    type: Literal["file", "directory"]
    owner: str
    group: str
    mode: str
    mtime: str | None = None
    source: Literal["real", "dataset"]


class Service(BaseModel):
    name: str
    active: str
    user: str
    exec_start: str
    source: Literal["real", "dataset"]
