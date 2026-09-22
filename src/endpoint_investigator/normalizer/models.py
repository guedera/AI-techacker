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
