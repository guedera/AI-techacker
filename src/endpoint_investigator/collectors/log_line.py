import re

# parte final da linha de log: "programa[pid]: mensagem" (o pid e opcional)
_SOURCE_RE = re.compile(r"^(?P<program>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$")


def split_program_message(text: str) -> tuple[str, int | None, str] | None:
    match = _SOURCE_RE.match(text)
    if match is None:
        return None
    pid = int(match["pid"]) if match["pid"] else None
    return match["program"], pid, match["message"]
