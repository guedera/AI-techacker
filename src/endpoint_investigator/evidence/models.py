from typing import Literal

from pydantic import BaseModel


class Finding(BaseModel):
    """Um achado da correlacao, sempre separando o que foi visto do que e so hipotese."""

    rule: str
    severity: Literal["info", "low", "medium", "high"]
    evidence: str
    interpretation: str
    hypothesis: str
    missing_evidence: str
