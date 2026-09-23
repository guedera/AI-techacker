from typing import Literal

from pydantic import BaseModel


class Finding(BaseModel):
    """Um achado da correlacao, sempre separando o que foi visto do que e so hipotese."""

    rule: str
    # severity = quao grave seria se a hipotese for verdade; confidence = quao
    # certos a gente esta de que ela e verdade. as duas sao independentes.
    severity: Literal["info", "low", "medium", "high"]
    confidence: Literal["low", "medium", "high"]
    evidence: str
    interpretation: str
    hypothesis: str
    missing_evidence: str
