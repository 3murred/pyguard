"""Data models for scan results."""
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    file: str
    line: int
    column: int
    evidence: str
    message: str
    recommendation: str
    cwe: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    findings: list[Finding]
    files_scanned: int = 0
    errors: list[str] | None = None

    def __post_init__(self) -> None:
        if self.errors is None:
            self.errors = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "finding_count": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": self.errors or [],
        }
