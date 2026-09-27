"""Shared data model for detector findings."""

from __future__ import annotations

from dataclasses import dataclass, field


SEVERITY_WEIGHTS = {"HIGH": 10, "MEDIUM": 5, "INFO": 1}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str  # "agentic" or "pqc"
    severity: str  # "HIGH" | "MEDIUM" | "INFO"
    title: str
    file: str
    line: int
    detail: str
    reference: str = ""

    def weight(self) -> int:
        return SEVERITY_WEIGHTS.get(self.severity, 1)


@dataclass
class ScanResult:
    root: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0

    def by_category(self, category: str) -> list[Finding]:
        return [f for f in self.findings if f.category == category]

    def risk_score(self) -> int:
        """Transparent weighted sum, capped at 100. Not a probability or a CVSS score.

        score = min(100, 10*HIGH + 5*MEDIUM + 1*INFO), counted across all findings.
        Documented here and in the README so nobody mistakes it for a calibrated metric.
        """
        raw = sum(f.weight() for f in self.findings)
        return min(100, raw)
