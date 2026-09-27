"""Terminal and JSON report rendering for a ScanResult."""

from __future__ import annotations

import json
from dataclasses import asdict

from .findings import ScanResult

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}


def to_json(result: ScanResult) -> str:
    payload = {
        "root": result.root,
        "files_scanned": result.files_scanned,
        "risk_score": result.risk_score(),
        "findings": [asdict(f) for f in sorted(result.findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id))],
    }
    return json.dumps(payload, indent=2)


def to_text(result: ScanResult) -> str:
    lines = []
    lines.append(f"QuantumAgentGuard scan: {result.root}")
    lines.append(f"Files scanned: {result.files_scanned}")
    lines.append(f"Findings: {len(result.findings)}  |  Risk score: {result.risk_score()}/100")
    lines.append("")

    for category, label in (("agentic", "AGENTIC VULNERABILITIES"), ("pqc", "QUANTUM-READINESS GAPS")):
        findings = sorted(result.by_category(category), key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id))
        lines.append(f"-- {label} ({len(findings)}) --")
        if not findings:
            lines.append("  (none detected)")
        for f in findings:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            ref = f"  [{f.reference}]" if f.reference else ""
            lines.append(f"  [{f.severity:6}] {f.rule_id} {loc}: {f.title}{ref}")
            lines.append(f"           {f.detail}")
        lines.append("")

    return "\n".join(lines)
