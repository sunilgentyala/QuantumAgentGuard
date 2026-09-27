"""Walks a directory, runs both rule sets, and applies the one cross-file
escalation: if the project is clearly an AI agent (a known framework marker
is present) and no PQC dependency marker is found anywhere in the project,
every classical-key-generation finding (PQ001/PQ002) is escalated, and a
standalone PQ004 finding is added.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from . import agentic_rules, pqc_rules
from .findings import Finding, ScanResult

MANIFEST_NAMES = {"requirements.txt", "pyproject.toml", "package.json", "Pipfile", "setup.py"}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", ".mypy_cache", ".pytest_cache", "dist", "build"}


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def scan_directory(root: str) -> ScanResult:
    root_path = Path(root)
    result = ScanResult(root=str(root_path))

    all_text_lower = []
    py_findings: list[Finding] = []

    for path in _iter_files(root_path):
        rel = str(path.relative_to(root_path))

        if path.suffix == ".py":
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            result.files_scanned += 1
            all_text_lower.append(source.lower())
            py_findings.extend(agentic_rules.scan_source(rel, source))
            py_findings.extend(pqc_rules.scan_source(rel, source))

        elif path.name in MANIFEST_NAMES:
            try:
                all_text_lower.append(path.read_text(encoding="utf-8", errors="ignore").lower())
            except OSError:
                continue

    project_text = "\n".join(all_text_lower)
    frameworks_found = pqc_rules.text_contains_any(project_text, pqc_rules.AGENT_FRAMEWORK_MARKERS)
    pqc_found = pqc_rules.text_contains_any(project_text, pqc_rules.PQC_MARKERS)

    is_agent_project = bool(frameworks_found)
    has_pqc = bool(pqc_found)

    for finding in py_findings:
        if is_agent_project and not has_pqc and finding.rule_id in ("PQ001", "PQ002") and finding.severity == "INFO":
            finding = replace(
                finding,
                severity="HIGH",
                detail=finding.detail
                + f" ESCALATED: this project uses {', '.join(sorted(frameworks_found))} "
                "and no post-quantum crypto dependency was found anywhere in the repo.",
            )
        result.findings.append(finding)

    if is_agent_project and not has_pqc:
        result.findings.append(
            Finding(
                rule_id="PQ004",
                category="pqc",
                severity="HIGH",
                title="Agent framework detected with zero post-quantum crypto dependencies",
                file="(project-wide)",
                line=0,
                detail=(
                    f"Detected agent framework marker(s): {', '.join(sorted(frameworks_found))}. "
                    "No PQC library marker (liboqs/oqs, pqcrypto, Kyber/ML-KEM, Dilithium/ML-DSA, "
                    "SPHINCS+/FALCON) was found in source or dependency manifests. "
                    "Every TLS session and certificate this project touches is classical-only by default."
                ),
            )
        )

    return result
