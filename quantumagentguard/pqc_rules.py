"""Detectors for quantum-readiness gaps in an agent framework's crypto/PKI usage.

Scope, stated plainly: these are static, syntactic checks against known-classical
primitives and known-PQC library names. A clean scan means "no classical-only
crypto patterns detected by these rules" -- it is not a cryptographic audit and
does not verify that any PQC library found is used correctly.
"""

from __future__ import annotations

import ast
import re

from .findings import Finding

WEAK_TLS_PROTOCOLS = {"PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1", "PROTOCOL_SSLv2", "PROTOCOL_SSLv23"}

# Framework markers: presence signals "this project runs an AI agent."
AGENT_FRAMEWORK_MARKERS = {
    "langchain",
    "langgraph",
    "semantic-kernel",
    "semantic_kernel",
    "autogen",
    "pyautogen",
    "crewai",
    "llama-index",
    "llama_index",
    "mcp",
    "modelcontextprotocol",
}

# PQC markers: presence signals "this project has at least one PQC-capable dependency."
# NIST FIPS 203 (ML-KEM/Kyber), FIPS 204 (ML-DSA/Dilithium), FIPS 205 (SLH-DSA/SPHINCS+).
PQC_MARKERS = {
    "oqs",
    "liboqs",
    "liboqs-python",
    "pyoqs",
    "pqcrypto",
    "open-quantum-safe",
    "kyber",
    "dilithium",
    "ml-kem",
    "ml_kem",
    "ml-dsa",
    "ml_dsa",
    "mlkem",
    "mldsa",
    "sphincs",
    "falcon",
}


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


class PQCVisitor(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        name = _dotted_name(node.func)
        short = name.rsplit(".", 1)[-1]

        if short == "generate_private_key" and "rsa" in name.lower():
            key_size = None
            for kw in node.keywords:
                if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                    key_size = kw.value.value
            if key_size is None and node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant):
                    key_size = first.value
            if isinstance(key_size, int) and key_size < 3072:
                self.findings.append(
                    Finding(
                        rule_id="PQ001",
                        category="pqc",
                        severity="MEDIUM",
                        title=f"RSA key generated at {key_size} bits",
                        file=self.filename,
                        line=node.lineno,
                        detail=(
                            f"RSA-{key_size} is below current classical best practice (>=3072) and, "
                            "regardless of size, RSA has no post-quantum migration path. "
                            "This key/certificate will need replacement under FIPS 203/204 (Kyber/Dilithium)."
                        ),
                    )
                )
            else:
                self.findings.append(
                    Finding(
                        rule_id="PQ001",
                        category="pqc",
                        severity="INFO",
                        title="RSA key generation (classical-only, no PQ path)",
                        file=self.filename,
                        line=node.lineno,
                        detail=(
                            "RSA key generated. RSA has no post-quantum migration path; "
                            "flagged for awareness even at an adequate classical key size."
                        ),
                    )
                )

        elif short == "generate_private_key" and ".ec." in f".{name}.":
            self.findings.append(
                Finding(
                    rule_id="PQ002",
                    category="pqc",
                    severity="INFO",
                    title="ECDSA key generation (classical-only, no PQ path)",
                    file=self.filename,
                    line=node.lineno,
                    detail=(
                        "EC key generated for signing. ECDSA has no post-quantum migration path; "
                        "escalated to MEDIUM/HIGH at repo level if no PQC dependency is found anywhere "
                        "in this project (see PQ004)."
                    ),
                )
            )

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:  # noqa: N802
        if node.attr in WEAK_TLS_PROTOCOLS:
            self.findings.append(
                Finding(
                    rule_id="PQ003",
                    category="pqc",
                    severity="MEDIUM",
                    title=f"Deprecated TLS protocol constant ssl.{node.attr}",
                    file=self.filename,
                    line=node.lineno,
                    detail=(
                        f"ssl.{node.attr} pins a deprecated, classical-only TLS version. "
                        "Even current TLS 1.3 hybrid PQ key exchange is unreachable while this is pinned."
                    ),
                )
            )
        self.generic_visit(node)


def scan_source(filename: str, source: str) -> list[Finding]:
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError:
        return []
    visitor = PQCVisitor(filename)
    visitor.visit(tree)
    return visitor.findings


def text_contains_any(text: str, markers: set[str]) -> set[str]:
    """Word-boundary match, not plain substring: a plain `m in lowered` check
    would let a marker like "autogen" match inside an unrelated word such as
    "autogenerated" (e.g. a common code-gen header comment), which is a real
    false-positive vector found by scanning genuine public repositories.
    """
    lowered = text.lower()
    found = set()
    for m in markers:
        pattern = r"(?<![a-z0-9_])" + re.escape(m) + r"(?![a-z0-9_])"
        if re.search(pattern, lowered):
            found.add(m)
    return found
