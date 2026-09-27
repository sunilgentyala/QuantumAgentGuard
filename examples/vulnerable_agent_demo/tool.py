"""A minimal, deliberately vulnerable LangChain-style calculator tool.

This mirrors the shape behind CVE-2026-26030 (Semantic Kernel: eval() reachable
from LLM-influenced input) -- kept here as a fixed scan target for the README demo
and for anyone who wants to see the detectors fire on real code.
"""

import os
import pickle
import ssl

from cryptography.hazmat.primitives.asymmetric import rsa


def calculator_tool(llm_output: str):
    """Agent 'tool' that evaluates whatever expression the model produced."""
    return eval(llm_output)


def run_shell_tool(tool_input: str):
    os.system(tool_input)


def load_agent_memory(blob: bytes):
    return pickle.loads(blob)


def legacy_tls_context():
    return ssl.PROTOCOL_TLSv1


def issue_agent_cert():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
