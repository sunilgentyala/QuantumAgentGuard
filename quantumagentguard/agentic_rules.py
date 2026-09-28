"""AST-based detectors for classic agentic-AI vulnerability patterns.

Every rule here targets a pattern with a documented real-world precedent
(most directly: CVE-2026-26030, an unsafe eval() reachable from LLM-influenced
input in Microsoft Semantic Kernel, patched 2026-05). These are static,
syntactic heuristics -- they flag code *shapes* known to have caused real
incidents, not proof of exploitability in the specific file scanned.
"""

from __future__ import annotations

import ast

from .findings import Finding

DANGEROUS_CALLS = {"eval", "exec"}
SHELL_CALLS = {"os.system", "os.popen", "subprocess.call", "subprocess.run", "subprocess.Popen"}
UNSAFE_DESERIALIZE = {"pickle.load", "pickle.loads", "yaml.load", "marshal.loads"}
SUBPROCESS_CALLS = {
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
}
INTERPRETER_CODE_FLAGS = {"-c"}

AGENT_INPUT_HINTS = (
    "llm_output",
    "llm_response",
    "agent_response",
    "agent_output",
    "tool_input",
    "tool_output",
    "user_input",
    "model_output",
    "completion",
    "response_text",
)

# Slightly broader than AGENT_INPUT_HINTS: AG004 flags dynamic code passed to an
# interpreter's -c flag regardless of variable name (the -c flag itself makes any
# non-literal argument a code-execution risk), but escalates to HIGH on this wider
# vocabulary since "code"/"script"/"snippet" are common agent-tool parameter names
# that AGENT_INPUT_HINTS' stricter substring match would otherwise also catch
# unrelated variables like "zip_code" on -- kept local to this one rule.
CODE_ARG_HINTS = AGENT_INPUT_HINTS + ("code", "script", "snippet")


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _mentions_agent_input(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and any(h in sub.id.lower() for h in AGENT_INPUT_HINTS):
            return True
    return False


def _mentions_code_hint(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and any(h in sub.id.lower() for h in CODE_ARG_HINTS):
            return True
    return False


def _find_interpreter_code_arg(node: ast.Call) -> ast.AST | None:
    """If a subprocess.* call's argv list contains an interpreter code flag
    (e.g. "-c") followed by a non-literal element, return that element.

    Covers `subprocess.run([sys.executable, "-c", code], ...)`: this runs
    arbitrary code exactly like eval()/exec() does, just through a
    subprocess instead of the current interpreter, and is invisible to both
    AG001 (no eval/exec call) and AG002 (no shell=True).
    """
    if not node.args:
        return None
    argv = node.args[0]
    if not isinstance(argv, (ast.List, ast.Tuple)):
        return None
    elts = argv.elts
    for i, elt in enumerate(elts[:-1]):
        if (
            isinstance(elt, ast.Constant)
            and isinstance(elt.value, str)
            and elt.value in INTERPRETER_CODE_FLAGS
        ):
            nxt = elts[i + 1]
            if not (isinstance(nxt, ast.Constant) and isinstance(nxt.value, str)):
                return nxt
    return None


class AgenticVisitor(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 (ast API)
        name = _dotted_name(node.func)

        if name in DANGEROUS_CALLS or name.rsplit(".", 1)[-1] in DANGEROUS_CALLS:
            reachable = _mentions_agent_input(node) or (node.args and _mentions_agent_input(node.args[0]))
            self.findings.append(
                Finding(
                    rule_id="AG001",
                    category="agentic",
                    severity="HIGH" if reachable else "MEDIUM",
                    title=f"Dynamic code execution via {name}()",
                    file=self.filename,
                    line=node.lineno,
                    detail=(
                        f"{name}() called"
                        + (" on a variable that looks like agent/LLM-derived input" if reachable else "")
                        + ". This is the exact shape of CVE-2026-26030 "
                        "(Semantic Kernel: eval() on LLM-influenced input)."
                    ),
                    reference="CVE-2026-26030",
                )
            )

        elif name in SHELL_CALLS:
            has_shell_true = any(
                isinstance(kw, ast.keyword) and kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if name in ("os.system", "os.popen") or has_shell_true:
                reachable = _mentions_agent_input(node)
                self.findings.append(
                    Finding(
                        rule_id="AG002",
                        category="agentic",
                        severity="HIGH" if reachable else "MEDIUM",
                        title=f"Shell command execution via {name}",
                        file=self.filename,
                        line=node.lineno,
                        detail=(
                            f"{name} runs a command through a shell"
                            + (", with an argument derived from agent/LLM input" if reachable else "")
                            + ". Tool-calling agents that build shell strings are command-injection prone."
                        ),
                    )
                )

        elif name in UNSAFE_DESERIALIZE:
            if name == "yaml.load":
                safe = any(
                    isinstance(kw, ast.keyword) and kw.arg == "Loader"
                    for kw in node.keywords
                )
                if safe:
                    self.generic_visit(node)
                    return
            self.findings.append(
                Finding(
                    rule_id="AG003",
                    category="agentic",
                    severity="MEDIUM",
                    title=f"Unsafe deserialization via {name}",
                    file=self.filename,
                    line=node.lineno,
                    detail=(
                        f"{name} deserializes data without a restricted loader/context. "
                        "Agents that persist or exchange memory/state this way are exposed to "
                        "arbitrary object instantiation if that data is ever attacker-influenced."
                    ),
                )
            )

        if name in SUBPROCESS_CALLS:
            code_arg = _find_interpreter_code_arg(node)
            if code_arg is not None:
                reachable = _mentions_code_hint(code_arg)
                self.findings.append(
                    Finding(
                        rule_id="AG004",
                        category="agentic",
                        severity="HIGH" if reachable else "MEDIUM",
                        title=f"Code execution via {name}([..., \"-c\", ...])",
                        file=self.filename,
                        line=node.lineno,
                        detail=(
                            f"{name} passes a non-literal argument to an interpreter's -c flag"
                            + (", and that argument looks like agent/LLM-derived or tool-supplied code"
                               if reachable else "")
                            + ". This runs arbitrary code exactly like eval()/exec() would, just "
                            "through a subprocess -- neither AG001 nor AG002 sees this shape."
                        ),
                    )
                )

        self.generic_visit(node)


def scan_source(filename: str, source: str) -> list[Finding]:
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError:
        return []
    visitor = AgenticVisitor(filename)
    visitor.visit(tree)
    return visitor.findings
