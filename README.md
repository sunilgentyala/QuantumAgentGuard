# QuantumAgentGuard

**Static analysis for AI agent codebases: agentic vulnerability patterns and quantum-readiness/PKI gaps, in one scan.**

Site: https://sunilgentyala.github.io/QuantumAgentGuard/

## The gap this fills

Two ecosystems currently exist in parallel and don't talk to each other:

- **Agentic-AI red-teaming tools** (e.g. DeepTeam) test whether an agent's *behavior* can be
  manipulated: prompt injection, jailbreaks, unsafe tool use.
- **Post-quantum cryptography tooling** (e.g. liboqs) tests whether a *cryptographic primitive*
  is quantum-safe.

Nothing checks both at once for the same project. That matters because the two problems
compound: a 2026 CVE in Microsoft Semantic Kernel (CVE-2026-26030) showed that current agent
frameworks fail from ordinary architecture bugs: an `eval()` reachable from LLM-influenced
input, a blocklist filter that's trivially bypassed, not from anything exotic about the model.
Microsoft's own conclusion was that the LLM cannot be treated as a security boundary. At the
same time, the entire Web PKI (root CAs down to every end-entity certificate) is still
RSA/ECDSA-based, and every agent framework built on top of it inherits that exposure by
default, whether or not anyone thought to check.

QuantumAgentGuard scans a codebase for **both** classes of gap in a single pass, and (this is
the part nothing else does) escalates the crypto findings automatically when it detects that
the project is an AI agent with no post-quantum dependency anywhere in it.

## What it actually is

A static-analysis CLI (`qag`), built on Python's `ast` module, with **zero runtime
dependencies**. It ships as source you can read end to end in a few minutes; there is no
opaque model or benchmark score behind it, only rules you can inspect in
`quantumagentguard/agentic_rules.py` and `quantumagentguard/pqc_rules.py`.

**It is a heuristic linter, not a proof of exploitability.** A clean scan means "none of these
known-bad shapes were found by these specific rules," nothing more. Read it, don't just trust
the score.

Scans `.py` files and `.ipynb` notebook code cells (line numbers for notebook findings are
relative to the cell, not the file). Dependency manifests (`requirements.txt`, `pyproject.toml`,
`package.json`, `Pipfile`, `setup.py`) are read for framework/PQC marker text but not parsed
for detector rules.

## Detectors

| Rule | Category | Fires on | Real-world precedent |
|------|----------|----------|----------------------|
| `AG001` | Agentic | `eval()` / `exec()`, escalated to HIGH if the argument looks LLM/agent-derived | CVE-2026-26030 (Semantic Kernel) |
| `AG002` | Agentic | `os.system`/`os.popen`, or `subprocess.*` with `shell=True` | Command injection via tool-calling agents |
| `AG003` | Agentic | `pickle.load(s)`, unguarded `yaml.load()` | Insecure deserialization of agent memory/state |
| `AG004` | Agentic | `subprocess.*([interpreter, "-c", code], ...)` with a non-literal code argument | Same risk as `eval()`/`exec()`, via a subprocess instead |
| `PQ001` | Quantum-readiness | RSA key generation (`<3072` bits = MEDIUM; any size = at least INFO) | RSA has no post-quantum migration path |
| `PQ002` | Quantum-readiness | ECDSA key generation | ECDSA has no post-quantum migration path |
| `PQ003` | Quantum-readiness | Deprecated `ssl.PROTOCOL_TLSv1*`/`SSLv2*`/`SSLv23` constants | Blocks hybrid PQ key exchange outright |
| `PQ004` | Quantum-readiness | Agent framework marker present (LangChain, Semantic Kernel, AutoGen, CrewAI, LlamaIndex, MCP) **and** zero PQC marker (liboqs/oqs, pqcrypto, Kyber/ML-KEM, Dilithium/ML-DSA, SPHINCS+, FALCON) anywhere in the project | Cross-file finding; escalates every `PQ001`/`PQ002` INFO to HIGH |

## Quickstart

```bash
pip install -e .
qag scan /path/to/your/agent/project
qag scan /path/to/your/agent/project --json
qag scan /path/to/your/agent/project --fail-on HIGH   # for CI
```

## Real output, not a mockup

Run against `examples/vulnerable_agent_demo/` (a minimal fixed target shaped after CVE-2026-26030,
included in this repo):

```
QuantumAgentGuard scan: examples\vulnerable_agent_demo
Files scanned: 1
Findings: 6  |  Risk score: 45/100

-- AGENTIC VULNERABILITIES (3) --
  [HIGH  ] AG001 tool.py:17: Dynamic code execution via eval()  [CVE-2026-26030]
  [HIGH  ] AG002 tool.py:21: Shell command execution via os.system
  [MEDIUM] AG003 tool.py:25: Unsafe deserialization via pickle.loads

-- QUANTUM-READINESS GAPS (3) --
  [HIGH  ] PQ004 (project-wide): Agent framework detected with zero post-quantum crypto dependencies
  [MEDIUM] PQ001 tool.py:33: RSA key generated at 2048 bits
  [MEDIUM] PQ003 tool.py:29: Deprecated TLS protocol constant ssl.PROTOCOL_TLSv1
```

Reproduce it yourself: `qag scan examples/vulnerable_agent_demo`.

## Real-world evaluation

v0.1.0 was run against 6 real public repositories (crewAI-examples, MCP servers,
Semantic Kernel, AutoGen, LlamaIndex samples, plus a negative control), not just the
bundled demo above. Every `PQ004` finding it produced was a true positive, but it also
missed two real findings entirely, both fixed in v0.2.0 (see `CHANGELOG.md`). Full
methodology, results, and known remaining limitations: [`EVALUATION.md`](EVALUATION.md).

## The risk score, exactly

```
score = min(100, 10 * count(HIGH) + 5 * count(MEDIUM) + 1 * count(INFO))
```

That's the whole formula, see `quantumagentguard/findings.py`. It is a transparent weighted
count for quick triage, not a calibrated probability, CVSS score, or ML output.

## Repository layout

```
quantumagentguard/   the package: findings model, both rule sets, scanner, report, CLI
tests/                pytest suite: every rule's positive and negative case
examples/             a small fixed target that exercises every detector, used above
docs/                 GitHub Pages site source
EVALUATION.md         real-world evaluation against public agent-framework repositories
```

## Contributing

Issues and PRs welcome. New detector ideas (especially for JS/TS agent frameworks, currently
out of scope), false-positive reports against real codebases, and additional PQC/agent-framework
markers for `pqc_rules.py` are the most useful contributions. Every new rule needs a positive and
a negative test case, same as the existing ones in `tests/`.

## License

MIT. See `LICENSE`.
