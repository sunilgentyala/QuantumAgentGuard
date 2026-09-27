# Changelog

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

## [0.1.0] - 2026-09-27

### Added
- `AG001`-`AG003`: AST-based detectors for unsafe `eval`/`exec`, shell injection
  (`os.system`, `subprocess` with `shell=True`), and insecure deserialization
  (`pickle`, unguarded `yaml.load`) in agent tool-calling code.
- `PQ001`-`PQ003`: detectors for RSA key generation below 3072 bits, any
  ECDSA key generation, and deprecated TLS protocol constants.
- `PQ004` + cross-file escalation: if an agent framework marker (LangChain,
  Semantic Kernel, AutoGen, CrewAI, LlamaIndex, MCP) is present anywhere in
  the project and no PQC library marker (liboqs/oqs, pqcrypto, Kyber/ML-KEM,
  Dilithium/ML-DSA, SPHINCS+, FALCON) is found in source or dependency
  manifests, every classical-key finding is escalated to HIGH.
- `qag scan <path>` CLI with text and `--json` output, and `--fail-on` for CI gating.
- Transparent, documented risk score (`10*HIGH + 5*MEDIUM + 1*INFO`, capped at 100).
- Full pytest suite covering every rule's positive and negative case.

[0.1.0]: https://github.com/sunilgentyala/QuantumAgentGuard/releases/tag/v0.1.0
