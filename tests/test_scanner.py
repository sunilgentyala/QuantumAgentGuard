from quantumagentguard.scanner import scan_directory


def test_agent_project_without_pqc_escalates_and_adds_pq004(tmp_path):
    (tmp_path / "requirements.txt").write_text("langchain==0.3.0\ncryptography\n")
    (tmp_path / "agent.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "def make_key():\n"
        "    return rsa.generate_private_key(public_exponent=65537, key_size=4096)\n"
    )

    result = scan_directory(str(tmp_path))

    pq004 = [f for f in result.findings if f.rule_id == "PQ004"]
    assert len(pq004) == 1
    assert pq004[0].severity == "HIGH"

    pq001 = [f for f in result.findings if f.rule_id == "PQ001"]
    assert len(pq001) == 1
    assert pq001[0].severity == "HIGH"  # escalated from INFO


def test_agent_project_with_pqc_dependency_not_escalated(tmp_path):
    (tmp_path / "requirements.txt").write_text("langchain==0.3.0\nliboqs-python\n")
    (tmp_path / "agent.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "def make_key():\n"
        "    return rsa.generate_private_key(public_exponent=65537, key_size=4096)\n"
    )

    result = scan_directory(str(tmp_path))

    assert not [f for f in result.findings if f.rule_id == "PQ004"]
    pq001 = [f for f in result.findings if f.rule_id == "PQ001"]
    assert pq001[0].severity == "INFO"


def test_non_agent_project_not_escalated(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")
    (tmp_path / "app.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "def make_key():\n"
        "    return rsa.generate_private_key(public_exponent=65537, key_size=4096)\n"
    )

    result = scan_directory(str(tmp_path))

    assert not [f for f in result.findings if f.rule_id == "PQ004"]
    pq001 = [f for f in result.findings if f.rule_id == "PQ001"]
    assert pq001[0].severity == "INFO"


def test_risk_score_and_files_scanned(tmp_path):
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n")
    result = scan_directory(str(tmp_path))
    assert result.files_scanned == 1
    assert result.risk_score() == 0
