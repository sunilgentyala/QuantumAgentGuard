from quantumagentguard.cli import main


def test_scan_clean_dir_exits_zero(tmp_path, capsys):
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n")
    code = main(["scan", str(tmp_path)])
    assert code == 0
    out = capsys.readouterr().out
    assert "QuantumAgentGuard scan" in out


def test_scan_json_output(tmp_path, capsys):
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n")
    code = main(["scan", str(tmp_path), "--json"])
    assert code == 0
    out = capsys.readouterr().out
    assert '"risk_score"' in out


def test_fail_on_high_exits_nonzero(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("crewai==0.1.0\n")
    (tmp_path / "agent.py").write_text("def handle(llm_output):\n    return eval(llm_output)\n")
    code = main(["scan", str(tmp_path), "--fail-on", "HIGH"])
    assert code == 1
