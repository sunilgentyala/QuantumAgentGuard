from quantumagentguard.agentic_rules import scan_source


def test_eval_on_llm_output_is_high_severity():
    src = "def handle(llm_output):\n    return eval(llm_output)\n"
    findings = scan_source("f.py", src)
    assert len(findings) == 1
    assert findings[0].rule_id == "AG001"
    assert findings[0].severity == "HIGH"


def test_eval_on_unrelated_literal_is_medium():
    src = "def handle():\n    return eval('1 + 1')\n"
    findings = scan_source("f.py", src)
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"


def test_no_findings_for_safe_code():
    src = "def add(a, b):\n    return a + b\n"
    assert scan_source("f.py", src) == []


def test_os_system_flagged():
    src = "import os\ndef run(cmd):\n    os.system(cmd)\n"
    findings = scan_source("f.py", src)
    assert any(f.rule_id == "AG002" for f in findings)


def test_subprocess_shell_true_flagged():
    src = "import subprocess\ndef run(tool_input):\n    subprocess.run(tool_input, shell=True)\n"
    findings = scan_source("f.py", src)
    assert any(f.rule_id == "AG002" and f.severity == "HIGH" for f in findings)


def test_subprocess_without_shell_true_not_flagged():
    src = "import subprocess\ndef run(cmd_list):\n    subprocess.run(cmd_list)\n"
    findings = scan_source("f.py", src)
    assert findings == []


def test_pickle_loads_flagged():
    src = "import pickle\ndef restore(blob):\n    return pickle.loads(blob)\n"
    findings = scan_source("f.py", src)
    assert any(f.rule_id == "AG003" for f in findings)


def test_yaml_load_with_safe_loader_not_flagged():
    src = "import yaml\ndef load(s):\n    return yaml.load(s, Loader=yaml.SafeLoader)\n"
    findings = scan_source("f.py", src)
    assert findings == []


def test_yaml_load_without_loader_flagged():
    src = "import yaml\ndef load(s):\n    return yaml.load(s)\n"
    findings = scan_source("f.py", src)
    assert any(f.rule_id == "AG003" for f in findings)


def test_syntax_error_returns_empty_not_raises():
    assert scan_source("broken.py", "def broken(:\n") == []


def test_subprocess_dash_c_with_variable_is_ag004_high():
    src = (
        "import subprocess, sys\n"
        "def code_interpreter(self, code):\n"
        "    return subprocess.run([sys.executable, '-c', code], capture_output=True)\n"
    )
    findings = scan_source("f.py", src)
    ag004 = [f for f in findings if f.rule_id == "AG004"]
    assert len(ag004) == 1
    assert ag004[0].severity == "HIGH"


def test_subprocess_dash_c_with_unrelated_variable_is_medium():
    src = (
        "import subprocess, sys\n"
        "def run(payload):\n"
        "    return subprocess.run([sys.executable, '-c', payload])\n"
    )
    findings = scan_source("f.py", src)
    ag004 = [f for f in findings if f.rule_id == "AG004"]
    assert len(ag004) == 1
    assert ag004[0].severity == "MEDIUM"


def test_subprocess_dash_c_with_literal_string_not_flagged():
    src = (
        "import subprocess, sys\n"
        "def run():\n"
        "    return subprocess.run([sys.executable, '-c', 'print(1)'])\n"
    )
    findings = scan_source("f.py", src)
    assert not [f for f in findings if f.rule_id == "AG004"]


def test_subprocess_without_dash_c_not_ag004():
    src = "import subprocess\ndef run(cmd_list):\n    subprocess.run(cmd_list)\n"
    findings = scan_source("f.py", src)
    assert not [f for f in findings if f.rule_id == "AG004"]
