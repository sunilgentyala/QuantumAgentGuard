from quantumagentguard.pqc_rules import scan_source


def test_rsa_2048_flagged_medium():
    src = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "def make_key():\n"
        "    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )
    findings = scan_source("f.py", src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PQ001"
    assert findings[0].severity == "MEDIUM"


def test_rsa_4096_flagged_info():
    src = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "def make_key():\n"
        "    return rsa.generate_private_key(public_exponent=65537, key_size=4096)\n"
    )
    findings = scan_source("f.py", src)
    assert len(findings) == 1
    assert findings[0].severity == "INFO"


def test_ec_key_generation_flagged_info():
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "def make_key():\n"
        "    return ec.generate_private_key(ec.SECP384R1())\n"
    )
    findings = scan_source("f.py", src)
    assert any(f.rule_id == "PQ002" for f in findings)


def test_deprecated_tls_protocol_flagged():
    src = "import ssl\nctx = ssl.PROTOCOL_TLSv1\n"
    findings = scan_source("f.py", src)
    assert any(f.rule_id == "PQ003" for f in findings)


def test_no_findings_for_unrelated_code():
    src = "def add(a, b):\n    return a + b\n"
    assert scan_source("f.py", src) == []
