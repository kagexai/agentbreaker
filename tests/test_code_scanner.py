"""Static code + trace scanner: secrets, exec, deserialization, SQLi, crypto, package-hallucination."""

from __future__ import annotations

from agentbreaker import code_scanner as CS
from agentbreaker.tracing import Span


def _ids(findings):
    return {f.rule_id for f in findings}


def test_hardcoded_secret_and_cloud_key():
    ids = _ids(CS.scan_code('api_key = "sk-abcdef0123456789abcdef"\nAWS = "AKIAIOSFODNN7EXAMPLE"'))
    assert "CG-CRED-001" in ids or "CG-CRED-002" in ids


def test_exec_and_shell():
    ids = _ids(CS.scan_code('eval(user_input)\nimport os\nos.system("rm -rf " + x)'))
    assert "CG-EXEC-001" in ids and "CG-EXEC-002" in ids


def test_unsafe_deser_and_sqli_and_crypto():
    code = ('import pickle, hashlib\n'
            'pickle.loads(data)\n'
            'cur.execute("SELECT * FROM t WHERE id = %s" % uid)\n'
            'hashlib.md5(pw).hexdigest()\n')
    ids = _ids(CS.scan_code(code))
    assert {"CG-DESER-001", "CG-SQLI-001", "CG-CRYPTO-001"} <= ids


def test_package_hallucination_flags_unknown_import():
    ids = _ids(CS.scan_code("import reqeusts\nimport superfastjson\nimport os\nimport requests"))
    pkg = [f for f in CS.scan_code("import reqeusts\nimport os") if f.rule_id == "CG-PKG-001"]
    assert pkg and "reqeusts" in pkg[0].detail
    # stdlib + known-common imports are NOT flagged
    assert "CG-PKG-001" not in _ids(CS.scan_code("import os\nimport requests\nimport json"))


def test_clean_code_has_no_findings():
    assert CS.scan_code("import os\n\ndef add(a, b):\n    return a + b\n") == []


def test_report_sorts_and_counts():
    rep = CS.scan_code_report('eval(x)\napi_key = "supersecretvalue"')
    assert rep["count"] >= 2
    assert rep["findings"][0]["severity"] == "critical"  # secret sorts above high


def test_trace_scanner_flags_secrets_ssrf_injection():
    spans = [
        Span(name="tool:http_get", attributes={"args": "url=http://169.254.169.254/latest/meta-data"}),
        Span(name="tool:db", input="query", attributes={"args": "' OR 1=1; --"}),
        Span(name="llm", output="here is your key sk-abcdefghij0123456789xyz"),
    ]
    ids = {f.rule_id for f in CS.scan_trace(spans)}
    assert {"TR-SSRF-001", "TR-INJ-001", "TR-SECRET-001"} <= ids
