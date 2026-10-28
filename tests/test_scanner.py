from pyguard import Scanner


def rules_for(source: str) -> set[str]:
    report = Scanner().scan_source("sample.py", source)
    assert not report.errors
    return {f.rule_id for f in report.findings}


def test_detects_eval_and_exec():
    found = rules_for("a = eval(user_input)\nexec(payload)\n")
    assert {"PYG001"} <= found


def test_detects_pickle():
    found = rules_for("import pickle\npickle.loads(blob)\n")
    assert "PYG002" in found


def test_detects_shell_true():
    found = rules_for("import subprocess\nsubprocess.run(cmd, shell=True)\n")
    assert "PYG003" in found


def test_detects_requests_verify_false():
    found = rules_for("import requests\nrequests.get(url, verify=False)\n")
    assert "PYG004" in found


def test_detects_secret_heuristic():
    found = rules_for('API_TOKEN = "sk_live_ABCDEF1234567890"\n')
    assert "PYG005" in found


def test_detects_legacy_hash():
    found = rules_for("import hashlib\nhashlib.md5(data)\n")
    assert "PYG006" in found


def test_does_not_flag_safe_patterns():
    found = rules_for('import json\njson.loads(data)\n')
    assert not found


def test_never_executes_scanned_code(tmp_path):
    marker = tmp_path / "SHOULD_NOT_EXIST.txt"
    source = f"open({str(marker)!r}, 'w').write('executed')\neval('1 + 1')\n"
    report = Scanner().scan_source("untrusted.py", source)
    assert report.findings
    assert not marker.exists()


def test_syntax_error_reported():
    report = Scanner().scan_source("broken.py", "def nope(:\n")
    assert report.errors
    assert report.files_scanned == 0
