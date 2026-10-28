# PyGuard Static

**PyGuard Static** is a small, explainable Python static-analysis library that looks for potentially unsafe patterns using Python's `ast` module. It does **not** execute the code it scans and has no runtime dependencies.

> **Alpha software:** findings are indicators, not proof of exploitability. Static analysis can produce false positives and miss vulnerabilities. Review results before making security decisions.

## Features in v0.1.0

- Detects calls to `eval()` and `exec()`.
- Detects risky `pickle.load()` / `pickle.loads()` usage.
- Detects `subprocess` calls with `shell=True`.
- Detects `requests` calls with `verify=False`.
- Flags likely hard-coded secrets in assignments.
- Flags direct use of MD5/SHA-1 hashing APIs as a review prompt.
- Reports rule ID, severity, confidence, file, line, evidence, explanation, and remediation.
- Python API, terminal CLI, JSON output, severity filtering, and nonzero exit code on findings.
- Uses only Python's standard library at runtime.

## Requirements

- Python 3.10+
- Windows, macOS, or Linux

## Install on Windows

Open PowerShell in the extracted project directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

If PowerShell blocks activation, either allow it for this terminal session with
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, or use the virtual
environment's executable directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

## Run it

Scan the included example:

```powershell
pyguard scan .\examples\vulnerable_example.py
```

Scan a directory recursively:

```powershell
pyguard scan .\src --recursive
```

Output JSON:

```powershell
pyguard scan .\examples --recursive --format json
```

Only show HIGH findings:

```powershell
pyguard scan .\examples --recursive --severity HIGH
```

The CLI exits with code `1` if findings at or above the selected severity are found, `0` if no matching findings are found, and `2` for usage or input errors. This makes it usable in CI pipelines.

## Python API

```python
from pyguard import Scanner

scanner = Scanner()
report = scanner.scan_file("app.py")

for finding in report.findings:
    print(finding.rule_id, finding.severity, finding.line)
    print(finding.evidence)
    print(finding.recommendation)
```

You can scan source text without writing a file:

```python
report = Scanner().scan_source(
    "sample.py",
    "user_value = input()\nresult = eval(user_value)\n",
)
```

## Rule catalog

| Rule | Default severity | What it flags | Main remediation |
|---|---|---|---|
| `PYG001` | HIGH | `eval()` / `exec()` calls | Avoid evaluating untrusted strings; use explicit parsing or dispatch |
| `PYG002` | HIGH | `pickle.load()` / `pickle.loads()` | Never unpickle untrusted or tamperable data; use a data-only format |
| `PYG003` | HIGH | `subprocess` with `shell=True` | Prefer argument lists and `shell=False`; validate inputs |
| `PYG004` | MEDIUM | `requests` with `verify=False` | Keep TLS certificate verification enabled |
| `PYG005` | HIGH | Likely hard-coded secret assignment | Load secrets from a secret manager or environment; rotate exposed credentials |
| `PYG006` | LOW | MD5/SHA-1 calls | For password storage use a dedicated password-hashing function; choose modern hashes for integrity needs |

The rules are intentionally conservative and syntax-based. For example, `PYG005` is a heuristic and can flag placeholders. `PYG006` is context-sensitive: MD5/SHA-1 may be acceptable for non-security uses, so it is a review warning rather than proof of a vulnerability.

## Architecture

- `scanner.py`: public API and file/directory traversal.
- `rules.py`: AST visitors and rule definitions.
- `models.py`: stable finding/report data models.
- `reporters.py`: human-readable and JSON rendering.
- `cli.py`: command-line interface.

## Tests

```powershell
python -m pytest
```

## Safety and limitations

- The scanned Python code is parsed as source; it is never imported or executed.
- This is not a sandbox, malware detector, or full taint-analysis engine.
- It does not resolve dynamic imports, aliases comprehensively, interprocedural flows, or all obfuscation.
- Only `.py` files are scanned. Syntax errors are reported as input errors, not findings.
- Never use scanner output as the sole basis for declaring a project secure.

## Roadmap ideas

1. Add SARIF output for GitHub code scanning.
2. Add configurable rules and inline suppressions.
3. Track source-to-sink flows for SQL injection and command injection.
4. Add baseline files to help teams focus on new findings.
5. Publish to PyPI after checking package-name availability and adding release automation.

## License

MIT. See `LICENSE`.
