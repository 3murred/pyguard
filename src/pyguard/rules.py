"""AST-based detection rules. No analyzed source is imported or executed."""
import ast
import re
from pathlib import Path
from .models import Finding

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

SECRET_NAME = re.compile(r"(?:api[_-]?key|secret|token|password|passwd|client[_-]?secret|private[_-]?key)", re.I)
PLACEHOLDER = re.compile(r"(?:your[_ -]?|example|changeme|replace[_ -]?me|dummy|placeholder|<.*?>|[*]{3,})", re.I)
LONG_LITERAL = re.compile(r"^[A-Za-z0-9_./+=:-]{12,}$")


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _literal_bool(keyword: ast.keyword, expected: bool) -> bool:
    return isinstance(keyword.value, ast.Constant) and keyword.value.value is expected


class RuleVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, source_lines: list[str]) -> None:
        self.filename = filename
        self.source_lines = source_lines
        self.findings: list[Finding] = []

    def add(self, node: ast.AST, rule_id: str, title: str, severity: str,
            confidence: str, message: str, recommendation: str,
            cwe: str | None = None) -> None:
        line = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0) + 1
        evidence = self.source_lines[line - 1].strip() if 0 < line <= len(self.source_lines) else ""
        self.findings.append(Finding(
            rule_id=rule_id, title=title, severity=severity, confidence=confidence,
            file=self.filename, line=line, column=col, evidence=evidence[:240],
            message=message, recommendation=recommendation, cwe=cwe,
        ))

    def visit_Call(self, node: ast.Call) -> None:
        called = _name(node.func)
        leaf = called.rsplit(".", 1)[-1]

        if leaf in {"eval", "exec"} and isinstance(node.func, ast.Name):
            self.add(
                node, "PYG001", "Dynamic code execution", "HIGH", "MEDIUM",
                f"{leaf}() interprets a string as Python code; risk depends on where its input comes from.",
                "Avoid evaluating untrusted strings. Prefer explicit parsing, a restricted data format, or a fixed dispatch table.",
                "CWE-95",
            )

        if called in {"pickle.load", "pickle.loads", "pickle.Unpickler"}:
            self.add(
                node, "PYG002", "Potentially unsafe pickle deserialization", "HIGH", "MEDIUM",
                f"{called} can execute attacker-controlled behavior when loading untrusted pickle data.",
                "Never unpickle data that can be supplied or modified by an untrusted party. Prefer JSON or another data-only format.",
                "CWE-502",
            )

        if called in {"subprocess.run", "subprocess.call", "subprocess.Popen",
                      "subprocess.check_call", "subprocess.check_output"}:
            if any(k.arg == "shell" and _literal_bool(k, True) for k in node.keywords):
                self.add(
                    node, "PYG003", "Shell-enabled subprocess call", "HIGH", "MEDIUM",
                    "shell=True delegates command parsing to a system shell; interpolated input can cause command injection.",
                    "Prefer an argument list with shell=False. Avoid building commands from untrusted input and validate allowed values.",
                    "CWE-78",
                )

        if called.startswith("requests.") and leaf in {"get", "post", "put", "patch", "delete", "request", "head", "options"}:
            if any(k.arg == "verify" and _literal_bool(k, False) for k in node.keywords):
                self.add(
                    node, "PYG004", "TLS certificate verification disabled", "MEDIUM", "HIGH",
                    "verify=False disables certificate validation and can expose traffic to interception.",
                    "Remove verify=False and use the system trust store or configure the correct CA bundle.",
                    "CWE-295",
                )

        if called in {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}:
            self.add(
                node, "PYG006", "Legacy hash algorithm", "LOW", "MEDIUM",
                f"{called} is a legacy hash and may be unsuitable for security-sensitive use; context matters.",
                "For password storage use a dedicated password-hashing algorithm such as Argon2id, scrypt, or PBKDF2. For integrity, choose a modern hash when appropriate.",
                "CWE-328",
            )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_secret_targets(node.targets, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._check_secret_targets([node.target], node.value, node)
        self.generic_visit(node)

    def _check_secret_targets(self, targets: list[ast.expr], value: ast.expr, node: ast.AST) -> None:
        names: list[str] = []
        for target in targets:
            if isinstance(target, ast.Name):
                names.append(target.id)
        if not names or not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        text = value.value.strip()
        if not text or PLACEHOLDER.search(text) or not LONG_LITERAL.match(text):
            return
        if any(SECRET_NAME.search(name) for name in names):
            self.add(
                node, "PYG005", "Possible hard-coded secret", "HIGH", "LOW",
                "A variable name associated with credentials is assigned a long string literal. This heuristic may flag test data or placeholders.",
                "Load secrets from a secret manager or environment variable. If a real credential was committed, revoke and rotate it; removing it from the latest commit may not remove it from history.",
                "CWE-798",
            )


def analyze_tree(tree: ast.AST, filename: str, source: str) -> list[Finding]:
    visitor = RuleVisitor(filename, source.splitlines())
    visitor.visit(tree)
    visitor.findings.sort(key=lambda f: (f.line, f.column, f.rule_id))
    return visitor.findings
