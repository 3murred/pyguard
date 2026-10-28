"""Public scanner API."""
import ast
from pathlib import Path
from .models import Report
from .rules import analyze_tree


class Scanner:
    """Analyze Python source without executing it."""

    def scan_source(self, filename: str, source: str) -> Report:
        try:
            tree = ast.parse(source, filename=filename)
        except (SyntaxError, ValueError) as exc:
            return Report(findings=[], files_scanned=0,
                          errors=[f"{filename}: syntax error: {exc}"])
        return Report(findings=analyze_tree(tree, filename, source), files_scanned=1)

    def scan_file(self, path: str | Path) -> Report:
        file_path = Path(path)
        try:
            # tokenize.open respects a Python source encoding declaration.
            import tokenize
            with tokenize.open(file_path) as handle:
                source = handle.read()
        except (OSError, UnicodeError, SyntaxError) as exc:
            return Report(findings=[], files_scanned=0,
                          errors=[f"{file_path}: could not read file: {exc}"])
        return self.scan_source(str(file_path), source)

    def scan_path(self, path: str | Path, recursive: bool = True) -> Report:
        target = Path(path)
        if target.is_file():
            if target.suffix.lower() != ".py":
                return Report(findings=[], files_scanned=0,
                              errors=[f"{target}: expected a .py file"])
            return self.scan_file(target)
        if not target.is_dir():
            return Report(findings=[], files_scanned=0,
                          errors=[f"{target}: path does not exist or is not accessible"])

        iterator = target.rglob("*.py") if recursive else target.glob("*.py")
        findings = []
        errors = []
        count = 0
        for file_path in sorted(iterator):
            report = self.scan_file(file_path)
            count += report.files_scanned
            findings.extend(report.findings)
            errors.extend(report.errors or [])
        findings.sort(key=lambda f: (f.file, f.line, f.column, f.rule_id))
        return Report(findings=findings, files_scanned=count, errors=errors)
