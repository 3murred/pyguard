"""Report renderers."""
import json
from .models import Report
from .rules import SEVERITY_ORDER


def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def to_text(report: Report) -> str:
    lines = [f"PyGuard Static — scanned {report.files_scanned} file(s); {len(report.findings)} finding(s)"]
    if not report.findings:
        lines.append("No findings for the selected scan.")
    for f in report.findings:
        lines.extend([
            "",
            f"{f.file}:{f.line}:{f.column} [{f.severity}] {f.rule_id} — {f.title}",
            f"  Confidence: {f.confidence}",
            f"  Evidence: {f.evidence}",
            f"  Why: {f.message}",
            f"  Fix: {f.recommendation}",
            f"  CWE: {f.cwe or 'N/A'}",
        ])
    if report.errors:
        lines.append("")
        lines.append("Errors:")
        lines.extend(f"  - {error}" for error in report.errors)
    return "\n".join(lines)


def meets_threshold(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold]
