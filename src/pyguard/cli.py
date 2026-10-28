"""Command-line interface."""
import argparse
import sys
from . import __version__
from .reporters import meets_threshold, to_json, to_text
from .scanner import Scanner
from .rules import SEVERITY_ORDER


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pyguard", description="AST-based static security scanner for Python.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a Python file or directory")
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument("-r", "--recursive", action="store_true", help="scan subdirectories recursively")
    scan.add_argument("--format", choices=("text", "json"), default="text", help="output format")
    scan.add_argument("--severity", choices=tuple(SEVERITY_ORDER), default="LOW",
                      help="minimum severity to display (default: LOW)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "scan":
        return 2
    report = Scanner().scan_path(args.path, recursive=args.recursive)
    thresholded = [f for f in report.findings if meets_threshold(f.severity, args.severity)]
    report.findings = thresholded
    print(to_json(report) if args.format == "json" else to_text(report))
    if report.errors and report.files_scanned == 0:
        return 2
    return 1 if report.findings else 0


if __name__ == "__main__":
    sys.exit(main())
