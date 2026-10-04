"""Command-line interface for mcp-audit."""

from __future__ import annotations

import argparse
import sys

from mcp_audit import __version__
from mcp_audit.analyzer import MCPAnalyzer
from mcp_audit.limits import AnalysisLimits, FileSizeExceededError, parse_byte_size
from mcp_audit.models import Severity
from mcp_audit.reporter import format_json_report, format_terminal_report, should_use_color


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="mcp-audit",
        description="Audit MCP servers and tools for permissions, risky capabilities, secrets, and context bloat.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  mcp-audit mcp-config.json
  mcp-audit mcp-config.json --json
  mcp-audit mcp-config.json --server github
  mcp-audit mcp-config.json --severity high
  mcp-audit mcp-config.json --fail-on high
  mcp-audit mcp-config.json --max-file-size 50MB
  mcp-audit mcp-config.json --no-color

Exit codes:
  0 = Audit completed successfully; no findings triggered --fail-on threshold
  1 = Findings detected at or above --fail-on threshold
  2 = Input, parsing, or configuration error

Disclaimer:
  mcp-audit provides heuristic analysis of MCP configurations and is not a
  formal security certification or guarantee. Developers remain responsible
  for reviewing MCP servers, permissions, credentials, and data exposed to AI systems.
""",
    )

    parser.add_argument(
        "config_path",
        nargs="?",
        help="Path to the JSON MCP configuration file to audit.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output structured, machine-readable JSON report.",
    )
    parser.add_argument(
        "--server",
        metavar="NAME",
        help="Filter audit results to a specific MCP server name.",
    )
    parser.add_argument(
        "--severity",
        metavar="LEVEL",
        choices=["info", "low", "medium", "high", "critical"],
        type=str.lower,
        help="Filter displayed findings to a minimum severity level (info, low, medium, high, critical).",
    )
    parser.add_argument(
        "--fail-on",
        metavar="LEVEL",
        choices=["info", "low", "medium", "high", "critical"],
        type=str.lower,
        help="Exit with code 1 if findings at or above this severity are detected (useful for CI/CD).",
    )
    parser.add_argument(
        "--max-file-size",
        metavar="SIZE",
        default="50MB",
        help="Maximum allowed configuration file size (e.g. 50MB, 10KB, 1048576). Default: 50MB.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color highlights in terminal output.",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"mcp-audit {__version__}",
        help="Show program version number and exit.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.config_path:
        parser.print_help(sys.stderr)
        return 2

    # Parse byte size limit
    try:
        max_bytes = parse_byte_size(args.max_file_size)
    except ValueError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 2

    limits = AnalysisLimits(max_file_size=max_bytes)
    analyzer = MCPAnalyzer(limits=limits)

    min_severity = Severity(args.severity.upper()) if args.severity else None
    fail_on_severity = Severity(args.fail_on.upper()) if args.fail_on else None
    use_color = should_use_color(no_color=args.no_color)

    try:
        report = analyzer.analyze_file(args.config_path)
    except (FileNotFoundError, OSError, FileSizeExceededError, ValueError) as exc:
        if args.json_output:
            err_dict = {
                "error": str(exc),
                "file": args.config_path,
                "tool_version": __version__,
            }
            import json
            print(json.dumps(err_dict, indent=2))
        else:
            sys.stderr.write("\nConfiguration error\n")
            sys.stderr.write(f"File: {args.config_path}\n")
            sys.stderr.write(f"Problem: {exc}\n\n")
            sys.stderr.write("No servers were executed.\n")
            sys.stderr.write("No files were modified.\n")
        return 2

    # If configuration has fatal parsing errors
    if report.errors:
        if args.json_output:
            print(format_json_report(report, server_filter=args.server, min_severity=min_severity))
        else:
            print(format_terminal_report(report, server_filter=args.server, min_severity=min_severity, use_color=use_color))
        return 2

    # Output report
    if args.json_output:
        print(format_json_report(report, server_filter=args.server, min_severity=min_severity))
    else:
        print(format_terminal_report(report, server_filter=args.server, min_severity=min_severity, use_color=use_color))

    # Evaluate --fail-on condition
    if fail_on_severity:
        matching_findings = [
            f for f in report.findings
            if (not args.server or f.server == args.server) and f.severity >= fail_on_severity
        ]
        if matching_findings:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
