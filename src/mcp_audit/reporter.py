"""Terminal and JSON report generators for mcp-audit."""

from __future__ import annotations

import json
import os
import sys
from typing import TYPE_CHECKING

from mcp_audit.models import AuditReport, Severity

if TYPE_CHECKING:
    pass


# ANSI Color Codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[1;35m",  # Bold Magenta
    Severity.HIGH: "\033[1;31m",      # Bold Red
    Severity.MEDIUM: "\033[1;33m",    # Bold Yellow
    Severity.LOW: "\033[34m",         # Blue
    Severity.INFO: "\033[36m",        # Cyan
}


def should_use_color(no_color: bool = False) -> bool:
    """Determine whether color output should be enabled."""
    if no_color:
        return False
    if "NO_COLOR" in os.environ:
        return False
    # Check if stdout is interactive
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def format_json_report(
    report: AuditReport,
    server_filter: str | None = None,
    min_severity: Severity | None = None,
) -> str:
    """Generate a clean, reproducible JSON report."""
    data = report.to_dict()

    # Apply filters to JSON findings if specified
    if server_filter:
        data["findings"] = [f for f in data["findings"] if f["server"] == server_filter]

    if min_severity:
        data["findings"] = [f for f in data["findings"] if Severity(f["severity"]) >= min_severity]

    return json.dumps(data, indent=2, ensure_ascii=False)


def format_terminal_report(
    report: AuditReport,
    server_filter: str | None = None,
    min_severity: Severity | None = None,
    use_color: bool = True,
) -> str:
    """Generate clean, transparent terminal output adhering to mcp-audit standards."""
    lines: list[str] = []

    def c(code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if use_color else text

    # Handle parsing errors first if configuration failed
    if report.errors:
        lines.append(c(BOLD + RED, "Configuration error"))
        lines.append("")
        for err in report.configuration.errors:
            lines.append(c(BOLD, "File:"))
            lines.append(f"  {err.file_path}")
            lines.append("")
            lines.append(c(BOLD, "Problem:"))
            lines.append(f"  {err.problem}")
            lines.append("")
            lines.append(c(BOLD, "Expected:"))
            for exp_line in err.expected.split("\n"):
                lines.append(f"  {exp_line}")
            lines.append("")
            if err.suggestion:
                lines.append(c(BOLD, "Suggestion:"))
                lines.append(f"  {err.suggestion}")
                lines.append("")

        lines.append(c(DIM, "No servers were executed."))
        lines.append(c(DIM, "No files were modified."))
        return "\n".join(lines)

    # Header
    lines.append(c(BOLD + CYAN, "mcp-audit"))
    lines.append("=========")
    lines.append("")
    lines.append(c(BOLD, "Configuration:"))
    lines.append(f"  {report.manifest.input_file}")
    lines.append("")
    lines.append(c(BOLD, "Servers:"))
    lines.append(f"  {report.manifest.servers_count}")
    lines.append("")
    lines.append(c(BOLD, "Tools:"))
    lines.append(f"  {report.manifest.tools_count}")
    lines.append("")
    lines.append(c(BOLD, "Estimated context:"))
    lines.append(f"  ~{report.total_estimated_tokens:,} tokens")
    lines.append("")

    # Parsing warnings summary if any exist
    if report.warnings:
        lines.append(c(BOLD + YELLOW, "Parsing summary"))
        lines.append("---------------")
        lines.append(f"Servers discovered: {report.manifest.servers_count}")
        lines.append(f"Warnings / notices: {len(report.warnings)}")
        for warn in report.warnings[:5]:
            lines.append(f"  • {warn}")
        if len(report.warnings) > 5:
            lines.append(f"  ... and {len(report.warnings) - 5} more warnings")
        lines.append("")

    # Limits reached warning if any
    if report.limits_reached:
        lines.append(c(BOLD + YELLOW, "⚠ Analysis Limits Reached"))
        lines.append("-----------------------")
        for lim in report.limits_reached:
            lines.append(f"  {lim}")
        lines.append(c(DIM, "Use CLI options (--max-file-size, etc.) to adjust limits if needed."))
        lines.append("")

    # Capabilities Breakdown
    lines.append(c(BOLD, "Capabilities"))
    lines.append("------------")
    cap_items = [
        ("READ", report.capability_counts.get("READ", 0)),
        ("WRITE", report.capability_counts.get("WRITE", 0)),
        ("DELETE", report.capability_counts.get("DELETE", 0)),
        ("EXECUTE", report.capability_counts.get("EXECUTE", 0)),
        ("NETWORK", report.capability_counts.get("NETWORK", 0)),
        ("AUTHENTICATION", report.capability_counts.get("AUTHENTICATION", 0)),
        ("SENSITIVE_DATA", report.capability_counts.get("SENSITIVE_DATA", 0)),
    ]
    if report.capability_counts.get("UNKNOWN", 0) > 0:
        cap_items.append(("UNKNOWN", report.capability_counts.get("UNKNOWN", 0)))

    for cap_name, count in cap_items:
        lines.append(f"{cap_name + ':':<16} {count:>4}")
    lines.append("")

    # Filter findings
    filtered_findings = report.findings
    if server_filter:
        filtered_findings = [f for f in filtered_findings if f.server == server_filter]
    if min_severity:
        filtered_findings = [f for f in filtered_findings if f.severity >= min_severity]

    # Findings summary count
    severity_order = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    severity_counts = {s: sum(1 for f in filtered_findings if f.severity == s) for s in severity_order}

    lines.append(c(BOLD, "Findings"))
    lines.append("--------")
    for sev in severity_order:
        count = severity_counts[sev]
        color_code = SEVERITY_COLORS.get(sev, "")
        sev_label = c(color_code + BOLD, f"{sev.value:<10}")
        lines.append(f"{sev_label} {count:>3}")
    lines.append("")

    # Detailed Findings grouped by severity
    for sev in severity_order:
        sev_findings = [f for f in filtered_findings if f.severity == sev]
        if not sev_findings:
            continue

        color_code = SEVERITY_COLORS.get(sev, "")
        lines.append(c(color_code + BOLD, sev.value))
        lines.append("-" * len(sev.value))

        for f in sev_findings:
            target = f"[{f.server}.{f.tool}]" if f.tool else f"[{f.server}]"
            lines.append(c(BOLD, target))
            lines.append(f.title)
            lines.append("")
            lines.append(c(DIM, "Observed:"))
            lines.append(f"  {f.description}")
            lines.append("")
            lines.append(c(DIM, "Evidence:"))
            lines.append(f"  {f.evidence}")
            lines.append("")
            lines.append(c(DIM, "Recommendation:"))
            lines.append(f"  {f.recommendation}")
            lines.append("")
            lines.append(c(DIM, f"Confidence: {f.confidence.value}"))
            lines.append("")

    # Context Footprint by Server
    lines.append(c(BOLD, "Context"))
    lines.append("-------")
    sorted_servers = sorted(
        report.server_tokens.items(),
        key=lambda x: x[1],
        reverse=True,
    )
    if sorted_servers:
        for srv_name, tokens in sorted_servers:
            lines.append(f"{srv_name:<20} ~{tokens:,} tokens")
    else:
        lines.append(c(DIM, "No servers configured"))
    lines.append("")

    # Disclaimer
    lines.append(c(BOLD, "Disclaimer"))
    lines.append("----------")
    lines.append(c(DIM, "mcp-audit provides heuristic analysis of MCP configurations and is not a"))
    lines.append(c(DIM, "formal security certification or guarantee. Developers remain responsible"))
    lines.append(c(DIM, "for reviewing MCP servers, permissions, credentials, and data exposed to AI systems."))
    lines.append("")

    # Safe Footer Guarantee
    lines.append(c(BOLD, "Guarantees"))
    lines.append("----------")
    lines.append(c(GREEN, "✓ No MCP servers were started."))
    lines.append(c(GREEN, "✓ No files were modified."))
    lines.append(c(GREEN, "✓ No data was uploaded."))

    return "\n".join(lines)
