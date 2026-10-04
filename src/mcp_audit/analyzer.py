"""Main analysis coordinator for mcp-audit."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from mcp_audit import __version__
from mcp_audit.limits import AnalysisLimits
from mcp_audit.models import (
    AuditManifest,
    AuditReport,
    Capability,
    Finding,
    MCPConfiguration,
)
from mcp_audit.parser import MCPConfigParser
from mcp_audit.rules import execute_all_rules
from mcp_audit.tokenizer import estimate_context_footprint


class MCPAnalyzer:
    """Coordinates parser, rules engine, capability classifier, and tokenizer."""

    def __init__(
        self,
        limits: AnalysisLimits | None = None,
        large_tool_threshold: int = 1_000,
    ):
        self.limits = limits or AnalysisLimits()
        self.large_tool_threshold = large_tool_threshold
        self.parser = MCPConfigParser(limits=self.limits)

    def analyze_file(self, file_path: str) -> AuditReport:
        """Run complete audit analysis on an MCP configuration file."""
        config = self.parser.parse_file(file_path)
        return self.analyze_configuration(config)

    def analyze_string(self, content: str, file_path: str = "inline.json") -> AuditReport:
        """Run complete audit analysis on a raw JSON configuration string."""
        config = self.parser.parse_string(content, file_path=file_path)
        return self.analyze_configuration(config)

    def analyze_configuration(self, config: MCPConfiguration) -> AuditReport:
        """Run complete analysis on a pre-parsed/normalized MCPConfiguration."""
        # Calculate context footprint
        total_tokens, server_tokens = estimate_context_footprint(config)

        # Execute security and quality rules
        findings: list[Finding] = []
        if not config.errors:
            findings = execute_all_rules(config, large_tool_threshold=self.large_tool_threshold)

        # Aggregate capability counts
        cap_counter: Counter[str] = Counter()
        tools_count = 0
        for server in config.servers.values():
            tools_count += len(server.tools)
            for tool in server.tools:
                for cap_assess in tool.capabilities:
                    cap_counter[cap_assess.capability.value] += 1

        # Populate all standard capabilities even if zero count for clean reporting
        cap_summary: dict[str, int] = {}
        for cap in Capability:
            if cap != Capability.UNKNOWN or cap_counter.get(Capability.UNKNOWN.value, 0) > 0:
                cap_summary[cap.value] = cap_counter.get(cap.value, 0)

        # Collect warning messages
        warnings_list: list[str] = [w.message for w in config.warnings]

        # Collect error messages
        errors_list: list[str] = [e.message for e in config.errors]

        # Audit manifest
        manifest = AuditManifest(
            tool_version=__version__,
            timestamp=datetime.now(UTC).isoformat(),
            input_file=config.file_path,
            configuration_hash=config.configuration_hash,
            servers_count=len(config.servers),
            tools_count=tools_count,
            estimated_context_tokens=total_tokens,
            analysis_limits=self.limits.to_dict(),
        )

        return AuditReport(
            manifest=manifest,
            configuration=config,
            findings=findings,
            capability_counts=cap_summary,
            server_tokens=server_tokens,
            total_estimated_tokens=total_tokens,
            warnings=warnings_list,
            errors=errors_list,
            limits_reached=config.limits_reached,
        )
