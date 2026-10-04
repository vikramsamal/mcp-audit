"""Unit tests for top-level MCPAnalyzer."""

from __future__ import annotations

import os

import pytest

from mcp_audit.analyzer import MCPAnalyzer
from mcp_audit.models import FindingCategory, Severity


@pytest.fixture
def fixtures_dir() -> str:
    return os.path.join(os.path.dirname(__file__), "fixtures")


def test_analyzer_safe_fixture(fixtures_dir: str):
    analyzer = MCPAnalyzer()
    report = analyzer.analyze_file(os.path.join(fixtures_dir, "safe.json"))

    assert report.manifest.servers_count == 2
    assert report.manifest.tools_count == 3
    assert report.total_estimated_tokens > 0
    assert report.capability_counts.get("READ", 0) >= 3
    assert report.capability_counts.get("DELETE", 0) == 0
    assert len(report.errors) == 0

    # No high findings
    high_findings = [f for f in report.findings if f.severity >= Severity.HIGH]
    assert len(high_findings) == 0


def test_analyzer_risky_fixture(fixtures_dir: str):
    analyzer = MCPAnalyzer()
    report = analyzer.analyze_file(os.path.join(fixtures_dir, "risky.json"))

    assert report.manifest.servers_count == 4
    assert len(report.findings) > 0

    # Check high findings (filesystem, secret, dangerous args)
    high_findings = [f for f in report.findings if f.severity == Severity.HIGH]
    assert len(high_findings) >= 2

    # Check categories
    categories = {f.category for f in report.findings}
    assert FindingCategory.FILESYSTEM in categories
    assert FindingCategory.COMMAND_EXECUTION in categories
    assert FindingCategory.SECRETS in categories
    assert FindingCategory.CONTEXT_BLOAT in categories
    assert FindingCategory.TOOL_OVERLAP in categories


def test_analyzer_edge_cases(fixtures_dir: str):
    analyzer = MCPAnalyzer()
    report = analyzer.analyze_file(os.path.join(fixtures_dir, "edge_cases.json"))

    assert report.manifest.servers_count == 2
    # Verify unicode handling didn't crash
    assert any("🚀" in s for s in report.configuration.servers.keys())
