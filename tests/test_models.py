"""Unit tests for models, enums, and data structures."""

from __future__ import annotations

from mcp_audit.models import (
    AuditManifest,
    AuditReport,
    Capability,
    CapabilityAssessment,
    Confidence,
    Finding,
    FindingCategory,
    MCPConfiguration,
    MCPServer,
    MCPTool,
    Severity,
)


def test_severity_ordering():
    assert Severity.INFO < Severity.LOW
    assert Severity.LOW < Severity.MEDIUM
    assert Severity.MEDIUM < Severity.HIGH
    assert Severity.HIGH < Severity.CRITICAL

    assert Severity.HIGH >= Severity.HIGH
    assert Severity.HIGH >= Severity.MEDIUM
    assert Severity.HIGH >= "medium"
    assert Severity.LOW <= "high"
    assert not (Severity.LOW > Severity.HIGH)


def test_capability_enums():
    assert str(Capability.READ) == "READ"
    assert str(Capability.WRITE) == "WRITE"
    assert str(Capability.DELETE) == "DELETE"
    assert str(Capability.EXECUTE) == "EXECUTE"
    assert str(Capability.NETWORK) == "NETWORK"
    assert str(Capability.AUTHENTICATION) == "AUTHENTICATION"
    assert str(Capability.SENSITIVE_DATA) == "SENSITIVE_DATA"
    assert str(Capability.UNKNOWN) == "UNKNOWN"


def test_finding_to_dict():
    finding = Finding(
        severity=Severity.HIGH,
        category=FindingCategory.SECRETS,
        server="github",
        tool="search",
        title="Potential secret detected",
        description="Observed secret",
        evidence="GITHUB_TOKEN=[REDACTED]",
        recommendation="Use env var",
        confidence=Confidence.HIGH,
    )

    data = finding.to_dict()
    assert data["severity"] == "HIGH"
    assert data["category"] == "SECRETS"
    assert data["server"] == "github"
    assert data["tool"] == "search"
    assert data["evidence"] == "GITHUB_TOKEN=[REDACTED]"
    assert data["confidence"] == "HIGH"


def test_audit_report_to_dict():
    tool = MCPTool(
        name="test_tool",
        description="A test tool",
        parameters=["param1"],
        capabilities=[
            CapabilityAssessment(
                capability=Capability.READ,
                confidence=Confidence.HIGH,
                evidence="name matches",
                source="tool_name",
            )
        ],
    )
    server = MCPServer(
        name="test_server",
        command="test-bin",
        tools=[tool],
    )
    config = MCPConfiguration(
        file_path="test.json",
        configuration_hash="sha256:123456",
        servers={"test_server": server},
    )
    manifest = AuditManifest(
        tool_version="0.1.0",
        timestamp="2026-10-04T00:00:00Z",
        input_file="test.json",
        configuration_hash="sha256:123456",
        servers_count=1,
        tools_count=1,
        estimated_context_tokens=150,
        analysis_limits={},
    )
    report = AuditReport(
        manifest=manifest,
        configuration=config,
        findings=[],
        capability_counts={"READ": 1},
        server_tokens={"test_server": 150},
        total_estimated_tokens=150,
    )

    dict_report = report.to_dict()
    assert dict_report["manifest"]["tool_version"] == "0.1.0"
    assert dict_report["configuration"]["file_path"] == "test.json"
    assert dict_report["context_footprint"]["total_estimated_tokens"] == 150
    assert "test_server" in dict_report["configuration"]["servers"]
