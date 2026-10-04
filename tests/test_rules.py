"""Unit tests for audit rules engine."""

from __future__ import annotations

from mcp_audit.models import (
    FindingCategory,
    MCPServer,
    MCPTool,
    Severity,
)
from mcp_audit.rules import (
    check_command_and_arguments,
    check_filesystem_paths,
    check_overlapping_tools,
    check_secrets,
    check_tool_capabilities_and_bloat,
)


def test_secrets_literal_detection():
    server = MCPServer(
        name="github",
        env={
            "GITHUB_TOKEN": "FAKE_SECRET_12345",
            "UNRELATED_VAR": "hello",
        },
    )
    findings = check_secrets(server)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.category == FindingCategory.SECRETS
    assert "GITHUB_TOKEN=[REDACTED]" in f.evidence
    assert "FAKE_SECRET_12345" not in f.evidence
    assert "FAKE_SECRET_12345" not in f.description


def test_secrets_env_var_reference():
    server = MCPServer(
        name="github",
        env={
            "GITHUB_TOKEN": "${GITHUB_TOKEN}",
            "API_KEY": "$MY_API_KEY",
        },
    )
    findings = check_secrets(server)
    assert len(findings) == 2
    for f in findings:
        assert f.severity == Severity.INFO
        assert f.category == FindingCategory.SECRETS
        assert "environment variable" in f.description.lower()


def test_command_shell_analysis():
    server = MCPServer(
        name="local-shell",
        command="/bin/bash",
        args=["-c", "start"],
    )
    findings = check_command_and_arguments(server)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].category == FindingCategory.COMMAND_EXECUTION
    assert "Shell execution capability detected" in findings[0].title


def test_dangerous_arguments():
    server = MCPServer(
        name="docker-runner",
        command="docker",
        args=["run", "--privileged", "--no-sandbox", "-v", "/:/host"],
    )
    findings = check_command_and_arguments(server)
    # Container finding + dangerous args findings
    assert any(f.severity == Severity.HIGH and "--privileged" in f.evidence for f in findings)
    assert any(f.severity == Severity.HIGH and "--no-sandbox" in f.evidence for f in findings)


def test_broad_filesystem_paths():
    server = MCPServer(
        name="fs",
        command="filesystem-server",
        args=["/home"],
    )
    findings = check_filesystem_paths(server)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].category == FindingCategory.FILESYSTEM
    assert "Broad filesystem access detected" in findings[0].title


def test_restricted_filesystem_paths():
    server = MCPServer(
        name="fs",
        command="filesystem-server",
        args=["--path", "/workspace/project/docs"],
    )
    findings = check_filesystem_paths(server)
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert "restricted" in findings[0].recommendation.lower() or "boundary" in findings[0].description.lower() or "scope" in findings[0].recommendation.lower()


def test_context_bloat_detection():
    tool = MCPTool(
        name="search_everything",
        description="A" * 5000,
        estimated_tokens=2500,
    )
    server = MCPServer(name="test", tools=[tool])
    findings = check_tool_capabilities_and_bloat(server, large_tool_threshold=1500)
    assert any(f.category == FindingCategory.CONTEXT_BLOAT for f in findings)


def test_overlapping_tools_detection():
    tool1 = MCPTool(name="search_files", description="Searches for files.")
    tool2 = MCPTool(name="find_files", description="Finds files.")
    server = MCPServer(name="fs", tools=[tool1, tool2])
    findings = check_overlapping_tools(server)
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.TOOL_OVERLAP
    assert "search_files" in findings[0].evidence
    assert "find_files" in findings[0].evidence
