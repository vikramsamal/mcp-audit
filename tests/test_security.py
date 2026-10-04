"""Security tests for mcp-audit.

Verifies:
1. Never executes configured commands (read-only verification)
2. No outbound network requests
3. No configuration file modification
4. Secret redaction in all outputs
5. Giant input & resource bounds safety
6. False-positive resistance for documentation phrases
"""

from __future__ import annotations

import hashlib
import os
import socket
import subprocess

import pytest

from mcp_audit.analyzer import MCPAnalyzer
from mcp_audit.capabilities import classify_tool_capabilities
from mcp_audit.limits import AnalysisLimits
from mcp_audit.models import Capability
from mcp_audit.reporter import format_json_report, format_terminal_report


@pytest.fixture
def fixtures_dir() -> str:
    return os.path.join(os.path.dirname(__file__), "fixtures")


def test_security_never_executes_configuration(monkeypatch, tmp_path):
    """Verify that dangerous strings in configuration are treated strictly as data."""
    should_not_exist_file = tmp_path / "SHOULD_NOT_EXIST"
    if should_not_exist_file.exists():
        should_not_exist_file.unlink()

    config_content = f"""
    {{
      "mcpServers": {{
        "malicious_server": {{
          "command": "touch {should_not_exist_file}",
          "args": ["&&", "rm", "-rf", "/tmp/non_existent_folder_test", "||", "python", "-c", "import sys; sys.exit(1)"]
        }}
      }}
    }}
    """
    config_file = tmp_path / "dangerous_config.json"
    config_file.write_text(config_content)

    # Spy on subprocess execution to ensure nothing is invoked
    def forbidden_call(*args, **kwargs):
        raise AssertionError("SECURITY BREACH: A subprocess or shell command was executed!")

    monkeypatch.setattr(subprocess, "Popen", forbidden_call)
    monkeypatch.setattr(subprocess, "run", forbidden_call)
    monkeypatch.setattr(os, "system", forbidden_call)

    analyzer = MCPAnalyzer()
    report = analyzer.analyze_file(str(config_file))

    # Assert SHOULD_NOT_EXIST was NEVER created
    assert not should_not_exist_file.exists(), "SECURITY VIOLATION: File was created by config execution!"

    # Assert findings were recorded purely as data
    assert len(report.findings) > 0


def test_security_no_network_calls(monkeypatch, fixtures_dir):
    """Verify that the tool operates 100% offline and opens zero network connections."""
    def forbidden_connect(*args, **kwargs):
        raise AssertionError("SECURITY BREACH: Network socket connection attempted!")

    monkeypatch.setattr(socket.socket, "connect", forbidden_connect)

    analyzer = MCPAnalyzer()
    safe_path = os.path.join(fixtures_dir, "safe.json")
    risky_path = os.path.join(fixtures_dir, "risky.json")

    # Run multiple audits
    report_safe = analyzer.analyze_file(safe_path)
    report_risky = analyzer.analyze_file(risky_path)

    assert report_safe.total_estimated_tokens > 0
    assert report_risky.total_estimated_tokens > 0


def test_security_no_configuration_modification(fixtures_dir):
    """Verify that audited files are never modified (read-only behavior)."""
    target_file = os.path.join(fixtures_dir, "risky.json")

    with open(target_file, "rb") as f:
        hash_before = hashlib.sha256(f.read()).hexdigest()

    analyzer = MCPAnalyzer()
    report = analyzer.analyze_file(target_file)

    with open(target_file, "rb") as f:
        hash_after = hashlib.sha256(f.read()).hexdigest()

    assert hash_before == hash_after, "SECURITY VIOLATION: Configuration file content was modified!"
    assert report.configuration.configuration_hash == f"sha256:{hash_before}"


def test_security_secret_redaction(capsys):
    """Verify secrets are redacted in terminal, JSON, and report structures."""
    secret_raw_value = "SUPER_SECRET_API_TOKEN_99999_XYZ"
    config_content = f"""
    {{
      "mcpServers": {{
        "github": {{
          "command": "node",
          "env": {{
            "GITHUB_TOKEN": "{secret_raw_value}",
            "AWS_SECRET_ACCESS_KEY": "ANOTHER_SECRET_VALUE_888"
          }}
        }}
      }}
    }}
    """
    analyzer = MCPAnalyzer()
    report = analyzer.analyze_string(config_content)

    term_output = format_terminal_report(report, use_color=False)
    json_output = format_json_report(report)

    # 1. The literal secret MUST NOT appear in terminal output
    assert secret_raw_value not in term_output
    assert "ANOTHER_SECRET_VALUE_888" not in term_output

    # 2. The literal secret MUST NOT appear in JSON report
    assert secret_raw_value not in json_output
    assert "ANOTHER_SECRET_VALUE_888" not in json_output

    # 3. Redacted placeholder must be present
    assert "[REDACTED]" in term_output
    assert "[REDACTED]" in json_output


def test_security_giant_input_bounds():
    """Verify memory safety and bounded processing for giant inputs."""
    huge_text = "A" * 500_000  # 500 KB string
    raw_config = f"""
    {{
      "mcpServers": {{
        "bloated": {{
          "command": "echo",
          "tools": [
            {{
              "name": "huge_tool",
              "description": "{huge_text}"
            }}
          ]
        }}
      }}
    }}
    """
    # Set limit to 20,000 characters
    limits = AnalysisLimits(max_description_size=20_000)
    analyzer = MCPAnalyzer(limits=limits)
    report = analyzer.analyze_string(raw_config)

    # Process did not crash and truncated description
    assert len(report.limits_reached) > 0
    tool = report.configuration.servers["bloated"].tools[0]
    assert len(tool.description) <= 20_000
    assert tool.is_truncated is True


def test_security_false_positive_immunity():
    """Verify documentation and explanation phrases are not falsely flagged as destructive capabilities."""
    cases = [
        ("search_help", "Returns documentation explaining how to delete files in Linux."),
        ("docs_browser", "Searches manuals for database commands like DROP TABLE and TRUNCATE."),
        ("guide_lookup", "Provides guides on bash terminal execution and shell scripts."),
    ]

    for tool_name, tool_desc in cases:
        caps = classify_tool_capabilities(
            tool_name=tool_name,
            tool_desc=tool_desc,
            parameters=["search_term"],
        )
        cap_types = [c.capability for c in caps]
        assert Capability.DELETE not in cap_types, f"False positive DELETE on {tool_name}"
        assert Capability.EXECUTE not in cap_types, f"False positive EXECUTE on {tool_name}"
        assert Capability.READ in cap_types, f"Expected READ for doc search on {tool_name}"
