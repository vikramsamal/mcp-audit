"""Unit tests for report formatters."""

from __future__ import annotations

import json

from mcp_audit.analyzer import MCPAnalyzer
from mcp_audit.models import Severity
from mcp_audit.reporter import format_json_report, format_terminal_report


def test_terminal_report_safe():
    analyzer = MCPAnalyzer()
    raw = """
    {
      "mcpServers": {
        "git": {
          "command": "git-mcp",
          "args": ["/workspace/repo"]
        }
      }
    }
    """
    report = analyzer.analyze_string(raw, file_path="config.json")
    output = format_terminal_report(report, use_color=False)

    assert "mcp-audit" in output
    assert "Configuration:" in output
    assert "Servers:" in output
    assert "Capabilities" in output
    assert "No MCP servers were started." in output
    assert "No files were modified." in output
    assert "No data was uploaded." in output


def test_json_report_structure():
    analyzer = MCPAnalyzer()
    raw = """
    {
      "mcpServers": {
        "github": {
          "command": "node",
          "env": {
            "GITHUB_TOKEN": "FAKE_SECRET_VAL"
          }
        }
      }
    }
    """
    report = analyzer.analyze_string(raw, file_path="config.json")
    json_str = format_json_report(report)
    parsed = json.loads(json_str)

    assert "manifest" in parsed
    assert "findings" in parsed
    assert "context_footprint" in parsed
    assert parsed["manifest"]["servers_count"] == 1

    # Ensure fake secret is redacted from json
    assert "FAKE_SECRET_VAL" not in json_str
    assert "[REDACTED]" in json_str


def test_reporter_severity_filtering():
    analyzer = MCPAnalyzer()
    raw = """
    {
      "mcpServers": {
        "srv": {
          "command": "/bin/bash",
          "env": {
            "API_KEY": "${API_KEY}"
          }
        }
      }
    }
    """
    report = analyzer.analyze_string(raw)
    high_only_json = format_json_report(report, min_severity=Severity.HIGH)
    parsed_high = json.loads(high_only_json)
    # Bash is MEDIUM, env ref is INFO -> 0 findings at HIGH level
    assert len(parsed_high["findings"]) == 0
