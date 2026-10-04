"""Unit tests for configuration parser and normalizer."""

from __future__ import annotations

import os
import tempfile

import pytest

from mcp_audit.limits import AnalysisLimits, FileSizeExceededError
from mcp_audit.parser import MCPConfigParser


@pytest.fixture
def fixtures_dir() -> str:
    return os.path.join(os.path.dirname(__file__), "fixtures")


def test_parse_safe_config(fixtures_dir: str):
    safe_path = os.path.join(fixtures_dir, "safe.json")
    parser = MCPConfigParser()
    config = parser.parse_file(safe_path)

    assert config.configuration_hash.startswith("sha256:")
    assert len(config.servers) == 2
    assert "git" in config.servers
    assert "docs-helper" in config.servers
    assert len(config.errors) == 0

    git_server = config.servers["git"]
    assert git_server.command == "git-mcp"
    assert len(git_server.tools) == 2
    assert git_server.tools[0].name == "get_status"
    assert git_server.env.get("GIT_AUTHOR_NAME") == "Developer"


def test_parse_direct_server_map():
    raw_json = """
    {
      "my_server": {
        "command": "python",
        "args": ["server.py"]
      }
    }
    """
    parser = MCPConfigParser()
    config = parser.parse_string(raw_json)

    assert len(config.servers) == 1
    assert "my_server" in config.servers
    assert config.servers["my_server"].command == "python"
    assert len(config.errors) == 0


def test_parse_invalid_json_syntax():
    invalid_json = '{"mcpServers": { "bad": '
    parser = MCPConfigParser()
    config = parser.parse_string(invalid_json)

    assert len(config.errors) == 1
    error = config.errors[0]
    assert "Invalid JSON syntax" in error.problem
    assert "No servers were executed" in error.message


def test_parse_empty_content():
    parser = MCPConfigParser()
    config = parser.parse_string("   ")

    assert len(config.errors) == 1
    assert "empty" in config.errors[0].problem.lower()


def test_parse_non_dict_root():
    parser = MCPConfigParser()
    config = parser.parse_string("[1, 2, 3]")

    assert len(config.errors) == 1
    assert "must be a JSON object" in config.errors[0].problem


def test_parse_missing_mcpservers():
    parser = MCPConfigParser()
    config = parser.parse_string('{"unrelated": 123}')

    assert len(config.errors) == 1
    assert 'Missing "mcpServers" section' in config.errors[0].problem


def test_parse_malformed_server_definitions(fixtures_dir: str):
    malformed_path = os.path.join(fixtures_dir, "malformed.json")
    parser = MCPConfigParser()
    config = parser.parse_file(malformed_path)

    assert len(config.servers) == 2  # valid_server and malformed_server_2
    assert "valid_server" in config.servers
    assert len(config.warnings) >= 3

    # Check that warnings captured issues
    warning_msgs = [w.message for w in config.warnings]
    assert any("must be an object" in msg for msg in warning_msgs)
    assert any("command must be a string" in msg for msg in warning_msgs)


def test_parse_file_size_exceeded():
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write('{"mcpServers": {"test": {"command": "echo"}}}')
        temp_path = f.name

    try:
        # Set limit very low (10 bytes)
        parser = MCPConfigParser(limits=AnalysisLimits(max_file_size=10))
        with pytest.raises(FileSizeExceededError):
            parser.parse_file(temp_path)
    finally:
        os.unlink(temp_path)


def test_parse_file_not_found():
    parser = MCPConfigParser()
    with pytest.raises(FileNotFoundError):
        parser.parse_file("non_existent_file_xyz_123.json")
