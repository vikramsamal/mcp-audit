"""Unit tests for CLI interface, arguments, and exit codes."""

from __future__ import annotations

import json
import os

import pytest

from mcp_audit.cli import main


@pytest.fixture
def fixtures_dir() -> str:
    return os.path.join(os.path.dirname(__file__), "fixtures")


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "mcp-audit" in captured.out
    assert "Exit codes:" in captured.out


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "mcp-audit 0.1.0" in captured.out


def test_cli_no_args(capsys):
    code = main([])
    assert code == 2
    captured = capsys.readouterr()
    assert "usage:" in captured.err.lower() or "mcp-audit" in captured.err


def test_cli_safe_file(fixtures_dir: str, capsys):
    safe_path = os.path.join(fixtures_dir, "safe.json")
    code = main([safe_path, "--no-color"])
    assert code == 0
    captured = capsys.readouterr()
    assert "mcp-audit" in captured.out
    assert "Servers:" in captured.out
    assert "✓ No MCP servers were started." in captured.out


def test_cli_json_output(fixtures_dir: str, capsys):
    safe_path = os.path.join(fixtures_dir, "safe.json")
    code = main([safe_path, "--json"])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["manifest"]["servers_count"] == 2


def test_cli_server_filter(fixtures_dir: str, capsys):
    safe_path = os.path.join(fixtures_dir, "safe.json")
    code = main([safe_path, "--server", "git", "--json"])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    for f in data["findings"]:
        assert f["server"] == "git"


def test_cli_fail_on_triggered(fixtures_dir: str, capsys):
    risky_path = os.path.join(fixtures_dir, "risky.json")
    # risky.json contains HIGH findings
    code = main([risky_path, "--fail-on", "high"])
    assert code == 1


def test_cli_fail_on_not_triggered(fixtures_dir: str, capsys):
    safe_path = os.path.join(fixtures_dir, "safe.json")
    # safe.json has no CRITICAL findings
    code = main([safe_path, "--fail-on", "critical"])
    assert code == 0


def test_cli_file_not_found(capsys):
    code = main(["non_existent_file_987.json"])
    assert code == 2
    captured = capsys.readouterr()
    assert "Configuration error" in captured.err or "not found" in captured.err


def test_cli_malformed_json_returns_code_2(fixtures_dir: str, capsys):
    # Testing a syntax-broken JSON file
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write("{ invalid json")
        tmp_name = f.name

    try:
        code = main([tmp_name])
        assert code == 2
        captured = capsys.readouterr()
        assert "Configuration error" in captured.out or "Configuration error" in captured.err
    finally:
        os.unlink(tmp_name)
