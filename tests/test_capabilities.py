"""Unit tests for capability classification and false positive immunity."""

from __future__ import annotations

from mcp_audit.capabilities import (
    classify_server_capabilities,
    classify_tool_capabilities,
)
from mcp_audit.models import Capability, Confidence, MCPServer


def test_classify_read_tool():
    caps = classify_tool_capabilities(
        tool_name="get_file_contents",
        tool_desc="Returns the content of the specified file.",
        parameters=["path"],
    )
    cap_types = [c.capability for c in caps]
    assert Capability.READ in cap_types
    assert Capability.DELETE not in cap_types
    assert Capability.WRITE not in cap_types


def test_classify_write_tool():
    caps = classify_tool_capabilities(
        tool_name="create_new_record",
        tool_desc="Creates a new database record in the collection.",
        parameters=["record_data"],
    )
    cap_types = [c.capability for c in caps]
    assert Capability.WRITE in cap_types
    assert Capability.DELETE not in cap_types


def test_classify_delete_tool():
    caps = classify_tool_capabilities(
        tool_name="delete_user_account",
        tool_desc="Permanently deletes the specified user account.",
        parameters=["user_id"],
    )
    cap_types = [c.capability for c in caps]
    assert Capability.DELETE in cap_types
    delete_cap = next(c for c in caps if c.capability == Capability.DELETE)
    assert delete_cap.confidence == Confidence.HIGH


def test_classify_execute_tool_by_param():
    caps = classify_tool_capabilities(
        tool_name="run_custom_job",
        tool_desc="Runs a customized processing script.",
        parameters=[],
        input_schema={"properties": {"command": {"type": "string"}}},
    )
    cap_types = [c.capability for c in caps]
    assert Capability.EXECUTE in cap_types


def test_classify_network_tool():
    caps = classify_tool_capabilities(
        tool_name="fetch_url_content",
        tool_desc="Makes an HTTP GET request to download web page HTML.",
        parameters=["url"],
    )
    cap_types = [c.capability for c in caps]
    assert Capability.NETWORK in cap_types


def test_false_positive_documentation_delete():
    # Crucial test: documentation search describing delete operation must NOT be classified as DELETE
    caps = classify_tool_capabilities(
        tool_name="search_documentation",
        tool_desc="Searches developer guides explaining how to delete obsolete resources.",
        parameters=["query"],
    )
    cap_types = [c.capability for c in caps]
    assert Capability.READ in cap_types
    assert Capability.DELETE not in cap_types
    assert Capability.EXECUTE not in cap_types


def test_false_positive_documentation_shell():
    caps = classify_tool_capabilities(
        tool_name="docs_viewer",
        tool_desc="Returns documentation manual for running shell commands in terminal.",
        parameters=["topic"],
    )
    cap_types = [c.capability for c in caps]
    assert Capability.READ in cap_types
    assert Capability.EXECUTE not in cap_types
    assert Capability.DELETE not in cap_types


def test_server_level_shell_capability():
    server = MCPServer(
        name="shell-server",
        command="/bin/bash",
        args=["-c", "agent"],
    )
    caps = classify_server_capabilities(server)
    cap_types = [c.capability for c in caps]
    assert Capability.EXECUTE in cap_types
    exec_cap = next(c for c in caps if c.capability == Capability.EXECUTE)
    assert exec_cap.confidence == Confidence.HIGH
