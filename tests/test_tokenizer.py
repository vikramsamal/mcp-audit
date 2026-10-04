"""Unit tests for tokenizer and context bloat estimation."""

from __future__ import annotations

from mcp_audit.models import MCPServer, MCPTool
from mcp_audit.tokenizer import (
    estimate_schema_tokens,
    estimate_server_tokens,
    estimate_text_tokens,
    estimate_tool_tokens,
)


def test_estimate_text_tokens_empty():
    assert estimate_text_tokens("") == 0
    assert estimate_text_tokens("   ") == 0


def test_estimate_text_tokens_basic():
    text = "Hello world, this is a test tool description."
    tok = estimate_text_tokens(text)
    assert 5 <= tok <= 20


def test_estimate_schema_tokens():
    schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query"},
            "limit": {"type": "integer"},
        },
        "required": ["query"],
    }
    tok = estimate_schema_tokens(schema)
    assert tok > 10


def test_estimate_tool_and_server_tokens():
    tool = MCPTool(
        name="test_tool",
        description="A helpful description for this MCP tool.",
        input_schema={"type": "object", "properties": {"input": {"type": "string"}}},
    )
    server = MCPServer(
        name="test_server",
        command="test-bin",
        tools=[tool],
    )

    tool_tok = estimate_tool_tokens(tool)
    assert tool_tok > 15

    server_tok = estimate_server_tokens(server)
    assert server_tok > tool_tok
