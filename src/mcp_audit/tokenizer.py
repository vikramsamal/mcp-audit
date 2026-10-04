"""Deterministic token estimation for MCP configurations and tool definitions.

Note: All token calculations are estimates based on standard BPE / subword
averages (~3.8 - 4.0 characters per token for JSON and technical text)
and structural syntax overhead. They should be presented as 'Estimated tokens'.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp_audit.models import MCPConfiguration, MCPServer, MCPTool


def estimate_text_tokens(text: str | None) -> int:
    """Estimate token count for a text string.

    Uses a deterministic heuristic based on character length and word count:
    - ~3.8 characters per token for prose and technical text
    - accounts for punctuation and whitespace overhead
    """
    if not text:
        return 0

    stripped = text.strip()
    if not stripped:
        return 0

    # Words + punctuation heuristic
    words = stripped.split()
    word_count = len(words)
    char_count = len(stripped)

    # Blend character length and word count to account for technical symbols / camelCase
    # Average subword token is roughly 3.8 chars in modern tokenizers
    estimate = int((char_count / 3.8) * 0.7 + (word_count * 1.3) * 0.3)
    return max(1, estimate)


def estimate_schema_tokens(schema: dict[str, Any] | None) -> int:
    """Estimate token count for a JSON schema object."""
    if not schema or not isinstance(schema, dict):
        return 0

    try:
        compact_json = json.dumps(schema, separators=(",", ":"), ensure_ascii=False)
        return estimate_text_tokens(compact_json)
    except (TypeError, ValueError):
        # Fallback if non-serializable elements exist
        return estimate_text_tokens(str(schema))


def estimate_tool_tokens(tool: MCPTool) -> int:
    """Estimate total context footprint for a single MCP tool definition.

    Calculates:
    - Tool name and formatting
    - Tool description
    - Input schema representation (properties, types, descriptions, required)
    - System protocol framing overhead (~15 tokens per tool for XML/JSON tag markers)
    """
    tokens = 0
    # Tool name & protocol wrapper overhead
    tokens += estimate_text_tokens(tool.name) + 15

    # Description
    if tool.description:
        tokens += estimate_text_tokens(tool.description)

    # Input schema
    if tool.input_schema:
        tokens += estimate_schema_tokens(tool.input_schema)

    return max(1, tokens)


def estimate_server_tokens(server: MCPServer) -> int:
    """Estimate total context footprint contributed by an MCP server.

    Calculates:
    - Server identifier and metadata overhead (~25 tokens)
    - Sum of all tool definitions
    - Sum of all resource definitions
    """
    tokens = 25 + estimate_text_tokens(server.name)

    # Server tools
    for tool in server.tools:
        tokens += estimate_tool_tokens(tool)

    # Server resources
    for resource in server.resources:
        tokens += estimate_text_tokens(resource.uri)
        tokens += estimate_text_tokens(resource.name)
        tokens += estimate_text_tokens(resource.description) + 10

    return tokens


def estimate_context_footprint(
    config: MCPConfiguration,
) -> tuple[int, dict[str, int]]:
    """Calculate total estimated context footprint and breakdown by server.

    Returns:
        (total_estimated_tokens, {server_name: estimated_tokens})
    """
    server_breakdown: dict[str, int] = {}
    total_tokens = 0

    for server_name, server in config.servers.items():
        server_tok = estimate_server_tokens(server)
        server.estimated_tokens = server_tok

        # Also populate estimated tokens on each tool
        for tool in server.tools:
            tool.estimated_tokens = estimate_tool_tokens(tool)

        server_breakdown[server_name] = server_tok
        total_tokens += server_tok

    return total_tokens, server_breakdown
