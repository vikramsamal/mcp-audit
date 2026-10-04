"""mcp-audit: Local, read-only MCP server security, permission, risk & context audit tool."""

__version__ = "0.1.0"
__author__ = "mcp-audit contributors"
__license__ = "MIT"

from mcp_audit.analyzer import MCPAnalyzer
from mcp_audit.models import (
    AuditManifest,
    AuditReport,
    Capability,
    Confidence,
    Finding,
    FindingCategory,
    MCPConfiguration,
    MCPServer,
    MCPTool,
    Severity,
)
from mcp_audit.parser import MCPConfigParser

__all__ = [
    "__version__",
    "AuditManifest",
    "AuditReport",
    "Capability",
    "Confidence",
    "Finding",
    "FindingCategory",
    "MCPAnalyzer",
    "MCPConfigParser",
    "MCPConfiguration",
    "MCPServer",
    "MCPTool",
    "Severity",
]
