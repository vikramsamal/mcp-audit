"""Data models and enums for mcp-audit."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Capability(StrEnum):
    """Deterministic capability classification for MCP tools and servers."""

    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"
    EXECUTE = "EXECUTE"
    NETWORK = "NETWORK"
    AUTHENTICATION = "AUTHENTICATION"
    SENSITIVE_DATA = "SENSITIVE_DATA"
    UNKNOWN = "UNKNOWN"

    def __str__(self) -> str:
        return self.value


class Confidence(StrEnum):
    """Confidence level of heuristic classification or finding."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    def __str__(self) -> str:
        return self.value


class Severity(StrEnum):
    """Finding severity levels with comparison support."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def level(self) -> int:
        levels = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return levels[self]

    def __ge__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            other = Severity(other.upper())
        return self.level >= other.level

    def __gt__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            other = Severity(other.upper())
        return self.level > other.level

    def __le__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            other = Severity(other.upper())
        return self.level <= other.level

    def __lt__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            other = Severity(other.upper())
        return self.level < other.level

    def __str__(self) -> str:
        return self.value


class FindingCategory(StrEnum):
    """Categorization for audit findings."""

    FILESYSTEM = "FILESYSTEM"
    COMMAND_EXECUTION = "COMMAND_EXECUTION"
    WRITE_ACCESS = "WRITE_ACCESS"
    DELETE_ACCESS = "DELETE_ACCESS"
    NETWORK_ACCESS = "NETWORK_ACCESS"
    SECRETS = "SECRETS"
    AUTHENTICATION = "AUTHENTICATION"
    CONTEXT_BLOAT = "CONTEXT_BLOAT"
    TOOL_OVERLAP = "TOOL_OVERLAP"
    CONFIGURATION = "CONFIGURATION"
    UNKNOWN = "UNKNOWN"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class CapabilityAssessment:
    """Individual capability determination for a tool or server."""

    capability: Capability
    confidence: Confidence
    evidence: str
    source: str  # "tool_name", "description", "schema_parameter", "command", "argument"

    def to_dict(self) -> dict[str, str]:
        return {
            "capability": self.capability.value,
            "confidence": self.confidence.value,
            "evidence": self.evidence,
            "source": self.source,
        }


@dataclass
class MCPTool:
    """Normalized MCP tool representation."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    parameters: list[str] = field(default_factory=list)
    required_parameters: list[str] = field(default_factory=list)
    capabilities: list[CapabilityAssessment] = field(default_factory=list)
    estimated_tokens: int = 0
    is_truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "parameters": self.parameters,
            "required_parameters": self.required_parameters,
            "capabilities": [c.to_dict() for c in self.capabilities],
            "estimated_tokens": self.estimated_tokens,
            "is_truncated": self.is_truncated,
        }


@dataclass
class MCPResource:
    """Normalized MCP resource representation."""

    uri: str
    name: str = ""
    description: str = ""
    mime_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "uri": self.uri,
            "name": self.name,
            "description": self.description,
            "mime_type": self.mime_type,
        }


@dataclass
class MCPServer:
    """Normalized MCP server representation."""

    name: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    tools: list[MCPTool] = field(default_factory=list)
    resources: list[MCPResource] = field(default_factory=list)
    raw_config: dict[str, Any] = field(default_factory=dict)
    estimated_tokens: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self, redact_secrets: bool = True) -> dict[str, Any]:
        redacted_env = {}
        secret_patterns = (
            "key", "token", "secret", "password", "passwd", "auth", "credential", "bearer"
        )
        for k, v in self.env.items():
            k_lower = str(k).lower()
            v_str = str(v)
            if redact_secrets and any(pat in k_lower for pat in secret_patterns):
                # Check if it is an env variable reference like ${VAR} or $VAR
                if v_str.startswith("${") or v_str.startswith("$") or v_str.startswith("%") or v_str.startswith("env:"):
                    redacted_env[k] = v_str
                else:
                    redacted_env[k] = "[REDACTED]"
            else:
                redacted_env[k] = v_str

        return {
            "name": self.name,
            "command": self.command,
            "args": self.args,
            "env": redacted_env,
            "tools": [t.to_dict() for t in self.tools],
            "resources": [r.to_dict() for r in self.resources],
            "estimated_tokens": self.estimated_tokens,
            "warnings": self.warnings,
        }


@dataclass(frozen=True)
class Finding:
    """Audit finding with full transparency: observed, why it matters, evidence, recommendation."""

    severity: Severity
    category: FindingCategory
    server: str
    title: str
    description: str
    evidence: str
    recommendation: str
    confidence: Confidence
    tool: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "category": self.category.value,
            "server": self.server,
            "tool": self.tool,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "confidence": self.confidence.value,
        }


@dataclass
class ParsingWarning:
    """Non-fatal warning during configuration parsing."""

    message: str
    server_name: str | None = None
    tool_name: str | None = None
    raw_snippet: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "message": self.message,
            "server_name": self.server_name,
            "tool_name": self.tool_name,
            "raw_snippet": self.raw_snippet,
        }


@dataclass
class ParsingError:
    """Structured, actionable configuration parsing error."""

    file_path: str
    problem: str
    expected: str
    suggestion: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "file_path": self.file_path,
            "problem": self.problem,
            "expected": self.expected,
            "suggestion": self.suggestion,
            "message": self.message,
        }


@dataclass
class MCPConfiguration:
    """Normalized top-level configuration container."""

    file_path: str
    configuration_hash: str
    servers: dict[str, MCPServer] = field(default_factory=dict)
    warnings: list[ParsingWarning] = field(default_factory=list)
    errors: list[ParsingError] = field(default_factory=list)
    limits_reached: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "configuration_hash": self.configuration_hash,
            "servers": {k: v.to_dict() for k, v in self.servers.items()},
            "warnings": [w.to_dict() for w in self.warnings],
            "errors": [e.to_dict() for e in self.errors],
            "limits_reached": self.limits_reached,
        }


DISCLAIMER_TEXT = (
    "mcp-audit provides heuristic analysis of MCP configurations and is not a formal "
    "security certification or guarantee. Developers remain responsible for reviewing "
    "MCP servers, permissions, credentials, and the data exposed to AI systems."
)


@dataclass
class AuditManifest:
    """Audit metadata for reproducibility."""

    tool_version: str
    timestamp: str
    input_file: str
    configuration_hash: str
    servers_count: int
    tools_count: int
    estimated_context_tokens: int
    analysis_limits: dict[str, Any]
    disclaimer: str = DISCLAIMER_TEXT

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    """Complete structured audit result."""

    manifest: AuditManifest
    configuration: MCPConfiguration
    findings: list[Finding]
    capability_counts: dict[str, int]
    server_tokens: dict[str, int]
    total_estimated_tokens: int
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    limits_reached: list[str] = field(default_factory=list)
    disclaimer: str = DISCLAIMER_TEXT

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest": self.manifest.to_dict(),
            "disclaimer": self.disclaimer,
            "configuration": {
                "file_path": self.configuration.file_path,
                "configuration_hash": self.configuration.configuration_hash,
                "servers": {k: v.to_dict() for k, v in self.configuration.servers.items()},
            },
            "findings": [f.to_dict() for f in self.findings],
            "capability_summary": self.capability_counts,
            "context_footprint": {
                "total_estimated_tokens": self.total_estimated_tokens,
                "by_server": self.server_tokens,
            },
            "warnings": self.warnings,
            "errors": self.errors,
            "limits_reached": self.limits_reached,
        }
