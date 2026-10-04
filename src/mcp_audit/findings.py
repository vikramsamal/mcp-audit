"""Structured findings generation and helpers for mcp-audit.

Every finding answers:
1. What did we observe? (Observed configuration)
2. Why might it matter? (Risk & context implications)
3. What evidence supports it? (Exact paths, keys, commands, or patterns)
4. What should the developer review? (Actionable recommendations)
"""

from __future__ import annotations

from mcp_audit.models import Confidence, Finding, FindingCategory, Severity


def create_filesystem_finding(
    server: str,
    path: str,
    is_broad: bool,
    details: str = "",
    tool: str | None = None,
) -> Finding:
    """Generate finding for filesystem access configuration."""
    if is_broad:
        severity = Severity.HIGH
        title = "Broad filesystem access detected"
        description = (
            f"Server '{server}' is configured with a broad filesystem path '{path}'. "
            "Broad filesystem access may allow an AI client or server process to read, "
            "traverse, or modify sensitive system or user files."
        )
        recommendation = (
            "Restrict the configured filesystem directory to the specific workspace "
            "or project folder required by the workflow."
        )
        confidence = Confidence.HIGH
    else:
        severity = Severity.LOW
        title = "Filesystem path configured"
        description = (
            f"Server '{server}' is configured with filesystem path '{path}'. "
            "Verify that the directory scope matches intended access boundaries."
        )
        recommendation = "Review file access scope to ensure no parent or sensitive paths are exposed."
        confidence = Confidence.MEDIUM

    if details:
        description += f" {details}"

    return Finding(
        severity=severity,
        category=FindingCategory.FILESYSTEM,
        server=server,
        tool=tool,
        title=title,
        description=description,
        evidence=path,
        recommendation=recommendation,
        confidence=confidence,
    )


def create_command_execution_finding(
    server: str,
    command: str,
    is_shell: bool,
    args: list[str] | None = None,
    tool: str | None = None,
) -> Finding:
    """Generate finding for shell or process command execution."""
    args_str = f" with arguments {' '.join(args)}" if args else ""
    if is_shell:
        severity = Severity.MEDIUM
        title = "Shell execution capability detected"
        description = (
            f"Server '{server}' is configured to run shell command '{command}'{args_str}. "
            "An MCP server utilizing an interactive shell or interpreter may expose broad command "
            "execution capabilities to an AI client."
        )
        recommendation = (
            "Review whether shell execution is strictly necessary. "
            "Prefer dedicated, single-purpose CLI binaries with restricted arguments."
        )
        confidence = Confidence.HIGH
    else:
        severity = Severity.LOW
        title = "Process execution capability detected"
        description = (
            f"Server '{server}' executes binary '{command}'{args_str}. "
            "Review process permissions and host capabilities granted to this binary."
        )
        recommendation = "Ensure the binary runs with the least privileges necessary."
        confidence = Confidence.MEDIUM

    return Finding(
        severity=severity,
        category=FindingCategory.COMMAND_EXECUTION,
        server=server,
        tool=tool,
        title=title,
        description=description,
        evidence=f"{command}{args_str}",
        recommendation=recommendation,
        confidence=confidence,
    )


def create_dangerous_argument_finding(
    server: str,
    arg: str,
    reason: str,
    tool: str | None = None,
) -> Finding:
    """Generate finding for dangerous or overly permissive command line arguments."""
    return Finding(
        severity=Severity.HIGH,
        category=FindingCategory.COMMAND_EXECUTION,
        server=server,
        tool=tool,
        title="Potentially broad or dangerous command argument",
        description=(
            f"Server '{server}' includes command argument '{arg}'. "
            f"This argument may enable unrestricted permissions or disable safety isolation ({reason})."
        ),
        evidence=arg,
        recommendation="Review and remove flags that disable sandboxing or grant elevated access.",
        confidence=Confidence.HIGH,
    )


def create_secret_finding(
    server: str,
    field_name: str,
    is_env_var_ref: bool,
    tool: str | None = None,
) -> Finding:
    """Generate finding for secrets detected in configuration.

    CRITICAL: Never include raw secret values in description or evidence!
    """
    if is_env_var_ref:
        severity = Severity.INFO
        title = "Environment variable reference for credential"
        description = (
            f"Server '{server}' references environment variable '{field_name}'. "
            "The configuration properly references an environment variable rather than hardcoding "
            "a static secret."
        )
        recommendation = (
            "Ensure the referenced environment variable is stored securely and not logged "
            "during AI agent sessions."
        )
        confidence = Confidence.HIGH
    else:
        severity = Severity.HIGH
        title = "Potential literal secret detected"
        description = (
            f"Server '{server}' contains a credential-like configuration field '{field_name}' "
            "that appears to be a static or hardcoded value rather than an environment reference."
        )
        recommendation = (
            f"Replace static secret in '{field_name}' with an environment variable reference "
            "(e.g. ${{VAR_NAME}} or by passing it via a secure credential manager)."
        )
        confidence = Confidence.HIGH

    return Finding(
        severity=severity,
        category=FindingCategory.SECRETS,
        server=server,
        tool=tool,
        title=title,
        description=description,
        evidence=f"{field_name}=[REDACTED]",
        recommendation=recommendation,
        confidence=confidence,
    )


def create_destructive_tool_finding(
    server: str,
    tool_name: str,
    capability: str,
    evidence: str,
    confidence: Confidence,
) -> Finding:
    """Generate finding for tools with destructive capabilities (e.g. DELETE or arbitrary execution)."""
    if capability == "DELETE":
        severity = Severity.MEDIUM
        title = "Destructive data deletion capability"
        description = (
            f"Tool '{server}.{tool_name}' appears capable of deleting or removing data, files, or resources."
        )
        recommendation = (
            "Verify that deletion tools require explicit user confirmation before execution "
            "when used by autonomous agents."
        )
    elif capability == "EXECUTE":
        severity = Severity.MEDIUM
        title = "Arbitrary code or command execution capability"
        description = (
            f"Tool '{server}.{tool_name}' appears capable of executing arbitrary commands, scripts, or queries."
        )
        recommendation = (
            "Restrict parameter inputs and ensure strict sanitization or confirmation gates "
            "for code execution tools."
        )
    else:
        severity = Severity.LOW
        title = f"Potentially sensitive {capability} capability"
        description = f"Tool '{server}.{tool_name}' exhibits {capability} capability."
        recommendation = "Review tool permissions and scope within your AI agent configuration."

    return Finding(
        severity=severity,
        category=FindingCategory.DELETE_ACCESS if capability == "DELETE" else FindingCategory.COMMAND_EXECUTION,
        server=server,
        tool=tool_name,
        title=title,
        description=description,
        evidence=evidence,
        recommendation=recommendation,
        confidence=confidence,
    )


def create_context_bloat_finding(
    server: str,
    tool_name: str,
    estimated_tokens: int,
    threshold: int,
) -> Finding:
    """Generate finding for unusually large tool definitions (context efficiency)."""
    return Finding(
        severity=Severity.INFO,
        category=FindingCategory.CONTEXT_BLOAT,
        server=server,
        tool=tool_name,
        title="Large MCP tool definition",
        description=(
            f"Tool '{server}.{tool_name}' has an estimated definition size of ~{estimated_tokens:,} tokens "
            f"(threshold: {threshold:,} tokens). Large tool definitions increase context overhead "
            "and prompt costs on every model invocation."
        ),
        evidence=f"~{estimated_tokens:,} estimated tokens",
        recommendation="Review whether tool descriptions or JSON schemas can be streamlined or modularized.",
        confidence=Confidence.HIGH,
    )


def create_tool_overlap_finding(
    server: str,
    tool1: str,
    tool2: str,
    similarity_reason: str,
) -> Finding:
    """Generate finding for potentially overlapping or redundant tools."""
    return Finding(
        severity=Severity.INFO,
        category=FindingCategory.TOOL_OVERLAP,
        server=server,
        tool=f"{tool1}, {tool2}",
        title="Potentially overlapping tools",
        description=(
            f"Tools '{server}.{tool1}' and '{server}.{tool2}' appear to provide overlapping functionality "
            f"({similarity_reason}). Overlapping tools may cause agent confusion or redundant context footprint."
        ),
        evidence=f"Tools: {tool1} <-> {tool2}",
        recommendation="Review whether both tools are necessary or if they can be unified.",
        confidence=Confidence.MEDIUM,
    )


def create_configuration_warning_finding(
    server: str,
    message: str,
    raw_snippet: str | None = None,
    tool: str | None = None,
) -> Finding:
    """Generate finding for configuration structure issues or malformed items."""
    return Finding(
        severity=Severity.LOW,
        category=FindingCategory.CONFIGURATION,
        server=server,
        tool=tool,
        title="Configuration structure issue",
        description=f"Server '{server}': {message}",
        evidence=raw_snippet or "Configuration syntax",
        recommendation="Review server configuration structure and verify expected fields.",
        confidence=Confidence.HIGH,
    )
