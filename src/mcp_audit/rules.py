"""Audit rules engine for analyzing normalized MCP configurations.

Implements:
- Secret detection (with literal vs env reference differentiation)
- Command and shell execution analysis
- Dangerous argument detection
- Filesystem scope and permission analysis
- Context bloat and large tool detection
- Deterministic tool overlap and redundancy analysis
- Destructive tool capability analysis
"""

from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING

from mcp_audit.findings import (
    create_command_execution_finding,
    create_configuration_warning_finding,
    create_context_bloat_finding,
    create_dangerous_argument_finding,
    create_destructive_tool_finding,
    create_filesystem_finding,
    create_secret_finding,
    create_tool_overlap_finding,
)
from mcp_audit.models import (
    Capability,
    Confidence,
    Finding,
    FindingCategory,
    MCPServer,
    Severity,
)

if TYPE_CHECKING:
    from mcp_audit.models import MCPConfiguration

# Secret key indicators
SECRET_KEY_PATTERNS = [
    r"API_?KEY",
    r"TOKEN",
    r"SECRET",
    r"PASSWORD",
    r"PASSWD",
    r"PRIVATE_?KEY",
    r"AWS_SECRET_ACCESS_KEY",
    r"AWS_ACCESS_KEY_ID",
    r"GITHUB_?TOKEN",
    r"DATABASE_?PASSWORD",
    r"DB_?PASSWORD",
    r"AUTH_?TOKEN",
    r"BEARER",
    r"CREDENTIAL",
    r"SSH_?KEY",
    r"ACCESS_?TOKEN",
    r"CLIENT_?SECRET",
]
SECRET_KEY_REGEX = re.compile(f"(?:{'|'.join(SECRET_KEY_PATTERNS)})", re.IGNORECASE)

# Environment variable reference indicators
ENV_REF_REGEX = re.compile(
    r"^(?:\$\{[A-Za-z0-9_]+\}|\$[A-Za-z0-9_]+|%[A-Za-z0-9_]+%|env:[A-Za-z0-9_]+|process\.env\.[A-Za-z0-9_]+)$"
)

# Placeholder values that are not real literal secrets
PLACEHOLDER_REGEX = re.compile(
    r"^(?:<.*>|\[.*\]|YOUR_.*|CHANGE_ME|PLACEHOLDER|XXX+|TODO|SAMPLE.*|DUMMY.*|FIXME)$",
    re.IGNORECASE,
)

# Shell and interpreter binaries
SHELL_COMMANDS = {
    "bash", "sh", "zsh", "powershell", "pwsh", "cmd", "cmd.exe", "csh", "tcsh", "fish", "dash"
}
INTERPRETER_COMMANDS = {
    "python", "python3", "node", "nodejs", "deno", "bun", "ruby", "perl", "php", "lua"
}
CONTAINER_COMMANDS = {
    "docker", "kubectl", "podman", "nerdctl", "crictl"
}

# Dangerous arguments
DANGEROUS_ARGS = {
    "--privileged": "grants extended host privileges",
    "--no-sandbox": "disables sandbox isolation",
    "--disable-web-security": "disables browser origin/security policies",
    "--allow-all": "grants unrestricted runtime permissions",
    "--allow-read": "grants broad filesystem read access",
    "--allow-write": "grants broad filesystem write access",
    "--allow-net": "grants unrestricted network access",
    "--cap-add=ALL": "adds all Linux kernel capabilities",
    "--cap-add=SYS_ADMIN": "adds administrative kernel capabilities",
    "--net=host": "shares host network namespace",
    "--insecure": "disables TLS/SSL verification",
    "-k": "disables TLS/SSL verification",
}

# Broad filesystem root paths
BROAD_PATHS = {
    "/", "~", "/home", "/Users", "/root", "/etc", "/var", "/tmp", "/private",
    "C:\\", "C:\\Users", "C:\\Windows", "C:\\Program Files", "D:\\",
}

# Synonym groups for tool overlap detection
ACTION_SYNONYMS = {
    "search": {"search", "find", "locate", "lookup", "query", "scan", "seek"},
    "get": {"get", "fetch", "read", "retrieve", "show", "view", "cat", "inspect", "describe", "obtain"},
    "delete": {"delete", "remove", "drop", "destroy", "purge", "unlink", "erase", "wipe", "clear"},
    "create": {"create", "write", "new", "add", "insert", "generate", "make", "build", "save"},
    "update": {"update", "modify", "edit", "patch", "alter", "change", "set", "replace"},
    "exec": {"exec", "execute", "run", "launch", "eval", "start", "spawn"},
}


def is_env_reference(value: str) -> bool:
    """Check if value is an environment variable reference or empty placeholder."""
    val_stripped = value.strip()
    if not val_stripped:
        return True
    if ENV_REF_REGEX.match(val_stripped):
        return True
    if PLACEHOLDER_REGEX.match(val_stripped):
        return True
    return False


def is_broad_filesystem_path(path: str) -> bool:
    """Check if a path represents a broad filesystem root or user home directory."""
    clean = path.strip().rstrip("/\\")
    if not clean or clean in BROAD_PATHS:
        return True

    # Normalize path
    norm = os.path.normpath(clean)
    if norm in ["/", "\\", "~", "/home", "/Users", "/root", "/etc", "/var", "/tmp"]:
        return True

    # Direct child of /home or /Users (e.g. /home/user or /Users/username is still broad home directory)
    parts = [p for p in norm.replace("\\", "/").split("/") if p]
    if len(parts) <= 2 and parts[0] in ["home", "Users"]:
        return True

    return False


def check_secrets(server: MCPServer) -> list[Finding]:
    """Scan server environment variables and configuration for secrets."""
    findings: list[Finding] = []

    for key, val in server.env.items():
        if SECRET_KEY_REGEX.search(key):
            is_ref = is_env_reference(str(val))
            findings.append(
                create_secret_finding(
                    server=server.name,
                    field_name=key,
                    is_env_var_ref=is_ref,
                )
            )

    return findings


def check_command_and_arguments(server: MCPServer) -> list[Finding]:
    """Analyze server command and arguments for shell execution and dangerous flags."""
    findings: list[Finding] = []
    if not server.command:
        return findings

    cmd = server.command.strip()
    cmd_name = os.path.basename(cmd.replace("\\", "/")).lower()

    # Check for shell execution
    if cmd_name in SHELL_COMMANDS:
        findings.append(
            create_command_execution_finding(
                server=server.name,
                command=server.command,
                is_shell=True,
                args=server.args,
            )
        )
    elif cmd_name in INTERPRETER_COMMANDS:
        findings.append(
            create_command_execution_finding(
                server=server.name,
                command=server.command,
                is_shell=False,
                args=server.args,
            )
        )
    elif cmd_name in CONTAINER_COMMANDS:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                category=FindingCategory.COMMAND_EXECUTION,
                server=server.name,
                title="Container execution capability detected",
                description=(
                    f"Server '{server.name}' invokes container CLI '{server.command}'. "
                    "Container commands may have container breakout or host volume mounting access."
                ),
                evidence=f"{server.command} {' '.join(server.args)}".strip(),
                recommendation="Review container isolation flags and mount points.",
                confidence=Confidence.HIGH,
            )
        )

    # Check dangerous arguments
    for arg in server.args:
        arg_clean = arg.strip()
        for dangerous_flag, reason in DANGEROUS_ARGS.items():
            if arg_clean == dangerous_flag or arg_clean.startswith(f"{dangerous_flag}="):
                findings.append(
                    create_dangerous_argument_finding(
                        server=server.name,
                        arg=arg_clean,
                        reason=reason,
                    )
                )

        # Check volume mounts like -v /:/host or --volume /:/...
        if re.match(r"^(?:-v|--volume)\s*=\s*/:.*|^/(?:[a-zA-Z0-9_-]+)?:/(?:host|root)", arg_clean):
            findings.append(
                create_dangerous_argument_finding(
                    server=server.name,
                    arg=arg_clean,
                    reason="mounts root filesystem into container",
                )
            )

    return findings


def check_filesystem_paths(server: MCPServer) -> list[Finding]:
    """Inspect arguments and server configuration for filesystem paths."""
    findings: list[Finding] = []

    # Check server args for filesystem path indicators
    path_flags = {"--path", "--root", "--dir", "--directory", "--folder", "-d"}
    skip_indices: set[int] = set()

    for idx, arg in enumerate(server.args):
        if idx in skip_indices:
            continue

        # Flag followed by path
        if arg in path_flags and idx + 1 < len(server.args):
            target_path = server.args[idx + 1]
            skip_indices.add(idx + 1)
            is_broad = is_broad_filesystem_path(target_path)
            findings.append(
                create_filesystem_finding(
                    server=server.name,
                    path=target_path,
                    is_broad=is_broad,
                    details=f"Passed via argument '{arg}'",
                )
            )
        # Argument formatted as --path=/...
        elif any(arg.startswith(f"{f}=") for f in path_flags):
            target_path = arg.split("=", 1)[1]
            is_broad = is_broad_filesystem_path(target_path)
            findings.append(
                create_filesystem_finding(
                    server=server.name,
                    path=target_path,
                    is_broad=is_broad,
                    details=f"Passed via argument '{arg}'",
                )
            )
        # Standalone path argument
        elif arg.startswith("/") or arg.startswith("~") or re.match(r"^[a-zA-Z]:\\", arg):
            # Ignore options and flags
            if not arg.startswith("--"):
                is_broad = is_broad_filesystem_path(arg)
                findings.append(
                    create_filesystem_finding(
                        server=server.name,
                        path=arg,
                        is_broad=is_broad,
                        details="Configured as positional argument",
                    )
                )

    return findings


def check_tool_capabilities_and_bloat(
    server: MCPServer,
    large_tool_threshold: int = 1_000,
) -> list[Finding]:
    """Analyze tool capabilities, detect destructive tools, missing descriptions, and context bloat."""
    findings: list[Finding] = []

    for tool in server.tools:
        # Check description
        if not tool.description or not tool.description.strip():
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    category=FindingCategory.CONFIGURATION,
                    server=server.name,
                    tool=tool.name,
                    title="Tool missing description",
                    description=(
                        f"Tool '{server.name}.{tool.name}' has no description. "
                        "An AI model may hallucinate tool capabilities or invoke it incorrectly without clear instructions."
                    ),
                    evidence=f"Tool: {tool.name}",
                    recommendation="Add a clear, specific description explaining the tool purpose and parameters.",
                    confidence=Confidence.HIGH,
                )
            )

        # Check for context bloat
        if tool.estimated_tokens > large_tool_threshold:
            findings.append(
                create_context_bloat_finding(
                    server=server.name,
                    tool_name=tool.name,
                    estimated_tokens=tool.estimated_tokens,
                    threshold=large_tool_threshold,
                )
            )

        # Check capabilities for destructive / sensitive operations
        for cap_assess in tool.capabilities:
            if cap_assess.capability in (Capability.DELETE, Capability.EXECUTE):
                findings.append(
                    create_destructive_tool_finding(
                        server=server.name,
                        tool_name=tool.name,
                        capability=cap_assess.capability.value,
                        evidence=cap_assess.evidence,
                        confidence=cap_assess.confidence,
                    )
                )

    return findings


def get_action_synset(verb: str) -> str:
    """Map action verb to its canonical synonym cluster."""
    verb_lower = verb.lower()
    for syn_name, synset in ACTION_SYNONYMS.items():
        if verb_lower in synset:
            return syn_name
    return verb_lower


def extract_tool_tokens(name: str) -> tuple[str, set[str]]:
    """Extract action verb and noun terms from tool name."""
    parts = re.split(r"[_.-]", name.lower())
    parts = [p for p in parts if p]
    if not parts:
        return "", set()

    action = get_action_synset(parts[0])
    noun_terms = set(parts[1:])
    return action, noun_terms


def check_overlapping_tools(server: MCPServer) -> list[Finding]:
    """Detect potentially redundant or overlapping tools within the server."""
    findings: list[Finding] = []
    tools = server.tools
    n = len(tools)

    for i in range(n):
        for j in range(i + 1, n):
            tool1 = tools[i]
            tool2 = tools[j]

            action1, nouns1 = extract_tool_tokens(tool1.name)
            action2, nouns2 = extract_tool_tokens(tool2.name)

            # Match criteria: same canonical action synset and shared noun terms
            if action1 == action2 and (nouns1 & nouns2):
                shared_nouns = ", ".join(nouns1 & nouns2)
                reason = f"both perform '{action1}' on '{shared_nouns}'"
                findings.append(
                    create_tool_overlap_finding(
                        server=server.name,
                        tool1=tool1.name,
                        tool2=tool2.name,
                        similarity_reason=reason,
                    )
                )
            # Match criteria: identical description words overlap with similar action
            elif tool1.description and tool2.description:
                words1 = set(re.findall(r"\w{4,}", tool1.description.lower()))
                words2 = set(re.findall(r"\w{4,}", tool2.description.lower()))
                if words1 and words2:
                    jaccard = len(words1 & words2) / len(words1 | words2)
                    if jaccard > 0.65 and action1 == action2:
                        findings.append(
                            create_tool_overlap_finding(
                                server=server.name,
                                tool1=tool1.name,
                                tool2=tool2.name,
                                similarity_reason=f"similar descriptions ({int(jaccard*100)}% term overlap)",
                            )
                        )

    return findings


def execute_all_rules(
    config: MCPConfiguration,
    large_tool_threshold: int = 1_000,
) -> list[Finding]:
    """Run all audit rules on normalized MCP configuration."""
    all_findings: list[Finding] = []

    # Record parsing warnings as configuration findings
    for warn in config.warnings:
        all_findings.append(
            create_configuration_warning_finding(
                server=warn.server_name or "unknown",
                tool=warn.tool_name,
                message=warn.message,
                raw_snippet=warn.raw_snippet,
            )
        )

    # Analyze each server
    for server in config.servers.values():
        all_findings.extend(check_secrets(server))
        all_findings.extend(check_command_and_arguments(server))
        all_findings.extend(check_filesystem_paths(server))
        all_findings.extend(check_tool_capabilities_and_bloat(server, large_tool_threshold))
        all_findings.extend(check_overlapping_tools(server))

    return all_findings
