"""Deterministic capability classification for MCP tools and servers.

Identifies: READ, WRITE, DELETE, EXECUTE, NETWORK, AUTHENTICATION, SENSITIVE_DATA, UNKNOWN.
Applies multi-signal matching and false-positive filtering (e.g. documentation vs execution).
"""

from __future__ import annotations

import re
from typing import Any

from mcp_audit.models import Capability, CapabilityAssessment, Confidence, MCPServer

# Documentation / Reference patterns that indicate the tool is describing/searching rather than executing
DOC_PATTERNS = [
    r"\b(?:search|searches|searching|browse|browsing|read|reading|view|viewing|look up|find)\b.*\b(?:doc|docs|documentation|guide|guides|tutorial|manual|wiki|help|reference|article|knowledge base)\b",
    r"\b(?:returns?|provides?|gets?|fetches?|displays?|shows?)\b.*\b(?:doc|docs|documentation|information|info|explanation|details|guide|help|instructions?)\b.*\b(?:about|on|for|how to|explaining)\b",
    r"\b(?:explains?|explaining|describes?|describing|details?|summarizes?|teaches?)\b.*\b(?:how to|methods?|ways?|options?|usage|concepts?)\b",
    r"\b(?:reference|cheat\s*sheet|troubleshooting)\b",
    r"\b(?:read-only|read only)\b",
]

DOC_REGEX = [re.compile(p, re.IGNORECASE) for p in DOC_PATTERNS]

# Name prefixes/keywords by capability
NAME_PATTERNS: dict[Capability, list[str]] = {
    Capability.DELETE: [
        r"^delete(?:_|\b)",
        r"^remove(?:_|\b)",
        r"^drop(?:_|\b)",
        r"^destroy(?:_|\b)",
        r"^purge(?:_|\b)",
        r"^unlink(?:_|\b)",
        r"^wipe(?:_|\b)",
        r"^truncate(?:_|\b)",
        r"^erase(?:_|\b)",
        r"^uninstall(?:_|\b)",
        r"^kill(?:_|\b)",
        r"^terminate(?:_|\b)",
        r"^prune(?:_|\b)",
    ],
    Capability.EXECUTE: [
        r"^exec(?:_|\b)",
        r"^execute(?:_|\b)",
        r"^run(?:_|\b)",
        r"^shell(?:_|\b)",
        r"^bash(?:_|\b)",
        r"^sh(?:_|\b)",
        r"^terminal(?:_|\b)",
        r"^eval(?:_|\b)",
        r"^spawn(?:_|\b)",
        r"^system(?:_|\b)",
        r"^invoke(?:_|\b)",
        r"^launch(?:_|\b)",
        r"^cmd(?:_|\b)",
    ],
    Capability.WRITE: [
        r"^write(?:_|\b)",
        r"^create(?:_|\b)",
        r"^update(?:_|\b)",
        r"^set(?:_|\b)",
        r"^put(?:_|\b)",
        r"^post(?:_|\b)",
        r"^insert(?:_|\b)",
        r"^save(?:_|\b)",
        r"^modify(?:_|\b)",
        r"^append(?:_|\b)",
        r"^patch(?:_|\b)",
        r"^upload(?:_|\b)",
        r"^send(?:_|\b)",
        r"^publish(?:_|\b)",
        r"^push(?:_|\b)",
        r"^edit(?:_|\b)",
        r"^add(?:_|\b)",
        r"^apply(?:_|\b)",
        r"^alter(?:_|\b)",
    ],
    Capability.READ: [
        r"^read(?:_|\b)",
        r"^get(?:_|\b)",
        r"^list(?:_|\b)",
        r"^fetch(?:_|\b)",
        r"^search(?:_|\b)",
        r"^find(?:_|\b)",
        r"^view(?:_|\b)",
        r"^describe(?:_|\b)",
        r"^inspect(?:_|\b)",
        r"^show(?:_|\b)",
        r"^cat(?:_|\b)",
        r"^tail(?:_|\b)",
        r"^head(?:_|\b)",
        r"^query(?:_|\b)",
        r"^scan(?:_|\b)",
        r"^browse(?:_|\b)",
        r"^check(?:_|\b)",
        r"^lookup(?:_|\b)",
        r"^status(?:_|\b)",
        r"^count(?:_|\b)",
    ],
    Capability.NETWORK: [
        r"^http(?:_|\b)",
        r"^curl(?:_|\b)",
        r"^fetch_url(?:_|\b)",
        r"^download(?:_|\b)",
        r"^request(?:_|\b)",
        r"^webhook(?:_|\b)",
        r"^ping(?:_|\b)",
        r"^dns(?:_|\b)",
        r"^socket(?:_|\b)",
        r"^connect(?:_|\b)",
        r"^api_call(?:_|\b)",
        r"^scrape(?:_|\b)",
    ],
    Capability.AUTHENTICATION: [
        r"^login(?:_|\b)",
        r"^authenticate(?:_|\b)",
        r"^auth(?:_|\b)",
        r"^token(?:_|\b)",
        r"^session(?:_|\b)",
        r"^oauth(?:_|\b)",
        r"^sso(?:_|\b)",
        r"^login_user(?:_|\b)",
    ],
    Capability.SENSITIVE_DATA: [
        r"^get_secret(?:_|\b)",
        r"^read_key(?:_|\b)",
        r"^export_key(?:_|\b)",
        r"^view_credential(?:_|\b)",
        r"^dump_vault(?:_|\b)",
        r"^list_secret(?:_|\b)",
    ],
}

# Operational action verbs in description
DESC_ACTION_PATTERNS: dict[Capability, list[str]] = {
    Capability.DELETE: [
        r"\b(?:deletes?|deleting|removes?|removing|drops?|dropping|destroys?|destroying|purges?|purging|unlinks?|wipes?|erases?)\b\s+(?:the|a|an|all|any|selected|specified)?\s*(?:file|directory|folder|table|database|user|resource|record|repo|container|volume|message|data)",
    ],
    Capability.EXECUTE: [
        r"\b(?:executes?|executing|runs?|running|evals?|evaluating|evaluates?)\b\s+(?:the|a|an|arbitrary|any|custom)?\s*(?:command|shell|script|bash|code|process|binary|executable|program|cli|sql)",
        r"\b(?:run|execute)\s+(?:in|on)\s+(?:the\s+)?(?:terminal|shell|host|system|container)\b",
    ],
    Capability.WRITE: [
        r"\b(?:writes?|writing|creates?|creating|updates?|updating|inserts?|inserting|modifies?|modifying|appends?|appending|edits?|editing|saves?|saving)\b\s+(?:the|a|an|to|new|specified)?\s*(?:file|content|directory|record|table|document|resource|message|data|entry|setting|config)",
        r"\b(?:sends?|sending|posts?|posting|publishes?|publishing)\b\s+(?:the|a|an|new)?\s*(?:message|email|notification|webhook|event|commit|pull request|issue|payload)",
    ],
    Capability.READ: [
        r"\b(?:reads?|reading|returns?|returning|fetches?|fetching|lists?|listing|searches?|searching|gets?|getting|views?|viewing|retrieves?|retrieving)\b\s+(?:the|a|an|all|contents?|information|data|metadata|files?|directories?|records?|tables?|messages?|entries|users?)",
    ],
    Capability.NETWORK: [
        r"\b(?:makes?|sending|performing)\s+(?:an?\s+)?(?:http|https|network|rest|graphql|api|external|remote)\s+(?:request|call|connection)\b",
        r"\b(?:downloads?|downloading|scrapes?|scraping|connects?|connecting\s+to)\s+(?:from\s+)?(?:the\s+)?(?:url|web|internet|remote|server|endpoint)\b",
    ],
    Capability.AUTHENTICATION: [
        r"\b(?:authenticates?|authenticating|generates?|generating|refreshes?|refreshing)\s+(?:an?\s+)?(?:auth|oauth|token|jwt|session|credential|access token)\b",
        r"\b(?:logs?\s*in|signs?\s*in)\s+(?:to|the\s+user)?\b",
    ],
    Capability.SENSITIVE_DATA: [
        r"\b(?:retrieves?|fetches?|gets?|exports?|dumps?|reads?)\s+(?:the\s+)?(?:secrets?|private\s+keys?|credentials?|passwords?|tokens?|vault)\b",
    ],
}

# Parameter patterns
PARAM_PATTERNS: dict[Capability, list[str]] = {
    Capability.EXECUTE: [
        r"^(?:command|cmd|script|bash|shell|sql_query|sql|eval_code|code_to_exec|executable)$",
    ],
    Capability.NETWORK: [
        r"^(?:url|uri|endpoint|webhook_url|remote_url|host|hostname|target_url)$",
    ],
    Capability.AUTHENTICATION: [
        r"^(?:token|auth_token|api_key|password|jwt|client_secret|access_token|refresh_token)$",
    ],
    Capability.DELETE: [
        r"^(?:force_delete|cascade_delete|purge|drop_if_exists)$",
    ],
    Capability.WRITE: [
        r"^(?:content|body|payload|new_content|text_to_append|data_to_write|file_content|changes)$",
    ],
    Capability.READ: [
        r"^(?:file_path|path|query|search_term|pattern|filter|limit|offset|page)$",
    ],
}


def is_doc_search_tool(tool_name: str, tool_desc: str) -> bool:
    """Check if the tool is primarily a documentation / search / reference tool."""
    name_lower = tool_name.lower()
    desc_lower = tool_desc.lower()

    # If name explicitly indicates documentation or search
    if any(k in name_lower for k in ["doc", "docs", "documentation", "guide", "manual", "search_doc", "wiki", "faq"]):
        return True

    # Check documentation regex against description
    for regex in DOC_REGEX:
        if regex.search(desc_lower):
            return True

    return False


def classify_tool_capabilities(
    tool_name: str,
    tool_desc: str,
    parameters: list[str],
    input_schema: dict[str, Any] | None = None,
) -> list[CapabilityAssessment]:
    """Classify the capabilities of an MCP tool using multi-signal analysis.

    Distinguishes operational verbs from documentation references.
    Assigns confidence (HIGH, MEDIUM, LOW) based on signal strength.
    """
    assessments: list[CapabilityAssessment] = []
    name_lower = tool_name.lower()
    desc_lower = tool_desc.lower()
    is_doc = is_doc_search_tool(name_lower, desc_lower)

    # 1. Analyze Tool Name
    name_matched_caps: set[Capability] = set()
    for cap, patterns in NAME_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, name_lower):
                # Strong name match
                confidence = Confidence.HIGH
                evidence = f"Tool name matches '{pattern}'"
                assessments.append(
                    CapabilityAssessment(
                        capability=cap,
                        confidence=confidence,
                        evidence=evidence,
                        source="tool_name",
                    )
                )
                name_matched_caps.add(cap)
                break

    # 2. Analyze Tool Parameters (input schema properties)
    param_names = list(parameters)
    if input_schema and isinstance(input_schema, dict):
        props = input_schema.get("properties", {})
        if isinstance(props, dict):
            for k in props.keys():
                if k not in param_names:
                    param_names.append(str(k))

    for param in param_names:
        param_clean = param.lower().strip()
        for cap, patterns in PARAM_PATTERNS.items():
            for pat in patterns:
                if re.match(pat, param_clean):
                    # Parameter match
                    # If this capability is EXECUTE (e.g. parameter is 'command' or 'script'), this is HIGH confidence
                    if cap == Capability.EXECUTE and param_clean in ["command", "cmd", "script", "bash"]:
                        conf = Confidence.HIGH
                    else:
                        conf = Confidence.MEDIUM

                    # Avoid duplicate if already high confidence from name
                    if cap not in name_matched_caps:
                        assessments.append(
                            CapabilityAssessment(
                                capability=cap,
                                confidence=conf,
                                evidence=f"Schema parameter '{param}' indicates {cap.value} input",
                                source="schema_parameter",
                            )
                        )
                    break

    # 3. Analyze Description Actions (with false positive protections)
    for cap, patterns in DESC_ACTION_PATTERNS.items():
        # If the tool is doc/search and the capability is destructive (DELETE/WRITE/EXECUTE),
        # do NOT flag it from description alone unless the name itself matched!
        if is_doc and cap in (Capability.DELETE, Capability.WRITE, Capability.EXECUTE):
            continue

        for pat in patterns:
            match = re.search(pat, desc_lower)
            if match:
                matched_snippet = match.group(0)[:80]
                # If name already matched this capability with HIGH confidence, skip duplicate
                if cap in name_matched_caps:
                    continue

                # If name didn't match, check confidence:
                # If doc tool, and cap is READ, it's HIGH confidence READ
                if is_doc and cap == Capability.READ:
                    conf = Confidence.HIGH
                elif cap in (Capability.DELETE, Capability.EXECUTE):
                    conf = Confidence.MEDIUM
                else:
                    conf = Confidence.MEDIUM

                assessments.append(
                    CapabilityAssessment(
                        capability=cap,
                        confidence=conf,
                        evidence=f"Description phrase: '{matched_snippet}'",
                        source="description",
                    )
                )
                break

    # 4. If doc tool and no READ capability yet, add READ
    if is_doc and not any(a.capability == Capability.READ for a in assessments):
        assessments.append(
            CapabilityAssessment(
                capability=Capability.READ,
                confidence=Confidence.HIGH,
                evidence="Tool is classified as documentation/search/reference retrieval",
                source="description",
            )
        )

    # 5. Default fallback to UNKNOWN if nothing matched
    if not assessments:
        assessments.append(
            CapabilityAssessment(
                capability=Capability.UNKNOWN,
                confidence=Confidence.LOW,
                evidence="No deterministic capability signals identified from tool definition",
                source="default",
            )
        )

    # Deduplicate assessments by capability, keeping the highest confidence
    deduped: dict[Capability, CapabilityAssessment] = {}
    for a in assessments:
        if a.capability not in deduped:
            deduped[a.capability] = a
        else:
            # Upgrade confidence if higher
            existing = deduped[a.capability]
            conf_ranks = {Confidence.LOW: 1, Confidence.MEDIUM: 2, Confidence.HIGH: 3}
            if conf_ranks[a.confidence] > conf_ranks[existing.confidence]:
                deduped[a.capability] = a

    return list(deduped.values())


def classify_server_capabilities(server: MCPServer) -> list[CapabilityAssessment]:
    """Classify server-level capabilities from configured command and aggregate tools."""
    assessments: list[CapabilityAssessment] = []
    cmd = (server.command or "").lower().strip()

    # Check command
    shell_binaries = ["bash", "sh", "zsh", "powershell", "pwsh", "cmd", "cmd.exe"]
    container_binaries = ["docker", "kubectl", "podman"]
    net_binaries = ["curl", "wget", "fetch", "wscat", "nc", "ncat"]

    cmd_base = cmd.split("/")[-1].split("\\")[-1]

    if any(cmd_base == b or cmd_base.startswith(f"{b}.") for b in shell_binaries):
        assessments.append(
            CapabilityAssessment(
                capability=Capability.EXECUTE,
                confidence=Confidence.HIGH,
                evidence=f"Server configured command is shell binary '{server.command}'",
                source="command",
            )
        )

    if any(cmd_base == b or cmd_base.startswith(f"{b}.") for b in container_binaries):
        assessments.append(
            CapabilityAssessment(
                capability=Capability.EXECUTE,
                confidence=Confidence.HIGH,
                evidence=f"Server configured command is container/cluster CLI '{server.command}'",
                source="command",
            )
        )

    if any(cmd_base == b for b in net_binaries):
        assessments.append(
            CapabilityAssessment(
                capability=Capability.NETWORK,
                confidence=Confidence.HIGH,
                evidence=f"Server configured command is network client '{server.command}'",
                source="command",
            )
        )

    # Aggregate tool capabilities
    for tool in server.tools:
        for cap_assessment in tool.capabilities:
            assessments.append(cap_assessment)

    # Deduplicate by capability, retaining highest confidence
    deduped: dict[Capability, CapabilityAssessment] = {}
    conf_ranks = {Confidence.LOW: 1, Confidence.MEDIUM: 2, Confidence.HIGH: 3}
    for a in assessments:
        if a.capability not in deduped:
            deduped[a.capability] = a
        else:
            existing = deduped[a.capability]
            if conf_ranks[a.confidence] > conf_ranks[existing.confidence]:
                deduped[a.capability] = a

    return list(deduped.values())
