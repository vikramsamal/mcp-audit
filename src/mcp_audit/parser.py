"""Parser and normalizer for MCP configuration files.

Safely parses JSON MCP configurations, enforces resource limits, normalizes server
and tool structures, and captures malformed definitions without crashing.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from mcp_audit.capabilities import classify_tool_capabilities
from mcp_audit.limits import AnalysisLimits
from mcp_audit.models import (
    MCPConfiguration,
    MCPResource,
    MCPServer,
    MCPTool,
    ParsingError,
    ParsingWarning,
)


class MCPConfigParser:
    """Safely loads and normalizes MCP configuration files."""

    def __init__(self, limits: AnalysisLimits | None = None):
        self.limits = limits or AnalysisLimits()

    def parse_file(self, file_path: str) -> MCPConfiguration:
        """Parse configuration from a file path with size checking and SHA-256 hashing."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Configuration file not found: '{file_path}'")

        if not os.path.isfile(file_path):
            raise ValueError(f"Path is not a regular file: '{file_path}'")

        # 1. Memory safety check
        self.limits.check_file_size(file_path)

        # 2. Read bytes and compute hash
        try:
            with open(file_path, "rb") as f:
                content_bytes = f.read(self.limits.max_file_size + 1)
        except OSError as exc:
            raise OSError(f"Failed to read configuration file '{file_path}': {exc}") from exc

        if len(content_bytes) > self.limits.max_file_size:
            from mcp_audit.limits import FileSizeExceededError
            raise FileSizeExceededError(file_path, len(content_bytes), self.limits.max_file_size)

        config_hash = f"sha256:{hashlib.sha256(content_bytes).hexdigest()}"

        try:
            content_str = content_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            error = ParsingError(
                file_path=file_path,
                problem=f"Configuration file is not valid UTF-8 text: {exc}",
                expected="UTF-8 encoded JSON configuration file.",
                suggestion="Ensure the file is encoded in UTF-8 text format.",
                message="File encoding error. No servers were executed. No files were modified.",
            )
            config = MCPConfiguration(
                file_path=file_path,
                configuration_hash=config_hash,
                errors=[error],
            )
            return config

        return self.parse_string(content_str, file_path=file_path, config_hash=config_hash)

    def parse_string(
        self,
        content: str,
        file_path: str = "inline.json",
        config_hash: str | None = None,
    ) -> MCPConfiguration:
        """Parse configuration from a JSON string."""
        if config_hash is None:
            config_hash = f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}"

        warnings: list[ParsingWarning] = []
        errors: list[ParsingError] = []
        limits_reached: list[str] = []

        if not content.strip():
            error = ParsingError(
                file_path=file_path,
                problem="Configuration file is empty.",
                expected='JSON object containing "mcpServers" configuration.',
                suggestion='Provide a valid JSON MCP configuration such as: {"mcpServers": {}}',
                message="Empty configuration. No servers were executed. No files were modified.",
            )
            return MCPConfiguration(
                file_path=file_path,
                configuration_hash=config_hash,
                errors=[error],
            )

        try:
            raw_data = json.loads(content)
        except json.JSONDecodeError as exc:
            error = ParsingError(
                file_path=file_path,
                problem=f"Invalid JSON syntax at line {exc.lineno}, column {exc.colno}: {exc.msg}",
                expected='Valid JSON object with "mcpServers" definitions.',
                suggestion="Check for trailing commas, missing quotes, or unescaped characters.",
                message=f"JSON syntax error: {exc.msg}. No servers were executed. No files were modified.",
            )
            return MCPConfiguration(
                file_path=file_path,
                configuration_hash=config_hash,
                errors=[error],
            )

        if not isinstance(raw_data, dict):
            error = ParsingError(
                file_path=file_path,
                problem=f"Top-level configuration must be a JSON object (got {type(raw_data).__name__}).",
                expected='{\n  "mcpServers": {\n    "server_name": {\n      "command": "..."\n    }\n  }\n}',
                suggestion='Wrap server definitions inside a JSON object under the "mcpServers" key.',
                message="Invalid root configuration structure. No servers were executed. No files were modified.",
            )
            return MCPConfiguration(
                file_path=file_path,
                configuration_hash=config_hash,
                errors=[error],
            )

        # Locate servers dictionary
        servers_dict: Any = None
        if "mcpServers" in raw_data:
            servers_dict = raw_data["mcpServers"]
        elif "servers" in raw_data:
            servers_dict = raw_data["servers"]
        elif self._looks_like_server_map(raw_data):
            servers_dict = raw_data
        else:
            error = ParsingError(
                file_path=file_path,
                problem='Missing "mcpServers" section in configuration.',
                expected='{\n  "mcpServers": {\n    "server_name": {\n      "command": "..."\n    }\n  }\n}',
                suggestion='Unsupported configuration format. Currently supported: JSON MCP configuration with "mcpServers".',
                message='Missing "mcpServers" section. No servers were executed. No files were modified.',
            )
            return MCPConfiguration(
                file_path=file_path,
                configuration_hash=config_hash,
                errors=[error],
                raw_data=raw_data,
            )

        if not isinstance(servers_dict, dict):
            error = ParsingError(
                file_path=file_path,
                problem=f'"mcpServers" must be a JSON object (got {type(servers_dict).__name__}).',
                expected='{\n  "mcpServers": {\n    "server_name": {\n      "command": "..."\n    }\n  }\n}',
                suggestion='Ensure "mcpServers" maps server names to server configuration objects.',
                message='"mcpServers" must be an object. No servers were executed. No files were modified.',
            )
            return MCPConfiguration(
                file_path=file_path,
                configuration_hash=config_hash,
                errors=[error],
                raw_data=raw_data,
            )

        # Parse normalized servers
        servers: dict[str, MCPServer] = {}
        server_items = list(servers_dict.items())

        if len(server_items) > self.limits.max_servers:
            limits_reached.append(
                f"Server count ({len(server_items)}) exceeded limit ({self.limits.max_servers}). "
                f"Only the first {self.limits.max_servers} servers were analyzed."
            )
            server_items = server_items[: self.limits.max_servers]

        for srv_name, srv_def in server_items:
            srv_name_str = str(srv_name)
            if not isinstance(srv_def, dict):
                warnings.append(
                    ParsingWarning(
                        message=f'Server "{srv_name_str}" definition must be an object (got {type(srv_def).__name__}).',
                        server_name=srv_name_str,
                        raw_snippet=str(srv_def)[:100],
                    )
                )
                continue

            parsed_server = self._normalize_server(
                name=srv_name_str,
                raw=srv_def,
                warnings=warnings,
                limits_reached=limits_reached,
            )
            servers[srv_name_str] = parsed_server

        return MCPConfiguration(
            file_path=file_path,
            configuration_hash=config_hash,
            servers=servers,
            warnings=warnings,
            errors=errors,
            limits_reached=limits_reached,
            raw_data=raw_data,
        )

    def _looks_like_server_map(self, d: dict[str, Any]) -> bool:
        """Check if dictionary directly maps server names to server config objects."""
        if not d:
            return False
        for val in d.values():
            if isinstance(val, dict) and ("command" in val or "args" in val or "tools" in val):
                return True
        return False

    def _normalize_server(
        self,
        name: str,
        raw: dict[str, Any],
        warnings: list[ParsingWarning],
        limits_reached: list[str],
    ) -> MCPServer:
        """Normalize raw server dictionary into MCPServer data model."""
        command: str | None = None
        args: list[str] = []
        env: dict[str, str] = {}
        tools: list[MCPTool] = []
        resources: list[MCPResource] = []
        srv_warnings: list[str] = []

        # Command extraction
        if "command" in raw:
            cmd_val = raw["command"]
            if isinstance(cmd_val, str):
                command, was_trunc = self.limits.bounded_string(cmd_val)
                if was_trunc:
                    limits_reached.append(f"Server '{name}' command was truncated to length limit.")
            elif cmd_val is None:
                command = None
            else:
                msg = f'Server "{name}" command must be a string (got {type(cmd_val).__name__}).'
                warnings.append(ParsingWarning(message=msg, server_name=name))
                srv_warnings.append(msg)

        # Arguments extraction
        if "args" in raw:
            args_val = raw["args"]
            if isinstance(args_val, list):
                for idx, a in enumerate(args_val):
                    if isinstance(a, (str, int, float, bool)):
                        arg_str, _ = self.limits.bounded_string(str(a))
                        args.append(arg_str)
                    else:
                        msg = f'Server "{name}" args[{idx}] must be a string or primitive.'
                        warnings.append(ParsingWarning(message=msg, server_name=name))
                        srv_warnings.append(msg)
            elif isinstance(args_val, str):
                args = [args_val]
            else:
                msg = f'Server "{name}" args must be a list (got {type(args_val).__name__}).'
                warnings.append(ParsingWarning(message=msg, server_name=name))
                srv_warnings.append(msg)

        # Environment variables extraction
        if "env" in raw:
            env_val = raw["env"]
            if isinstance(env_val, dict):
                for k, v in env_val.items():
                    k_str, _ = self.limits.bounded_string(str(k))
                    v_str, _ = self.limits.bounded_string(str(v) if v is not None else "")
                    env[k_str] = v_str
            else:
                msg = f'Server "{name}" env must be an object (got {type(env_val).__name__}).'
                warnings.append(ParsingWarning(message=msg, server_name=name))
                srv_warnings.append(msg)

        # Embedded tool definitions
        raw_tools = raw.get("tools") or raw.get("mcp_tools") or []
        if isinstance(raw_tools, list):
            tool_items = raw_tools
            if len(tool_items) > self.limits.max_tools_per_server:
                limits_reached.append(
                    f"Server '{name}' tool count exceeded limit ({self.limits.max_tools_per_server})."
                )
                tool_items = tool_items[: self.limits.max_tools_per_server]

            for tool_raw in tool_items:
                if isinstance(tool_raw, dict):
                    tool_obj = self._normalize_tool(name, tool_raw, warnings, limits_reached)
                    if tool_obj:
                        tools.append(tool_obj)
                else:
                    msg = f'Server "{name}" tool definition must be an object.'
                    warnings.append(ParsingWarning(message=msg, server_name=name))
                    srv_warnings.append(msg)

        # Embedded resource definitions
        raw_resources = raw.get("resources") or []
        if isinstance(raw_resources, list):
            for res_raw in raw_resources:
                if isinstance(res_raw, dict) and "uri" in res_raw:
                    resources.append(
                        MCPResource(
                            uri=str(res_raw.get("uri", "")),
                            name=str(res_raw.get("name", "")),
                            description=str(res_raw.get("description", "")),
                            mime_type=res_raw.get("mimeType"),
                        )
                    )

        return MCPServer(
            name=name,
            command=command,
            args=args,
            env=env,
            tools=tools,
            resources=resources,
            raw_config=raw,
            warnings=srv_warnings,
        )

    def _normalize_tool(
        self,
        server_name: str,
        tool_raw: dict[str, Any],
        warnings: list[ParsingWarning],
        limits_reached: list[str],
    ) -> MCPTool | None:
        """Normalize a tool definition dictionary into an MCPTool model."""
        if "name" not in tool_raw:
            warnings.append(
                ParsingWarning(
                    message=f'Server "{server_name}" tool is missing required "name" field.',
                    server_name=server_name,
                    raw_snippet=str(tool_raw)[:100],
                )
            )
            return None

        tool_name = str(tool_raw["name"])
        raw_desc = str(tool_raw.get("description", ""))
        desc, desc_trunc = self.limits.bounded_string(raw_desc, self.limits.max_description_size)
        if desc_trunc:
            limits_reached.append(
                f"Tool '{server_name}.{tool_name}' description exceeded {self.limits.max_description_size} chars and was truncated."
            )

        # Input schema parsing
        input_schema = tool_raw.get("inputSchema") or tool_raw.get("input_schema") or {}
        if not isinstance(input_schema, dict):
            input_schema = {}

        parameters: list[str] = []
        required_params: list[str] = []

        if isinstance(input_schema, dict):
            props = input_schema.get("properties")
            if isinstance(props, dict):
                parameters = [str(p) for p in props.keys()]
            req = input_schema.get("required")
            if isinstance(req, list):
                required_params = [str(r) for r in req]

        # Classify tool capabilities
        capabilities = classify_tool_capabilities(
            tool_name=tool_name,
            tool_desc=desc,
            parameters=parameters,
            input_schema=input_schema,
        )

        return MCPTool(
            name=tool_name,
            description=desc,
            input_schema=input_schema,
            parameters=parameters,
            required_parameters=required_params,
            capabilities=capabilities,
            is_truncated=desc_trunc,
        )
