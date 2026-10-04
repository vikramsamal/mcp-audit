# mcp-audit

[![CI](https://github.com/vikramsamal/mcp-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/vikramsamal/mcp-audit/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Local Only](https://img.shields.io/badge/network-offline%20only-success.svg)](SECURITY.md)

**Audit your MCP configuration before giving it to an AI agent.**

`mcp-audit` is a local, read-only CLI that analyzes Model Context Protocol (MCP) servers and tools for potentially broad permissions, risky capabilities, secrets, configuration issues, and context bloat.

* 🔒 **No API key required**
* 🌐 **100% Offline & Private** — No cloud services, SaaS, telemetry, or remote logging
* ⚡ **Deterministic & Fast** — No LLMs or models needed; instant static analysis
* 🛡️ **Strictly Read-Only** — No MCP servers are started, no commands executed, no files modified

---

## Why mcp-audit?

When configuring MCP servers in Claude Desktop, Cursor, VS Code, or custom AI agent environments, developers grant agents access to host commands, databases, and filesystem paths.

`mcp-audit` inspects these configurations beforehand to answer:

1. **What MCP servers and processes are configured?**
2. **What capabilities are exposed?** (Read, Write, Delete, Command Execution, Network, Authentication)
3. **Are filesystem scopes unusually broad?** (e.g. root `/`, `/home`, `~`, `C:\`)
4. **Are secrets hardcoded in environment variables?** (with automatic value redaction)
5. **How much context overhead do MCP tool definitions consume?** (Estimated token footprint)
6. **Are there redundant or overlapping tools?** (e.g. `search_files` vs `find_files`)
7. **What should the developer review?** (Actionable recommendations with observed evidence)

---

## Quick Start

### Installation

Install globally using `pipx` (recommended) or `pip`:

```bash
# Recommended: install once and use across any workspace
pipx install mcp-audit
```

Or via standard pip:

```bash
pip install mcp-audit
```

### Run an Audit

```bash
mcp-audit ./mcp-config.json
```

Or run directly with `pipx run`:

```bash
pipx run mcp-audit ./mcp-config.json
```

---

## Example Output

Running `mcp-audit examples/risky.json`:

```text
mcp-audit
=========

Configuration:
  examples/risky.json

Servers:
  4

Tools:
  6

Estimated context:
  ~1,772 tokens

Capabilities
------------
READ:               5
WRITE:              0
DELETE:             2
EXECUTE:            1
NETWORK:            0
AUTHENTICATION:     0
SENSITIVE_DATA:     0

Findings
--------
CRITICAL     0
HIGH         3
MEDIUM       4
LOW          1
INFO         2

HIGH
----
[filesystem]
Potentially broad or dangerous command argument

Observed:
  Server 'filesystem' includes command argument '--allow-all'. This argument may enable unrestricted permissions or disable safety isolation (grants unrestricted runtime permissions).

Evidence:
  --allow-all

Recommendation:
  Review and remove flags that disable sandboxing or grant elevated access.

Confidence: HIGH

[filesystem]
Broad filesystem access detected

Observed:
  Server 'filesystem' is configured with a broad filesystem path '/home'. Broad filesystem access may allow an AI client or server process to read, traverse, or modify sensitive system or user files. Configured as positional argument

Evidence:
  /home

Recommendation:
  Restrict the configured filesystem directory to the specific workspace or project folder required by the workflow.

Confidence: HIGH

[github]
Potential literal secret detected

Observed:
  Server 'github' contains a credential-like configuration field 'GITHUB_TOKEN' that appears to be a static or hardcoded value rather than an environment reference.

Evidence:
  GITHUB_TOKEN=[REDACTED]

Recommendation:
  Replace static secret in 'GITHUB_TOKEN' with an environment variable reference (e.g. ${VAR_NAME} or by passing it via a secure credential manager).

Confidence: HIGH

MEDIUM
------
[filesystem.delete_file]
Destructive data deletion capability

Observed:
  Tool 'filesystem.delete_file' appears capable of deleting or removing data, files, or resources.

Evidence:
  Tool name matches '^delete(?:_|\b)'

Recommendation:
  Verify that deletion tools require explicit user confirmation before execution when used by autonomous agents.

Confidence: HIGH

[local-shell]
Shell execution capability detected

Observed:
  Server 'local-shell' is configured to run shell command '/bin/bash' with arguments -c run-mcp-agent. An MCP server utilizing an interactive shell or interpreter may expose broad command execution capabilities to an AI client.

Evidence:
  /bin/bash with arguments -c run-mcp-agent

Recommendation:
  Review whether shell execution is strictly necessary. Prefer dedicated, single-purpose CLI binaries with restricted arguments.

Confidence: HIGH

[database.execute_query]
Arbitrary code or command execution capability

Observed:
  Tool 'database.execute_query' appears capable of executing arbitrary commands, scripts, or queries.

Evidence:
  Tool name matches '^execute(?:_|\b)'

Recommendation:
  Restrict parameter inputs and ensure strict sanitization or confirmation gates for code execution tools.

Confidence: HIGH

[database.drop_table]
Destructive data deletion capability

Observed:
  Tool 'database.drop_table' appears capable of deleting or removing data, files, or resources.

Evidence:
  Tool name matches '^drop(?:_|\b)'

Recommendation:
  Verify that deletion tools require explicit user confirmation before execution when used by autonomous agents.

Confidence: HIGH

LOW
---
[github]
Process execution capability detected

Observed:
  Server 'github' executes binary 'node' with arguments dist/index.js. Review process permissions and host capabilities granted to this binary.

Evidence:
  node with arguments dist/index.js

Recommendation:
  Ensure the binary runs with the least privileges necessary.

Confidence: MEDIUM

INFO
----
[filesystem.search_files, find_files]
Potentially overlapping tools

Observed:
  Tools 'filesystem.search_files' and 'filesystem.find_files' appear to provide overlapping functionality (both perform 'search' on 'files'). Overlapping tools may cause agent confusion or redundant context footprint.

Evidence:
  Tools: search_files <-> find_files

Recommendation:
  Review whether both tools are necessary or if they can be unified.

Confidence: MEDIUM

[github.search_everything]
Large MCP tool definition

Observed:
  Tool 'github.search_everything' has an estimated definition size of ~1,417 tokens (threshold: 1,000 tokens). Large tool definitions increase context overhead and prompt costs on every model invocation.

Evidence:
  ~1,417 estimated tokens

Recommendation:
  Review whether tool descriptions or JSON schemas can be streamlined or modularized.

Confidence: HIGH

Context
-------
github               ~1,443 tokens
filesystem           ~168 tokens
database             ~134 tokens
local-shell          ~27 tokens

✓ No MCP servers were started.
✓ No files were modified.
✓ No data was uploaded.
```

---

## Core Capabilities & Findings

`mcp-audit` categorizes signals into structured findings with clear evidence and confidence levels:

### 1. Filesystem Scope
* **Broad Access (`HIGH`)**: Identifies access to root directories (`/`, `~`, `/home`, `/Users`, `C:\`).
* **Restricted Access (`LOW`)**: Confirms when scope is constrained to a workspace folder (e.g. `/workspace/project`).

### 2. Command & Process Execution
* **Interactive Shells (`MEDIUM`)**: Identifies shells (`bash`, `sh`, `zsh`, `powershell`, `cmd`).
* **Dangerous Flags (`HIGH`)**: Flags switches like `--privileged`, `--no-sandbox`, `--allow-all`, `-v /:/host`.

### 3. Secret Detection & Redaction
* **Literal Secrets (`HIGH`)**: Flags hardcoded keys (e.g. `GITHUB_TOKEN=abc12345`). Secret values are **ALWAYS redacted** (`[REDACTED]`).
* **Environment References (`INFO`)**: Recognizes dynamic variable references (e.g. `${GITHUB_TOKEN}`, `$API_KEY`).

### 4. Deterministic Capability Classification
Classifies tool operations into deterministic categories:
* `READ` — Querying, fetching, searching, or viewing data
* `WRITE` — Creating, updating, or modifying resources
* `DELETE` — Removing, unlinking, or purging data
* `EXECUTE` — Running shell commands, scripts, or arbitrary SQL
* `NETWORK` — Initiating outbound HTTP/API or socket connections
* `AUTHENTICATION` — Logging in, issuing credentials, or managing tokens
* `SENSITIVE_DATA` — Exporting credentials, secrets, or vaults

> **False-Positive Immunity:** `mcp-audit` distinguishes documentation and search tools from actual operations. A tool named `search_docs` describing *"how to delete a file"* is classified as `READ`, not `DELETE`.

### 5. Context Footprint & Bloat Estimation
Estimates the token overhead contributed by tool names, descriptions, and JSON schemas.
* Flags oversized tool definitions (> 1,000 estimated tokens) for context optimization.

### 6. Redundant / Overlapping Tools
Uses deterministic action-synset and noun matching to detect duplicate or overlapping tools (e.g. `search_files` vs `find_files`).

---

## CLI Options

```text
usage: mcp-audit [-h] [--json] [--server NAME] [--severity LEVEL] [--fail-on LEVEL]
                 [--max-file-size SIZE] [--no-color] [-v] [config_path]

Audit MCP servers and tools for permissions, risky capabilities, secrets, and context bloat.

positional arguments:
  config_path           Path to the JSON MCP configuration file to audit.

options:
  -h, --help            show this help message and exit
  --json                Output structured, machine-readable JSON report.
  --server NAME         Filter audit results to a specific MCP server name.
  --severity LEVEL      Filter displayed findings to a minimum severity level (info, low, medium, high, critical).
  --fail-on LEVEL       Exit with code 1 if findings at or above this severity are detected (useful for CI/CD).
  --max-file-size SIZE  Maximum allowed configuration file size (e.g. 50MB, 10KB, 1048576). Default: 50MB.
  --no-color            Disable ANSI color highlights in terminal output.
  -v, --version         Show program version number and exit.
```

---

## Machine-Readable JSON Output

Generate structured JSON for CI/CD or automated tooling:

```bash
mcp-audit ./mcp-config.json --json
```

Includes an audit manifest with SHA-256 configuration hashing:

```json
{
  "manifest": {
    "tool_version": "0.1.0",
    "timestamp": "2026-10-04T00:33:15.123456+00:00",
    "input_file": "./mcp-config.json",
    "configuration_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "servers_count": 4,
    "tools_count": 6,
    "estimated_context_tokens": 1772,
    "analysis_limits": {
      "max_file_size": 52428800,
      "max_file_size_formatted": "50.0 MB",
      "max_string_length": 100000,
      "max_description_size": 50000,
      "max_schema_size": 200000,
      "max_servers": 1000,
      "max_tools_per_server": 1000
    }
  },
  "capabilities": {
    "READ": 5,
    "WRITE": 0,
    "DELETE": 2,
    "EXECUTE": 1,
    "NETWORK": 0,
    "AUTHENTICATION": 0,
    "SENSITIVE_DATA": 0
  },
  "findings": [ ... ]
}
```

---

## CI / CD Integration & Exit Codes

`mcp-audit` supports clean pipeline automation:

* `0`: Audit succeeded, no findings at or above `--fail-on` threshold
* `1`: Findings detected at or above `--fail-on` threshold
* `2`: Input error, file unreadable, or invalid configuration

### Example GitHub Actions step:

```yaml
- name: Audit MCP Configuration
  run: |
    pipx run mcp-audit ./mcp-config.json --fail-on high
```

---

## Security Model & Privacy

`mcp-audit` treats user configuration as **untrusted data**:

* 🚫 **Never executes configuration**: Shell commands and binaries in configs are analyzed purely as static text strings.
* 🚫 **Zero network activity**: Makes no HTTP requests, socket connections, or external API calls.
* 🚫 **No data modification**: Files are opened strictly in read-only mode.
* 🚫 **No data collection**: No telemetry, crash reporting, or analytics.
* 🔒 **Automatic secret redaction**: Never outputs or stores literal secret values.
* 🛡️ **Memory safety**: Configurable limits prevent resource exhaustion on large inputs (`--max-file-size`).

---

## Limitations

* **Heuristic Analysis**: Capability detection uses deterministic multi-signal heuristics. It does not replace code review of the underlying MCP server implementation.
* **Token Estimation**: Context footprints are subword/BPE estimates (`~3.8` characters per token for technical text + JSON protocol framing) and not exact tokenizer counts for a specific model.
* **Format Support**: V1 supports standard JSON MCP configuration files.

---

## Disclaimer

> `mcp-audit` provides heuristic analysis of MCP configurations and is not a formal security certification or guarantee. Developers remain responsible for reviewing MCP servers, permissions, credentials, and the data exposed to AI systems.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
