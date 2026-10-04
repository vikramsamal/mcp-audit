# Security Policy

## Security Model & Design Principles

`mcp-audit` is designed from the ground up as a **strictly local, read-only audit tool**.

### Core Guarantees:
1. **Never executes configuration**: Commands, scripts, binaries, and parameters present in configuration files are treated strictly as passive data. `mcp-audit` will never spawn, invoke, or start any MCP server or subprocess based on user input.
2. **Zero network calls**: The CLI operates completely offline. No telemetry, SaaS analytics, cloud endpoints, or external API keys are used.
3. **No configuration or filesystem mutation**: Files audited are accessed in read-only mode. `mcp-audit` will never modify, overwrite, or delete user configuration or project files.
4. **Secret redaction**: Credential-like fields (such as tokens, passwords, API keys) are detected and automatically redacted in both terminal and JSON outputs (`[REDACTED]`).

## Reporting a Vulnerability

If you discover a security vulnerability or a violation of our safety boundaries in `mcp-audit`, please report it privately:

- **Email**: `security@vikramsamal.com` (or create a GitHub Private Security Advisory)
- Please include:
  - Description of the vulnerability
  - Minimal reproducible example or test case
  - Potential impact

We take all security reports seriously and will respond promptly with an assessment and remediation plan.
