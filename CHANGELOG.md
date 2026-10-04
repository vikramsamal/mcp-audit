# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-04

### Added
- **MCP configuration analysis**: Safe, bounded parsing and normalization of JSON MCP configuration files.
- **Deterministic capability classification**: Classify tool capabilities (`READ`, `WRITE`, `DELETE`, `EXECUTE`, `NETWORK`, `AUTHENTICATION`, `SENSITIVE_DATA`, `UNKNOWN`) with multi-signal confidence scores and false-positive immunity for documentation/reference tools.
- **Filesystem scope analysis**: Detect broad root paths (`/`, `/home`, `~`, `C:\`) vs narrow project scopes.
- **Command & argument security inspection**: Analyze configured commands for interactive shells (`bash`, `sh`, `zsh`), container breakout flags (`--privileged`, `--no-sandbox`), and dangerous switches.
- **Secret detection & automatic redaction**: Identify credential-like variables (`GITHUB_TOKEN`, `API_KEY`, `PASSWORD`) and differentiate static literal secrets from dynamic environment variable references (`${VAR}`). Automatic redaction (`[REDACTED]`) across all outputs.
- **Context footprint estimation**: Estimate token overhead for server definitions, schemas, and tool descriptions.
- **Context bloat & large tool detection**: Flag oversized tool definitions that contribute to prompt bloat.
- **Redundant / Overlapping tools analysis**: Deterministic tool similarity detection based on action synsets and noun overlap.
- **CLI interface & CI support**: Clean ANSI terminal output, `--no-color`, `--server` filtering, `--severity` filtering, `--max-file-size` controls, and `--fail-on` exit codes (0, 1, 2) for automated CI pipelines.
- **Machine-readable JSON output**: Full structured audit reports with reproducible audit manifests and configuration hashes.
- **Read-only and offline safety model**: Zero subprocess execution of configs, zero network calls, zero file mutations.
