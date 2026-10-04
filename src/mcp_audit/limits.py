"""Resource limits and memory safety configurations for mcp-audit."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
DEFAULT_MAX_STRING_LENGTH = 100_000       # 100,000 chars
DEFAULT_MAX_DESCRIPTION_SIZE = 50_000     # 50,000 chars
DEFAULT_MAX_SCHEMA_SIZE = 200_000         # 200,000 chars
DEFAULT_MAX_SERVERS = 1_000
DEFAULT_MAX_TOOLS_PER_SERVER = 1_000


class FileSizeExceededError(ValueError):
    """Raised when a configuration file exceeds the maximum allowed size."""

    def __init__(self, file_path: str, size: int, max_size: int):
        self.file_path = file_path
        self.size = size
        self.max_size = max_size
        super().__init__(
            f"Configuration file '{file_path}' exceeds limit: "
            f"{format_byte_size(size)} > {format_byte_size(max_size)}"
        )


def parse_byte_size(size_str: str) -> int:
    """Parse a human-readable size string (e.g. '50MB', '10KB', '1048576') into bytes.

    Raises:
        ValueError: If size_str cannot be parsed into a valid positive integer.
    """
    if not size_str or not isinstance(size_str, str):
        raise ValueError("Invalid file size string: cannot be empty")

    size_str = size_str.strip()
    match = re.match(r"^(\d+(?:\.\d+)?)\s*([a-zA-Z]*)$", size_str)
    if not match:
        raise ValueError(f"Invalid byte size specification: '{size_str}'")

    number_str, unit = match.groups()
    number = float(number_str)
    unit = unit.upper()

    multipliers = {
        "": 1,
        "B": 1,
        "BYTES": 1,
        "K": 1024,
        "KB": 1024,
        "KIB": 1024,
        "M": 1024 * 1024,
        "MB": 1024 * 1024,
        "MIB": 1024 * 1024,
        "G": 1024 * 1024 * 1024,
        "GB": 1024 * 1024 * 1024,
        "GIB": 1024 * 1024 * 1024,
    }

    if unit not in multipliers:
        raise ValueError(f"Unknown size unit: '{unit}' in '{size_str}'")

    bytes_val = int(number * multipliers[unit])
    if bytes_val <= 0:
        raise ValueError(f"Size must be greater than zero: '{size_str}'")
    return bytes_val


def format_byte_size(bytes_val: int) -> str:
    """Format bytes into a human-readable string."""
    if bytes_val < 1024:
        return f"{bytes_val} B"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.1f} KB"
    elif bytes_val < 1024 * 1024 * 1024:
        return f"{bytes_val / (1024 * 1024):.1f} MB"
    else:
        return f"{bytes_val / (1024 * 1024 * 1024):.1f} GB"


@dataclass(frozen=True)
class AnalysisLimits:
    """Configuration limits for static analysis."""

    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    max_string_length: int = DEFAULT_MAX_STRING_LENGTH
    max_description_size: int = DEFAULT_MAX_DESCRIPTION_SIZE
    max_schema_size: int = DEFAULT_MAX_SCHEMA_SIZE
    max_servers: int = DEFAULT_MAX_SERVERS
    max_tools_per_server: int = DEFAULT_MAX_TOOLS_PER_SERVER

    def check_file_size(self, file_path: str) -> int:
        """Check if file size exceeds max_file_size without reading content into memory."""
        try:
            stat_info = os.stat(file_path)
            size = stat_info.st_size
        except OSError as exc:
            raise OSError(f"Cannot access file '{file_path}': {exc}") from exc

        if size > self.max_file_size:
            raise FileSizeExceededError(file_path, size, self.max_file_size)
        return size

    def bounded_string(self, text: str, max_length: int | None = None) -> tuple[str, bool]:
        """Truncate string to max_length if it exceeds bounds, returning (result, was_truncated)."""
        limit = max_length if max_length is not None else self.max_string_length
        if len(text) > limit:
            return text[:limit], True
        return text, False

    def to_dict(self) -> dict[str, str | int]:
        """Convert limits to JSON-serializable dictionary."""
        return {
            "max_file_size": self.max_file_size,
            "max_file_size_formatted": format_byte_size(self.max_file_size),
            "max_string_length": self.max_string_length,
            "max_description_size": self.max_description_size,
            "max_schema_size": self.max_schema_size,
            "max_servers": self.max_servers,
            "max_tools_per_server": self.max_tools_per_server,
        }
