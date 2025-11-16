"""
MCP (Model Context Protocol) validator

Validates MCP server implementations against the specification:
https://modelcontextprotocol.io/

Copyright 2025 SyzygySys
Licensed under the Apache License, Version 2.0
"""

from preflight_tools.mcp.validator import MCPValidator
from preflight_tools.mcp.checks import (
    ToolNameCheck,
    PropertiesSchemaCheck,
    ContentWrapperCheck,
    NotificationHandlingCheck,
    StdoutPollutionCheck,
)

__all__ = [
    "MCPValidator",
    "ToolNameCheck",
    "PropertiesSchemaCheck",
    "ContentWrapperCheck",
    "NotificationHandlingCheck",
    "StdoutPollutionCheck",
]
