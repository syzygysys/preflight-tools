# Preflight Tools

Reference validators for autonomous systems protocols: MCP, A2A, ACE, OCC/OCS/OCP

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## Overview

Preflight Tools provides reference implementations for protocol compliance validation across autonomous agent ecosystems. These validators catch common integration issues before deployment, saving hours of debugging.

### Supported Protocols

- **MCP** (Model Context Protocol) - Anthropic's protocol for LLM tool integration
- **A2A** (Agent-to-Agent) - Peer communication protocol for autonomous agents
- **ACE** (Autonomic Compliance Ecosystem) - Platform orchestration standards
- **OCC/OCS/OCP** - *(Coming soon)* Observability, compliance, and policy protocols

## Installation
```bash
# Via pip
pip install preflight-tools

# Via Poetry
poetry add preflight-tools

# From source
git clone https://github.com/syzygysys/preflight-tools.git
cd preflight-tools
poetry install
```

## Quick Start

### MCP Validation

Validate your MCP server implementation against the specification:
```bash
# Validate a tools definition file
mcp-preflight-check validate path/to/tools.py

# Test a running server
mcp-preflight-check test http://localhost:8000

# Full report with verbose output
mcp-preflight-check validate --verbose path/to/tools.py
```

**Example output:**
```
✅ Tool names: All valid [a-zA-Z0-9_-]
✅ Properties schemas: All using objects {}
✅ Content wrappers: All responses properly wrapped
✅ Notification handling: Correctly implemented
✅ JSON-RPC structure: All responses include required fields
❌ Stdout pollution: Found 3 print statements that will break stdio transport

Fix suggestions:
  Line 42: Remove print() statement
  Line 89: Use logging instead of print()
  Line 134: Redirect to stderr
```

### A2A Validation

*(Coming soon)* Validate Agent-to-Agent protocol implementations:
```bash
a2a-preflight-check validate path/to/agent_config.yml
```

## The Six Critical MCP Fixes

This validator is built from real-world debugging of LAP::CORE's MCP integration. See the full story: [Debugging the Bridge](https://syzygysys.github.io/docs/architects_notebook/log_14.html)

### 1. Tool Name Pattern

**Problem:** Tool names with dots fail Zod validation  
**Rule:** Must match `^[a-zA-Z0-9_-]{1,64}$`
```python
# ❌ FAILS
{"name": "lap.health.ping"}

# ✅ PASSES
{"name": "lap_health_ping"}
```

### 2. Properties Schema Type

**Problem:** Empty properties as `[]` instead of `{}`  
**Rule:** JSON Schema requires properties to be an object
```python
# ❌ FAILS
{
    "inputSchema": {
        "type": "object",
        "properties": []  # Wrong type
    }
}

# ✅ PASSES
{
    "inputSchema": {
        "type": "object",
        "properties": {}  # Correct type
    }
}
```

### 3. Content Wrapper Structure

**Problem:** Returning raw data instead of MCP content structure  
**Rule:** All responses must be wrapped
```python
# ❌ FAILS
return {"status": "ok", "value": 42}

# ✅ PASSES
return {
    "content": [{
        "type": "text",
        "text": json.dumps({"status": "ok", "value": 42})
    }]
}
```

### 4. Notification Handling

**Problem:** Returning errors for notification requests (no `id` field)  
**Rule:** Notifications don't expect responses
```python
# ❌ FAILS
async def dispatch(self, request: dict) -> str:
    method = request.get("method")
    if method not in self.handlers:
        return json.dumps({"error": "unknown method"})

# ✅ PASSES
async def dispatch(self, request: dict) -> str:
    # Check if this is a notification (no "id" field)
    if "id" not in request:
        return ""  # Silent success
    
    method = request.get("method")
    # ... handle request-response
```

### 5. Stdout Pollution

**Problem:** Any output to stdout breaks JSON-RPC stdio transport  
**Rule:** Redirect stderr early, never use print()
```bash
# ❌ FAILS - stderr goes to stdout
poetry run mcp-server 2>> /tmp/debug.log

# ✅ PASSES - redirect before Python starts
exec 2>/tmp/debug.log; poetry run mcp-server
```

**In code:**
```python
# ❌ NEVER
print("Debug message")

# ✅ ALWAYS
import logging
logging.error("Debug message")  # Goes to stderr
```

### 6. JSON-RPC Response Structure

**Problem:** Using `exclude_none=True` removes required fields when they're `None`  
**Rule:** JSON-RPC 2.0 requires `id` and `jsonrpc` in every response
```python
# ❌ FAILS - removes 'id' when it's None
class JsonRpcResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Any] = None
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None
    
    def json(self, **kwargs):
        return self.model_dump_json(exclude_none=True, **kwargs)

# ✅ PASSES - keeps required fields
class JsonRpcResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Any] = None
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None
    
    def json(self, **kwargs):
        data = self.model_dump()
        # Keep id and jsonrpc always, only exclude result/error conditionally
        if data.get('error') is not None:
            data.pop('result', None)
        elif data.get('result') is not None:
            data.pop('error', None)
        return json.dumps(data)
```

## API Usage

### Python API
```python
from preflight_tools.mcp import MCPValidator

validator = MCPValidator()

# Validate a tools file
results = validator.validate_file("path/to/tools.py")

for issue in results.issues:
    print(f"{issue.severity}: {issue.message}")
    print(f"  Fix: {issue.suggestion}")

# Test a running server
results = validator.test_server("http://localhost:8000")
print(f"Protocol version: {results.protocol_version}")
print(f"Tools found: {len(results.tools)}")
```

### Configuration

Create a `.preflight.toml` in your project root:
```toml
[mcp]
strict = true  # Fail on warnings
ignore = ["stdout-pollution"]  # Skip specific checks

[a2a]
version = "0.1.0"
require_auth = true
```

## Development
```bash
# Clone and setup
git clone https://github.com/syzygysys/preflight-tools.git
cd preflight-tools
poetry install

# Run tests
poetry run pytest

# Run validator on itself
poetry run mcp-preflight-check validate src/

# Format and lint
poetry run black src/ tests/
poetry run ruff check src/ tests/
poetry run mypy src/
```

## Architecture
```
preflight-tools/
├── src/preflight_tools/
│   ├── mcp/              # MCP validation
│   │   ├── validator.py  # Core validation logic
│   │   ├── checks.py     # Individual check implementations
│   │   └── cli.py        # Command-line interface
│   ├── a2a/              # A2A validation (coming soon)
│   └── common/           # Shared utilities
├── tests/
│   ├── test_mcp.py
│   └── fixtures/         # Test cases
└── docs/
    └── protocols/        # Protocol specs
```

## Contributing

We welcome contributions! This is a reference implementation for the community.

1. Fork the repo
2. Create a feature branch
3. Add tests for new validators
4. Submit a PR with clear description

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Related Projects

- [LAP::CORE](https://github.com/syzygysys/lap_core) - LAPI orchestration platform
- [ACE Framework](https://github.com/syzygysys) - Autonomic Compliance Ecosystem
- [MCP Specification](https://modelcontextprotocol.io/) - Official MCP docs

## References

- [Log 14: Debugging the Bridge](https://syzygysys.github.io/docs/architects_notebook/log_14.html) - The debugging session that inspired this tool
- [MCP GitHub Issues](https://github.com/anthropics/mcp/issues) - Report MCP bugs here
- [SyzygySys Architecture Notebook](https://syzygysys.github.io/docs/architects_notebook/) - More technical deep-dives

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

Copyright 2025 SyzygySys

## Support

- Issues: [GitHub Issues](https://github.com/syzygysys/preflight-tools/issues)
- Discussions: [GitHub Discussions](https://github.com/syzygysys/preflight-tools/discussions)
- Email: kevin@syzygysys.com

---

Built with ❤️ as a gift to the autonomous systems community.
