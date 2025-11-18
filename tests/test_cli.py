"""CLI coverage tests for MCP and A2A placeholders."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from preflight_tools.mcp.cli import app as mcp_cli
from preflight_tools.a2a.cli import app as a2a_cli


runner = CliRunner()


class TestA2ACLI:
    def test_validate_acknowledges_placeholder(self, tmp_path: Path):
        dummy_file = tmp_path / "a2a.yml"
        dummy_file.write_text("name: test")

        result = runner.invoke(a2a_cli, ["validate", str(dummy_file)])

        assert result.exit_code == 0
        stdout = result.stdout.lower()
        assert "coming soon" in stdout
        assert "community contributions" in stdout


class TestMcpCLI:
    def test_version_command_outputs_metadata(self):
        result = runner.invoke(mcp_cli, ["version"])

        assert result.exit_code == 0
        assert "mcp-preflight-check version" in result.stdout

    def test_list_checks_displays_registry(self):
        result = runner.invoke(mcp_cli, ["list-checks"])

        assert result.exit_code == 0
        assert "tool_name_pattern" in result.stdout
        assert "stdout_pollution" in result.stdout

    def test_validate_file_success(self, tmp_path: Path):
        tool_file = tmp_path / "tools.py"
        tool_file.write_text(
            """
def ping():
    return {
        "content": [{"type": "text", "text": "pong"}]
    }
"""
        )

        result = runner.invoke(mcp_cli, ["validate", str(tool_file)])

        assert result.exit_code == 0
        assert "PASSED" in result.stdout

    def test_validate_missing_path_fails_with_reason(self, tmp_path: Path):
        missing = tmp_path / "missing.py"

        result = runner.invoke(mcp_cli, ["validate", str(missing)])

        assert result.exit_code == 1
        assert "path not found" in result.stderr.lower()
