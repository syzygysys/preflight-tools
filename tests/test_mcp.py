"""
Tests for MCP validator

Copyright 2025 SyzygySys.io
Licensed under the Apache License, Version 2.0
"""

import pytest
from pathlib import Path
import textwrap
from typing import List

from preflight_tools.mcp.validator import MCPValidator, ValidationResult
from preflight_tools.mcp.checks import (
    BaseCheck,
    ToolNameCheck,
    PropertiesSchemaCheck,
    ContentWrapperCheck,
    NotificationHandlingCheck,
    StdoutPollutionCheck,
    JsonRpcResponseStructureCheck,
    ValidationIssue,
    IssueSeverity,
)


class TestBaseCheck:
    def test_check_not_implemented(self):
        base = BaseCheck()
        with pytest.raises(NotImplementedError):
            base.check("content")


class TestToolNameCheck:
    """Test tool name validation"""
    
    def test_valid_names(self):
        check = ToolNameCheck()
        
        valid_content = '''
        tools = [
            {"name": "lap_health_ping"},
            {"name": "lap_core_status"},
            {"name": "my-tool-123"},
            {"name": "TOOL_NAME"},
        ]
        '''
        
        issues = check.check(valid_content)
        assert len(issues) == 0
    
    def test_invalid_names_with_dots(self):
        check = ToolNameCheck()
        
        invalid_content = '''
        tools = [
            {"name": "lap.health.ping"},
            {"name": "my.tool"},
        ]
        '''
        
        issues = check.check(invalid_content)
        assert len(issues) == 2
        assert all(issue.severity == IssueSeverity.ERROR for issue in issues)
        assert "lap.health.ping" in issues[0].message
    
    def test_invalid_names_with_spaces(self):
        check = ToolNameCheck()
        
        invalid_content = '''{"name": "my tool"}'''
        
        issues = check.check(invalid_content)
        assert len(issues) == 1
        assert "my tool" in issues[0].message
    
    def test_name_too_long(self):
        check = ToolNameCheck()
        
        long_name = "a" * 65
        invalid_content = f'{{"name": "{long_name}"}}'
        
        issues = check.check(invalid_content)
        assert len(issues) == 1

    def test_documentation_examples_are_ignored(self):
        check = ToolNameCheck()

        doc_content = '''
        {"name": "..."}
        {"name": "tool_name"}
        {"name": "example"}
        '''

        issues = check.check(doc_content)
        assert issues == []


class TestPropertiesSchemaCheck:
    """Test properties schema validation"""
    
    def test_valid_empty_properties(self):
        check = PropertiesSchemaCheck()
        
        valid_content = '''
        {
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }
        '''
        
        issues = check.check(valid_content)
        assert len(issues) == 0
    
    def test_invalid_array_properties(self):
        check = PropertiesSchemaCheck()
        
        invalid_content = '''
        {
            "inputSchema": {
                "type": "object",
                "properties": []
            }
        }
        '''
        
        issues = check.check(invalid_content)
        assert len(issues) == 1
        assert issues[0].severity == IssueSeverity.ERROR
        assert "array" in issues[0].message.lower()

    def test_docstring_examples_are_ignored(self):
        check = PropertiesSchemaCheck()

        doc_content = '''
        """
        Example:
            "properties": []
        """
        '''

        issues = check.check(doc_content)
        assert issues == []

    def test_commented_properties_are_ignored(self):
        check = PropertiesSchemaCheck()

        comment_content = '#   "properties": []'

        issues = check.check(comment_content)
        assert issues == []


class TestContentWrapperCheck:
    """Test content wrapper validation"""
    
    def test_properly_wrapped_response(self):
        check = ContentWrapperCheck()
        
        valid_content = '''
        def tool():
            return {
                "content": [{
                    "type": "text",
                    "text": json.dumps({"status": "ok"})
                }]
            }
        '''
        
        issues = check.check(valid_content)
        # Should have no errors (might have warnings on heuristics)
        errors = [i for i in issues if i.severity == IssueSeverity.ERROR]
        assert len(errors) == 0
    
    def test_missing_wrapper(self):
        check = ContentWrapperCheck()
        
        invalid_content = '''
        def tool():
            return {"status": "ok", "value": 42}
        '''
        
        issues = check.check(invalid_content)
        assert len(issues) >= 1
        assert any("wrapper" in issue.message.lower() for issue in issues)


class TestNotificationHandlingCheck:
    """Test notification handling validation"""
    
    def test_proper_notification_check(self):
        check = NotificationHandlingCheck()
        
        valid_content = '''
        def dispatch(request):
            if "id" not in request:
                return ""
            # handle request
        '''
        
        issues = check.check(valid_content)
        # Heuristic check - should pass
        assert len([i for i in issues if i.severity == IssueSeverity.ERROR]) == 0
    
    def test_missing_notification_check(self):
        check = NotificationHandlingCheck()
        
        invalid_content = '''
        def dispatch(request):
            method = request.get("method")
            # no notification check
        '''
        
        issues = check.check(invalid_content)
        assert len(issues) >= 1


class TestStdoutPollutionCheck:
    """Test stdout pollution detection"""
    
    @staticmethod
    def _clean(content: str) -> str:
        return textwrap.dedent(content).strip("\n")
    
    def test_no_print_statements(self):
        check = StdoutPollutionCheck()
        
        valid_content = self._clean('''
        import logging
        
        def tool():
            logging.error("Debug message")
            return result
        ''')
        
        issues = check.check(valid_content)
        assert len(issues) == 0
    
    def test_print_statement_detected(self):
        check = StdoutPollutionCheck()
        
        invalid_content = self._clean('''
        def tool():
            print("Debug message")
            return result
        ''')
        
        issues = check.check(invalid_content)
        assert len(issues) == 1
        assert issues[0].severity == IssueSeverity.ERROR
        assert "print()" in issues[0].message
    
    def test_stdout_write_detected(self):
        check = StdoutPollutionCheck()
        
        invalid_content = self._clean('''
        import sys
        sys.stdout.write("message")
        ''')
        
        issues = check.check(invalid_content)
        assert len(issues) == 1
        assert "stdout" in issues[0].message.lower()

    def test_console_print_not_flagged(self):
        check = StdoutPollutionCheck()
        
        content = self._clean('''
        from rich.console import Console
        console = Console(stderr=True)
        console.print("ok")
        ''')
        
        issues = check.check(content)
        assert issues == []

    def test_print_alias_detected(self):
        check = StdoutPollutionCheck()
        
        content = self._clean('''
        logger = print
        
        def tool():
            logger("debug")
        ''')
        
        issues = check.check(content)
        assert len(issues) == 1
        assert "print()" in issues[0].message.lower()

    def test_stdout_alias_write_detected(self):
        check = StdoutPollutionCheck()
        
        content = self._clean('''
        import sys
        stdout = sys.stdout
        
        def tool():
            stdout.write("bad")
        ''')
        
        issues = check.check(content)
        assert len(issues) == 1
        assert "stdout" in issues[0].message.lower()

    def test_sys_stdout_reassignment_detected(self):
        check = StdoutPollutionCheck()
        
        content = self._clean('''
        import sys
        import io
        
        sys.stdout = io.StringIO()
        ''')
        
        issues = check.check(content)
        assert len(issues) == 1
        assert "reassigning" in issues[0].message.lower()

    def test_from_sys_import_stdout_detected(self):
        check = StdoutPollutionCheck()

        content = self._clean('''
        from sys import stdout as std_out

        def tool():
            std_out.write("bad")
        ''')

        issues = check.check(content)
        assert len(issues) == 1
        assert "stdout" in issues[0].message.lower()

    def test_annotated_stdout_alias_detected(self):
        check = StdoutPollutionCheck()

        content = self._clean('''
        import sys
        from typing import TextIO

        stdout_alias: TextIO = sys.stdout

        def tool():
            stdout_alias.write("still bad")
        ''')

        issues = check.check(content)
        assert len(issues) == 1
        assert "stdout" in issues[0].message.lower()

    def test_alias_reassignment_warns(self):
        check = StdoutPollutionCheck()

        content = self._clean('''
        import sys

        stdout_alias = sys.stdout
        stdout_alias = object()
        ''')

        issues = check.check(content)
        assert len(issues) == 1
        assert "alias" in issues[0].message.lower()

    def test_attribute_print_detected(self):
        check = StdoutPollutionCheck()

        content = self._clean('''
        class Wrapper:
            def __init__(self):
                self.print = print

        def tool():
            wrapper = Wrapper()
            wrapper.print("hi")
        ''')

        issues = check.check(content)
        assert len(issues) == 1
        assert "print" in issues[0].message.lower()

    def test_imported_print_alias_detected(self):
        check = StdoutPollutionCheck()

        content = self._clean('''
        from sys import print as builtin_print

        def tool():
            builtin_print("noise")
        ''')

        issues = check.check(content)
        assert len(issues) == 1
        assert "print" in issues[0].message.lower()

    def test_console_print_alias_allowed(self):
        check = StdoutPollutionCheck()

        content = self._clean('''
        from rich.console import Console
        console = Console()
        safe_print = console.print

        def tool():
            safe_print("ok")
        ''')

        issues = check.check(content)
        assert issues == []

    def test_unrelated_write_not_flagged(self):
        check = StdoutPollutionCheck()

        content = self._clean('''
        class Writer:
            def write(self, message):
                pass

        writer = Writer()

        def tool():
            writer.write("ok")
        ''')

        issues = check.check(content)
        assert issues == []


class TestMCPValidator:
    """Test MCPValidator integration"""
    
    def test_validate_content_all_pass(self):
        validator = MCPValidator()
        
        clean_content = '''
        import logging
        
        tools = [
            {
                "name": "lap_health_ping",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ]
        
        def lap_health_ping():
            return {
                "content": [{
                    "type": "text",
                    "text": "pong"
                }]
            }
        '''
        
        result = validator.validate_content(clean_content)
        assert result.passed
        assert result.error_count == 0
    
    def test_validate_content_with_errors(self):
        validator = MCPValidator()
        
        bad_content = '''
        tools = [{"name": "lap.bad.name"}]
        
        def tool():
            print("Bad!")
            return {"status": "ok"}
        '''
        
        result = validator.validate_content(bad_content)
        assert not result.passed
        assert result.error_count > 0
    
    def test_strict_mode(self):
        validator = MCPValidator(strict=True)
        
        # Content that has warnings but no errors
        warning_content = '''
        def dispatch(request):
            # Missing notification check - warning
            return handle(request)
        '''
        
        result = validator.validate_content(warning_content)
        # In strict mode, warnings fail the validation
        assert not result.passed
    
    def test_ignore_checks(self):
        validator = MCPValidator(ignore_checks=["stdout_pollution"])
        
        content_with_print = '''
        def tool():
            print("This is ignored")
        '''
        
        result = validator.validate_content(content_with_print)
        # Should pass because we're ignoring stdout_pollution
        assert result.passed

    def test_validate_file_missing_path(self, tmp_path):
        validator = MCPValidator()
        missing = tmp_path / "missing.py"

        result = validator.validate_file(missing)
        assert not result.passed
        assert result.error_count == 1
        assert result.issues[0].check_name == "file_access"

    def test_validate_file_reads_content(self, tmp_path):
        validator = MCPValidator()
        file_path = tmp_path / "tool.py"
        file_path.write_text('def tool():\n    return {"content": [{"type": "text", "text": "ok"}]}\n')

        result = validator.validate_file(file_path)
        assert result.file_path == file_path
        assert result.total_checks == len(validator.checks)

    def test_validate_directory_collects_files(self, tmp_path):
        validator = MCPValidator(ignore_checks=["stdout_pollution"])
        (tmp_path / "sub").mkdir()
        files = [
            tmp_path / "tool_a.py",
            tmp_path / "sub" / "tool_b.py",
        ]
        for f in files:
            f.write_text('def tool():\n    return {"content": [{"type": "text", "text": "ok"}]}\n')

        results = validator.validate_directory(tmp_path)
        assert set(results.keys()) == set(files)


class TestValidatorIntegration:
    """Integration tests for full validation workflow"""
    
    def test_lap_core_style_tools(self):
        """Test validation against LAP::CORE style tools"""
        validator = MCPValidator()
        
        lap_style_content = '''
"""LAP::CORE MCP Tools"""
import logging
from typing import Dict, Any
import json

def _wrap_mcp_content(result: Any) -> dict:
    """Wrap tool results in MCP content structure."""
    if isinstance(result, dict) and "content" in result:
        return result
    text = json.dumps(result) if not isinstance(result, str) else result
    return {
        "content": [{
            "type": "text",
            "text": text
        }]
    }

TOOLS = [
    {
        "name": "lap_health_ping",
        "description": "Check LAP::CORE health",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "lap_core_status",
        "description": "Get platform status",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scope": {
                    "type": "string",
                    "enum": ["basic", "detailed", "full"]
                }
            }
        }
    }
]

async def dispatch(request: dict) -> str:
    """Dispatch MCP request to appropriate handler."""
    # Check if this is a notification (no "id" field)
    if "id" not in request:
        return ""
    
    method = request.get("method")
    logging.info(f"Dispatching: {method}")
    
    # Handle method...
    return json.dumps(response)
'''
        
        result = validator.validate_content(lap_style_content)
        
        # Should pass all checks
        assert result.passed
        assert result.error_count == 0
        
        # Verify the good patterns are detected
        assert "lap_health_ping" in lap_style_content
        assert '"id" not in request' in lap_style_content
        assert "logging." in lap_style_content


class TestJsonRpcResponseStructureCheck:
    """Test JSON-RPC response structure validation"""

    def test_exclude_none_flagged(self):
        check = JsonRpcResponseStructureCheck()

        content = '''
        def respond():
            payload = {"jsonrpc": "2.0", "id": 1}
            return payload.model_dump_json(exclude_none=True)
        '''

        issues = check.check(content)
        assert len(issues) == 1
        assert "exclude_none" in issues[0].message

    def test_docstring_exclude_none_ignored(self):
        check = JsonRpcResponseStructureCheck()

        content = '''
        """
        jsonrpc example
        model_dump_json(exclude_none=True)
        """
        '''

        issues = check.check(content)
        assert issues == []

    def test_pop_required_field_flagged(self):
        check = JsonRpcResponseStructureCheck()

        content = '''
        def cleanup():
            response = {"jsonrpc": "2.0", "id": 1}
            response.pop("jsonrpc")
            return response
        '''

        issues = check.check(content)
        assert len(issues) == 1
        assert "jsonrpc" in issues[0].message.lower()

    def test_exclude_none_comment_ignored(self):
        check = JsonRpcResponseStructureCheck()

        content = '''
        # payload.model_dump_json(exclude_none=True)
        jsonrpc = "2.0"
        '''

        issues = check.check(content)
        assert issues == []

    def test_exclude_none_end_of_file(self):
        check = JsonRpcResponseStructureCheck()

        content = textwrap.dedent('''
        def respond():
            payload = {"jsonrpc": "2.0"}
            return payload.model_dump_json(exclude_none=True)
        ''').strip()

        issues = check.check(content)
        assert len(issues) == 1

    def test_pop_docstring_ignored(self):
        check = JsonRpcResponseStructureCheck()

        content = '''
        """
        response.pop("jsonrpc")
        """
        jsonrpc = "2.0"
        '''

        issues = check.check(content)
        assert issues == []

    def test_pop_comment_ignored(self):
        check = JsonRpcResponseStructureCheck()

        content = '''
        # response.pop("id")
        jsonrpc = "2.0"
        '''

        issues = check.check(content)
        assert issues == []

    def test_pop_end_of_file(self):
        check = JsonRpcResponseStructureCheck()

        content = textwrap.dedent('''
        def cleanup():
            response = {"jsonrpc": "2.0", "id": 1}
            response.pop("id")
        ''').strip()

        issues = check.check(content)
        assert len(issues) == 1


class TestValidationResultCounts:
    def test_counts(self):
        issues: List[ValidationIssue] = [
            ValidationIssue("test", IssueSeverity.ERROR, "err"),
            ValidationIssue("test", IssueSeverity.WARNING, "warn"),
            ValidationIssue("test", IssueSeverity.INFO, "info"),
        ]
        result = ValidationResult(Path("sample.py"), total_checks=3, issues=issues, passed=False)

        assert result.error_count == 1
        assert result.warning_count == 1
        assert result.info_count == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
