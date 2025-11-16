"""
Tests for MCP validator

Copyright 2025 SyzygySys
Licensed under the Apache License, Version 2.0
"""

import pytest
from pathlib import Path

from preflight_tools.mcp.validator import MCPValidator
from preflight_tools.mcp.checks import (
    ToolNameCheck,
    PropertiesSchemaCheck,
    ContentWrapperCheck,
    NotificationHandlingCheck,
    StdoutPollutionCheck,
    IssueSeverity,
)


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
    
    def test_no_print_statements(self):
        check = StdoutPollutionCheck()
        
        valid_content = '''
        import logging
        
        def tool():
            logging.error("Debug message")
            return result
        '''
        
        issues = check.check(valid_content)
        assert len(issues) == 0
    
    def test_print_statement_detected(self):
        check = StdoutPollutionCheck()
        
        invalid_content = '''
        def tool():
            print("Debug message")
            return result
        '''
        
        issues = check.check(invalid_content)
        assert len(issues) == 1
        assert issues[0].severity == IssueSeverity.ERROR
        assert "print()" in issues[0].message
    
    def test_stdout_write_detected(self):
        check = StdoutPollutionCheck()
        
        invalid_content = '''
        import sys
        sys.stdout.write("message")
        '''
        
        issues = check.check(invalid_content)
        assert len(issues) == 1
        assert "stdout" in issues[0].message.lower()


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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
