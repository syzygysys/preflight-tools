"""
MCP Protocol Compliance Checks

Implements the five critical validations from debugging LAP::CORE integration.
See: https://syzygysys.github.io/docs/architects_notebook/log_14.html

Copyright 2025 SyzygySys
Licensed under the Apache License, Version 2.0
"""

import re
import ast
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class IssueSeverity(Enum):
    """Issue severity levels"""
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass
class ValidationIssue:
    """A validation issue found during preflight checks"""
    check_name: str
    severity: IssueSeverity
    message: str
    line_number: Optional[int] = None
    suggestion: Optional[str] = None
    code_snippet: Optional[str] = None


class BaseCheck:
    """Base class for validation checks"""
    
    name: str = "base_check"
    description: str = "Base validation check"
    
    def check(self, content: str, file_path: Optional[Path] = None) -> List[ValidationIssue]:
        """Run the check and return any issues found"""
        raise NotImplementedError


class ToolNameCheck(BaseCheck):
    """
    Check #1: Tool names must match ^[a-zA-Z0-9_-]{1,64}$
    
    The MCP specification enforces strict naming via Zod schema validation.
    Dots, spaces, and other special characters are not allowed.
    
    Example:
        Bad: "lap.health.ping"
        Good: "lap_health_ping"
    """
    
    name = "tool_name_pattern"
    description = "Validate tool names match [a-zA-Z0-9_-] pattern"
    
    PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')
    
    def check(self, content: str, file_path: Optional[Path] = None) -> List[ValidationIssue]:
        issues = []
        
        # Find all "name": "..." entries in JSON-like structures
        for match in re.finditer(r'"name":\s*"([^"]+)"', content):
            name = match.group(1)
            # Skip documentation examples
            if name in ['...', 'tool_name', 'example']:
                continue
            if not self.PATTERN.match(name):
                line_num = content[:match.start()].count('\n') + 1
                issues.append(ValidationIssue(
                    check_name=self.name,
                    severity=IssueSeverity.ERROR,
                    message=f"Invalid tool name: '{name}'",
                    line_number=line_num,
                    suggestion=f"Use only [a-zA-Z0-9_-]. Try: '{name.replace('.', '_')}'",
                    code_snippet=match.group(0)
                ))
        
        return issues


class PropertiesSchemaCheck(BaseCheck):
    """
    Check #2: Properties must be objects {}, not arrays []
    
    JSON Schema strictly requires properties to be an object type.
    Python's type system is forgiving, but validation fails.
    
    Example:
        Bad: "properties": []
        Good: "properties": {}
    """
    
    name = "properties_schema_type"
    description = "Validate properties are objects, not arrays"
    
    def check(self, content: str, file_path: Optional[Path] = None) -> List[ValidationIssue]:
        issues = []
        
        # Find "properties": [] patterns, but skip docstrings
        for match in re.finditer(r'"properties":\s*\[\s*\]', content):
            # Check if this is in a docstring
            line_num = content[:match.start()].count('\n') + 1
            line_start = content.rfind('\n', 0, match.start()) + 1
            line_content = content[line_start:match.end()]
            
            # Skip if in docstring or comment
            if '"""' in content[max(0, match.start()-100):match.start()] or "'''" in content[max(0, match.start()-100):match.start()]:
                continue
            if line_content.strip().startswith('#'):
                continue
                
            issues.append(ValidationIssue(
                check_name=self.name,
                severity=IssueSeverity.ERROR,
                message="Properties defined as array instead of object",
                line_number=line_num,
                suggestion="Change 'properties: []' to 'properties: {}'",
                code_snippet=match.group(0)
            ))
        
        return issues


class ContentWrapperCheck(BaseCheck):
    """
    Check #3: Tool responses must be wrapped in MCP content structure
    
    All tool responses must follow:
    {"content": [{"type": "text", "text": "..."}]}
    
    Example:
        Bad: return {"status": "ok"}
        Good: return {"content": [{"type": "text", "text": '{"status": "ok"}'}]}
    """
    
    name = "content_wrapper"
    description = "Validate responses use MCP content wrapper"
    
    def check(self, content: str, file_path: Optional[Path] = None) -> List[ValidationIssue]:
        issues = []
        
        # Look for return statements that don't wrap content
        # This is a heuristic check - looks for common anti-patterns
        
        # Pattern: return statements with dict literals but no "content" key
        return_pattern = r'return\s+\{[^}]*\}'
        for match in re.finditer(return_pattern, content):
            return_statement = match.group(0)
            if '"content"' not in return_statement and 'content' not in return_statement:
                # Check if it looks like a tool response
                if any(key in return_statement for key in ['"result"', '"data"', '"status"', '"value"']):
                    line_num = content[:match.start()].count('\n') + 1
                    issues.append(ValidationIssue(
                        check_name=self.name,
                        severity=IssueSeverity.WARNING,
                        message="Return statement may need MCP content wrapper",
                        line_number=line_num,
                        suggestion="Wrap response: {'content': [{'type': 'text', 'text': json.dumps(result)}]}",
                        code_snippet=return_statement[:50] + "..." if len(return_statement) > 50 else return_statement
                    ))
        
        return issues


class NotificationHandlingCheck(BaseCheck):
    """
    Check #4: Notifications (no "id" field) must not return errors
    
    MCP uses JSON-RPC notifications for lifecycle events like
    notifications/initialized. These requests have no "id" field
    and don't expect responses.
    
    Example:
        Bad: if method not in handlers: return error_response()
        Good: if "id" not in request: return ""
    """
    
    name = "notification_handling"
    description = "Validate notification requests return empty string"
    
    def check(self, content: str, file_path: Optional[Path] = None) -> List[ValidationIssue]:
        issues = []
        
        # Look for dispatch/handler functions that don't check for notifications
        # Pattern: functions that handle requests but don't check for "id" field
        
        # Find function definitions that look like request handlers
        func_pattern = r'def\s+(dispatch|handle|process).*?\(.*?request.*?\)'
        for match in re.finditer(func_pattern, content, re.IGNORECASE):
            func_start = match.start()
            # Get the function body (simplified - just check next 500 chars)
            func_body = content[func_start:func_start + 500]
            
            # Check if it validates for notifications
            if '"id"' not in func_body and "'id'" not in func_body:
                line_num = content[:func_start].count('\n') + 1
                issues.append(ValidationIssue(
                    check_name=self.name,
                    severity=IssueSeverity.WARNING,
                    message=f"Request handler may not check for notifications",
                    line_number=line_num,
                    suggestion='Add: if "id" not in request: return ""',
                    code_snippet=match.group(0)
                ))
        
        return issues


class StdoutPollutionCheck(BaseCheck):
    """
    Check #5: No stdout pollution in stdio transport
    
    Any output to stdout breaks JSON-RPC parsing. Use logging to stderr.
    
    Example:
        Bad: standard print function calls
        Good: logging.error() or console.print() from Rich
    """
    
    name = "stdout_pollution"
    description = "Detect stdout pollution that breaks stdio transport"
    
    def check(self, content: str, file_path: Optional[Path] = None) -> List[ValidationIssue]:
        issues = []
        
        # Find bare print() calls (not console.print or in docstrings)
        for match in re.finditer(r'(?<!console\.)\bprint\s*\(', content):
            line_num = content[:match.start()].count('\n') + 1
            
            # Get surrounding context to check if in docstring/comment
            line_start = content.rfind('\n', 0, match.start()) + 1
            line_end = content.find('\n', match.start())
            if line_end == -1:
                line_end = len(content)
            line_content = content[line_start:line_end].strip()
            
            # Skip if in docstring, comment, or string literal
            context_before = content[max(0, match.start()-200):match.start()]
            if '"""' in context_before[-100:] or "'''" in context_before[-100:]:
                # Check if we're in a docstring
                triple_count = context_before.count('"""') + context_before.count("'''")
                if triple_count % 2 == 1:  # Odd number = inside docstring
                    continue
            
            if line_content.startswith('#'):
                continue
                
            # Skip if it's clearly an example in a string
            if match.start() > 0 and content[match.start()-1] in ['"', "'"]:
                continue
            
            issues.append(ValidationIssue(
                check_name=self.name,
                severity=IssueSeverity.ERROR,
                message="print() statement will pollute stdout and break stdio transport",
                line_number=line_num,
                suggestion="Use logging.error() or console.print() from Rich library",
                code_snippet=line_content
            ))
        
        # Check for sys.stdout.write (but not in docstrings)
        for match in re.finditer(r'sys\.stdout\.write', content):
            line_num = content[:match.start()].count('\n') + 1
            
            # Check if in docstring
            context_before = content[max(0, match.start()-200):match.start()]
            triple_count = context_before.count('"""') + context_before.count("'''")
            if triple_count % 2 == 1:  # Inside docstring
                continue
                
            issues.append(ValidationIssue(
                check_name=self.name,
                severity=IssueSeverity.ERROR,
                message="sys.stdout.write() will break stdio transport",
                line_number=line_num,
                suggestion="Use sys.stderr.write() or logging",
            ))
        
        return issues


class JsonRpcResponseStructureCheck(BaseCheck):
    """
    Check #6: JSON-RPC responses must always include 'id' and 'jsonrpc' fields
    
    The JSON-RPC 2.0 spec requires every response to have both 'jsonrpc' and 'id'
    fields, even if 'id' is null. Using exclude_none=True or manually removing
    these fields creates invalid responses that fail Zod validation.
    
    Example:
        Bad: model_dump_json(exclude_none=True)  # Removes 'id' when None
        Good: Always include 'id' and 'jsonrpc' in responses
    """
    
    name = "jsonrpc_response_structure"
    description = "Validate JSON-RPC responses include required 'id' and 'jsonrpc' fields"
    
    def check(self, content: str, file_path: Optional[Path] = None) -> List[ValidationIssue]:
        issues = []
        
        # Check for exclude_none=True in JSON-RPC response code
        # Look for context indicating this is JSON-RPC related
        is_jsonrpc_file = any(indicator in content for indicator in [
            'JsonRpcResponse', 'jsonrpc', 'JSON-RPC', 'json-rpc'
        ])
        
        if is_jsonrpc_file:
            for match in re.finditer(r'exclude_none\s*=\s*True', content):
                line_num = content[:match.start()].count('\n') + 1
                line_start = content.rfind('\n', 0, match.start()) + 1
                line_end = content.find('\n', match.start())
                if line_end == -1:
                    line_end = len(content)
                line_content = content[line_start:line_end].strip()
                
                # Skip if in docstring or comment
                context_before = content[max(0, match.start()-200):match.start()]
                triple_count = context_before.count('"""') + context_before.count("'''")
                if triple_count % 2 == 1:  # Inside docstring
                    continue
                if line_content.startswith('#'):
                    continue
                
                issues.append(ValidationIssue(
                    check_name=self.name,
                    severity=IssueSeverity.ERROR,
                    message="Using exclude_none=True removes required JSON-RPC fields when they are None",
                    line_number=line_num,
                    suggestion="Keep 'id' and 'jsonrpc' fields always present. Only exclude result/error conditionally.",
                    code_snippet=line_content
                ))
        
        # Check for manual removal of required JSON-RPC fields
        for match in re.finditer(r"\.pop\s*\(\s*['\"](?:id|jsonrpc)['\"]\s*\)", content):
            line_num = content[:match.start()].count('\n') + 1
            line_start = content.rfind('\n', 0, match.start()) + 1
            line_end = content.find('\n', match.start())
            if line_end == -1:
                line_end = len(content)
            line_content = content[line_start:line_end].strip()
            
            # Skip if in docstring or comment
            context_before = content[max(0, match.start()-200):match.start()]
            triple_count = context_before.count('"""') + context_before.count("'''")
            if triple_count % 2 == 1:
                continue
            if line_content.startswith('#'):
                continue
            
            # Check if this is explicitly checking for result/error mutual exclusivity
            # (that's valid - we only care about id/jsonrpc)
            field_name = re.search(r"['\"](.+?)['\"]", match.group(0)).group(1)
            if field_name in ['id', 'jsonrpc']:
                issues.append(ValidationIssue(
                    check_name=self.name,
                    severity=IssueSeverity.ERROR,
                    message=f"Removing required JSON-RPC field '{field_name}'",
                    line_number=line_num,
                    suggestion="JSON-RPC 2.0 requires 'id' and 'jsonrpc' in every response (can be null but must be present)",
                    code_snippet=line_content
                ))
        
        return issues


# Registry of all checks
ALL_CHECKS = [
    ToolNameCheck(),
    PropertiesSchemaCheck(),
    ContentWrapperCheck(),
    NotificationHandlingCheck(),
    StdoutPollutionCheck(),
    JsonRpcResponseStructureCheck(),
]
