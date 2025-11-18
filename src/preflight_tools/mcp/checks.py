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


class _StdoutPollutionVisitor(ast.NodeVisitor):
    """AST visitor that detects stdout pollution patterns."""

    SAFE_PRINT_BASES = {"console", "console_err"}

    def __init__(self, content: str, check_name: str):
        self.content = content
        self.check_name = check_name
        self.issues: List[ValidationIssue] = []
        self.sys_modules: set[str] = set()
        self.stdout_aliases: set[str] = set()
        self.print_aliases: set[str] = {"print"}

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            if alias.name == "sys":
                self.sys_modules.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module == "sys":
            for alias in node.names:
                if alias.name == "stdout":
                    self.stdout_aliases.add(alias.asname or alias.name)
                if alias.name == "print":
                    self.print_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        self._handle_assignment(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        targets = [node.target]
        self._handle_assignment(targets, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        if self._is_print_call(node.func):
            self._add_issue(
                node,
                "print() statement will pollute stdout and break stdio transport",
                "Use logging.error() or configure Rich console to write to stderr.",
            )
        elif self._is_stdout_write_call(node.func):
            self._add_issue(
                node,
                "Writing to sys.stdout will break stdio transport",
                "Use sys.stderr.write() or a logger configured for stderr.",
            )
        self.generic_visit(node)

    # Assignment helpers -------------------------------------------------
    def _handle_assignment(self, targets: List[ast.expr], value: Optional[ast.expr]) -> None:
        if value and self._value_refers_to_stdout(value):
            for target in targets:
                if isinstance(target, ast.Name):
                    self.stdout_aliases.add(target.id)
        if value and self._value_refers_to_print(value):
            for target in targets:
                if isinstance(target, ast.Name):
                    self.print_aliases.add(target.id)

        for target in targets:
            self._maybe_flag_assignment(target, value)

    def _maybe_flag_assignment(self, target: ast.expr, value: Optional[ast.expr]) -> None:
        if self._is_sys_stdout_attribute(target):
            self._add_issue(
                target,
                "Reassigning sys.stdout breaks MCP stdio transport",
                "Avoid redirecting sys.stdout; log to stderr instead.",
            )
        elif isinstance(target, ast.Name) and target.id in self.stdout_aliases:
            if value is None or not self._value_refers_to_stdout(value):
                self._add_issue(
                    target,
                    "Reassigning stdout alias breaks MCP stdio transport",
                    "Keep stdout aliases pointed at sys.stderr or remove them entirely.",
                )

    # Detection helpers --------------------------------------------------
    def _is_print_call(self, func: ast.expr) -> bool:
        if isinstance(func, ast.Name):
            return func.id in self.print_aliases

        if isinstance(func, ast.Attribute):
            parts = self._attribute_chain(func)
            if parts and parts[-1] == "print":
                if any(part in self.SAFE_PRINT_BASES for part in parts[:-1]):
                    return False
                return True

        return False

    def _is_stdout_write_call(self, func: ast.expr) -> bool:
        if not isinstance(func, ast.Attribute):
            return False

        if func.attr != "write":
            return False

        target = func.value
        if self._is_sys_stdout_attribute(target):
            return True

        if isinstance(target, ast.Name) and target.id in self.stdout_aliases:
            return True

        return False

    def _is_sys_stdout_attribute(self, node: ast.expr) -> bool:
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "stdout"
            and isinstance(node.value, ast.Name)
            and node.value.id in self.sys_modules
        )

    def _value_refers_to_stdout(self, value: ast.expr) -> bool:
        if isinstance(value, ast.Name):
            return value.id in self.stdout_aliases

        if isinstance(value, ast.Attribute):
            return (
                value.attr == "stdout"
                and isinstance(value.value, ast.Name)
                and value.value.id in self.sys_modules
            )

        return False

    def _value_refers_to_print(self, value: ast.expr) -> bool:
        if isinstance(value, ast.Name):
            return value.id in self.print_aliases

        if isinstance(value, ast.Attribute):
            parts = self._attribute_chain(value)
            if parts and parts[-1] == "print":
                return not any(part in self.SAFE_PRINT_BASES for part in parts[:-1])

        return False

    def _attribute_chain(self, node: ast.expr) -> List[str]:
        parts: List[str] = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return list(reversed(parts))

    def _add_issue(self, node: ast.AST, message: str, suggestion: str) -> None:
        snippet = ast.get_source_segment(self.content, node)
        self.issues.append(ValidationIssue(
            check_name=self.check_name,
            severity=IssueSeverity.ERROR,
            message=message,
            line_number=getattr(node, "lineno", None),
            suggestion=suggestion,
            code_snippet=snippet.strip() if snippet else None,
        ))


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
        try:
            tree = ast.parse(content)
        except SyntaxError as exc:
            return [ValidationIssue(
                check_name=self.name,
                severity=IssueSeverity.INFO,
                message=f"Unable to parse file for stdout analysis: {exc.msg}",
                suggestion="Ensure the file parses before running preflight checks.",
            )]
        
        visitor = _StdoutPollutionVisitor(content, self.name)
        visitor.visit(tree)
        return visitor.issues


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
