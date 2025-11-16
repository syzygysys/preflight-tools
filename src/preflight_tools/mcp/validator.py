"""
MCP Validator - Orchestrates all compliance checks

Copyright 2025 SyzygySys
Licensed under the Apache License, Version 2.0
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from preflight_tools.mcp.checks import (
    ALL_CHECKS,
    ValidationIssue,
    IssueSeverity,
)


@dataclass
class ValidationResult:
    """Result of a validation run"""
    file_path: Optional[Path]
    total_checks: int
    issues: List[ValidationIssue]
    passed: bool
    
    @property
    def error_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity == IssueSeverity.ERROR)
    
    @property
    def warning_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity == IssueSeverity.WARNING)
    
    @property
    def info_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity == IssueSeverity.INFO)


class MCPValidator:
    """
    MCP Protocol Compliance Validator
    
    Validates MCP server implementations against the five critical checks
    identified during LAP::CORE debugging.
    
    Example:
        validator = MCPValidator()
        result = validator.validate_file("path/to/tools.py")
        
        if not result.passed:
            for issue in result.issues:
                print(f"{issue.severity.value}: {issue.message}")
    """
    
    def __init__(self, strict: bool = False, ignore_checks: Optional[List[str]] = None):
        """
        Initialize validator
        
        Args:
            strict: Treat warnings as errors
            ignore_checks: List of check names to skip
        """
        self.strict = strict
        self.ignore_checks = set(ignore_checks or [])
        self.checks = [
            check for check in ALL_CHECKS 
            if check.name not in self.ignore_checks
        ]
    
    def validate_file(self, file_path: str | Path) -> ValidationResult:
        """
        Validate a Python file containing MCP tools
        
        Args:
            file_path: Path to the file to validate
            
        Returns:
            ValidationResult with all issues found
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            return ValidationResult(
                file_path=file_path,
                total_checks=0,
                issues=[ValidationIssue(
                    check_name="file_access",
                    severity=IssueSeverity.ERROR,
                    message=f"File not found: {file_path}",
                )],
                passed=False
            )
        
        content = file_path.read_text(encoding='utf-8')
        return self.validate_content(content, file_path)
    
    def validate_content(self, content: str, file_path: Optional[Path] = None) -> ValidationResult:
        """
        Validate content string
        
        Args:
            content: Python code to validate
            file_path: Optional path for error reporting
            
        Returns:
            ValidationResult with all issues found
        """
        all_issues = []
        
        for check in self.checks:
            issues = check.check(content, file_path)
            all_issues.extend(issues)
        
        # Determine if passed
        error_count = sum(1 for issue in all_issues if issue.severity == IssueSeverity.ERROR)
        warning_count = sum(1 for issue in all_issues if issue.severity == IssueSeverity.WARNING)
        
        passed = error_count == 0 and (not self.strict or warning_count == 0)
        
        return ValidationResult(
            file_path=file_path,
            total_checks=len(self.checks),
            issues=all_issues,
            passed=passed
        )
    
    def validate_directory(self, dir_path: str | Path, pattern: str = "*.py") -> Dict[Path, ValidationResult]:
        """
        Validate all matching files in a directory
        
        Args:
            dir_path: Directory to scan
            pattern: File pattern to match (default: *.py)
            
        Returns:
            Dict mapping file paths to their validation results
        """
        dir_path = Path(dir_path)
        results = {}
        
        for file_path in dir_path.rglob(pattern):
            if file_path.is_file():
                results[file_path] = self.validate_file(file_path)
        
        return results
