"""
MCP Preflight Check CLI

Command-line interface for MCP protocol validation

Copyright 2025 SyzygySys
Licensed under the Apache License, Version 2.0
"""

from pathlib import Path
from typing import Optional, List
import sys

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from preflight_tools.mcp.validator import MCPValidator
from preflight_tools.mcp.checks import IssueSeverity


app = typer.Typer(
    name="mcp-preflight-check",
    help="MCP Protocol Compliance Validator",
    add_completion=False,
)
console = Console()
console_err = Console(stderr=True)


def _print_result(result, verbose: bool = False):
    """Print validation result in a nice format"""
    
    # Summary panel
    if result.passed:
        console.print(Panel(
            f"✅ [green]PASSED[/green] - No issues found\n"
            f"Ran {result.total_checks} checks",
            title=f"Validation Result: {result.file_path.name if result.file_path else 'Content'}",
            border_style="green"
        ))
    else:
        console.print(Panel(
            f"❌ [red]FAILED[/red]\n"
            f"Errors: {result.error_count}, "
            f"Warnings: {result.warning_count}, "
            f"Info: {result.info_count}",
            title=f"Validation Result: {result.file_path.name if result.file_path else 'Content'}",
            border_style="red"
        ))
    
    if not result.issues:
        return
    
    # Issues table
    table = Table(title="Issues Found", box=box.ROUNDED)
    table.add_column("Severity", style="bold")
    table.add_column("Check", style="cyan")
    table.add_column("Line", justify="right")
    table.add_column("Message")
    
    for issue in sorted(result.issues, key=lambda x: (x.severity.value, x.line_number or 0)):
        severity_style = {
            IssueSeverity.ERROR: "[red]ERROR[/red]",
            IssueSeverity.WARNING: "[yellow]WARNING[/yellow]",
            IssueSeverity.INFO: "[blue]INFO[/blue]",
        }[issue.severity]
        
        table.add_row(
            severity_style,
            issue.check_name,
            str(issue.line_number) if issue.line_number else "-",
            issue.message
        )
    
    console.print(table)
    
    # Suggestions (in verbose mode)
    if verbose and any(issue.suggestion for issue in result.issues):
        console.print("\n[bold cyan]Fix Suggestions:[/bold cyan]")
        for issue in result.issues:
            if issue.suggestion:
                console.print(f"  Line {issue.line_number or '?'}: [yellow]{issue.suggestion}[/yellow]")
                if issue.code_snippet:
                    console.print(f"    Code: [dim]{issue.code_snippet}[/dim]")


@app.command()
def validate(
    path: str = typer.Argument(..., help="File or directory to validate"),
    strict: bool = typer.Option(False, "--strict", help="Treat warnings as errors"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
    ignore: Optional[List[str]] = typer.Option(None, "--ignore", help="Checks to ignore"),
    pattern: str = typer.Option("*.py", "--pattern", "-p", help="File pattern for directory validation"),
):
    """
    Validate MCP server implementation files
    
    Examples:
    
        # Validate a single file
        mcp-preflight-check validate path/to/tools.py
        
        # Validate directory with verbose output
        mcp-preflight-check validate --verbose src/
        
        # Strict mode (warnings fail)
        mcp-preflight-check validate --strict path/to/tools.py
        
        # Ignore specific checks
        mcp-preflight-check validate --ignore stdout_pollution src/
    """
    path_obj = Path(path)
    
    if not path_obj.exists():
        console_err.print(f"[red]Error:[/red] Path not found: {path}")
        raise typer.Exit(1)
    
    validator = MCPValidator(strict=strict, ignore_checks=ignore)
    
    if path_obj.is_file():
        result = validator.validate_file(path_obj)
        _print_result(result, verbose)
        
        if not result.passed:
            raise typer.Exit(1)
    else:
        results = validator.validate_directory(path_obj, pattern)
        
        if not results:
            console.print(f"[yellow]Warning:[/yellow] No files matching '{pattern}' found in {path}")
            raise typer.Exit(0)
        
        passed_count = sum(1 for r in results.values() if r.passed)
        failed_count = len(results) - passed_count
        
        console.print(f"\n[bold]Validated {len(results)} files:[/bold]")
        console.print(f"  ✅ Passed: {passed_count}")
        console.print(f"  ❌ Failed: {failed_count}\n")
        
        for file_path, result in results.items():
            if not result.passed or verbose:
                _print_result(result, verbose)
        
        if failed_count > 0:
            raise typer.Exit(1)


@app.command()
def version():
    """Show version information"""
    from preflight_tools import __version__
    console.print(f"mcp-preflight-check version {__version__}")
    console.print("Part of preflight-tools: https://github.com/syzygysys/preflight-tools")


@app.command()
def list_checks():
    """List all available validation checks"""
    from preflight_tools.mcp.checks import ALL_CHECKS
    
    table = Table(title="Available MCP Checks", box=box.ROUNDED)
    table.add_column("Check Name", style="cyan")
    table.add_column("Description")
    
    for check in ALL_CHECKS:
        table.add_row(check.name, check.description)
    
    console.print(table)


if __name__ == "__main__":
    app()
