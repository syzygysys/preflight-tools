# Contributing to preflight-tools

Thanks for your interest in improving the MCP Preflight Validator! We welcome bug reports, feature suggestions, and pull requests that help autonomous-agent developers avoid the landmines documented in [Architect’s Notebook — Log 14](https://syzygysys.io/docs/log_14.html).

## Getting Started

1. **Fork & clone** the repository.  
2. **Install dependencies** using Poetry (Python 3.10+ required):
   ```bash
   poetry install
   ```
3. **Run tests** to make sure everything passes before you start:
   ```bash
   PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 pytest -p no:cacheprovider
   ```

## Development Workflow

1. Create a topic branch off `main` (or the currently active feature branch) that describes your change, e.g. `fix/stdout-alias-detection`.
2. Make your changes with clear commits. Add tests whenever possible, especially for new validation rules or CLI behavior.
3. Run the full test suite and ensure coverage stays healthy:
   ```bash
   PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 pytest -p no:cacheprovider --cov=preflight_tools
   ```
4. Submit a pull request with:
   - A concise summary of the change and motivation
   - Any additional context (linked issues, protocol references)
   - Confirmation that tests pass locally

## Reporting Issues

Use GitHub Issues for bugs or feature requests. Please include:
* **Steps to reproduce** (or the tool/server snippet that triggers the validator)
* **Expected vs. actual behavior**
* **Environment** (OS, Python version, validator version)
* **Logs/output** if relevant (redact sensitive data)

If the issue is security-sensitive (e.g., a vulnerability in the validator or its dependencies), please follow the process in [SECURITY.md](SECURITY.md).

## Style & Standards

* Follow [PEP 8](https://peps.python.org/pep-0008/) style guidelines; run `ruff`/`black` if you have them installed.
* Keep the validator’s checks deterministic—avoid filesystem or network access inside check classes.
* Prefer AST analysis over regex when validating Python code snippets (see `StdoutPollutionCheck` for reference).
* Document new checks in the README and the CLI’s `list-checks` output.

## Community Expectations

By participating, you agree to uphold our [Code of Conduct](CODE_OF_CONDUCT.md). Please be respectful, stay factual, and remember that contributors span multiple time zones and backgrounds.

## Questions?

Open a discussion or email the maintainers at support@syzygysys.io if you’re unsure about the best way to contribute. We’re excited to collaborate!
