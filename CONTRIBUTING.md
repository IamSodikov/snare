# Contributing to Desktop Sniffer

Thank you for your interest in contributing to Desktop Sniffer! 

## Code of Conduct
Please be respectful, collaborative, and considerate of others in discussions and pull requests.

## How Can I Contribute?

### Reporting Bugs
- Use the GitHub issue tracker.
- Describe the bug clearly, including:
  - Your OS version (Windows / macOS / Linux)
  - Python version
  - Exact steps to reproduce the issue
  - Relevant logs from the **Engine Logs** tab

### Suggesting Enhancements
- Open a feature request issue.
- Explain why the enhancement would be useful and how it should behave.

### Pull Requests
1. Fork the repo and create your branch from `main`.
2. Ensure existing tests pass:
   ```bash
   pytest
   ```
3. Follow PEP 8 style standards with Ruff:
   ```bash
   ruff check .
   ```
4. Write clear commit messages and describe your changes in the PR description.
