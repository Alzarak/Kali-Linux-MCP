# Contributing to Kali Linux MCP Server

Thank you for your interest in contributing to this project! This document provides guidelines for contributions.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Remember this tool is for **defensive security testing only**
- Do not submit tools or modifications intended for malicious use

## How to Contribute

### Reporting Issues

1. Check existing issues first
2. Provide clear reproduction steps
3. Include relevant logs and configuration
4. Specify your environment (OS, Docker version, etc.)

### Suggesting Features

1. Open an issue with the "feature request" label
2. Describe the use case
3. Consider security implications
4. Propose implementation approach if possible

### Submitting Code

1. Fork the repository
2. Create a feature branch
3. Write clean, commented code
4. Add tests for new functionality
5. Update documentation
6. Submit a pull request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/kali-linux-mcp.git
cd kali-linux-mcp

# Build the Docker image
docker build -t kali-mcp-server:dev .

# Run tests
docker run --rm kali-mcp-server:dev python -m pytest

# Start development container
docker compose up -d
```

## Adding New Tools

When adding a new security tool:

### 1. Create Tool Module

```python
# src/tools/my_tool.py
from typing import Any
from ..utils.validation import validate_target
from ..utils.execution import run_command
from ..utils.rate_limiter import get_rate_limiter

TOOL_DEFINITION = {
    "name": "my_tool",
    "description": """Tool description here.

⚠️ AUTHORIZATION REQUIRED: Only use against authorized systems.

Detailed description of what the tool does...""",
    "inputSchema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target description"
            }
            # Add other parameters
        },
        "required": ["target"]
    }
}

async def execute(arguments: dict[str, Any]) -> str:
    """Execute the tool."""
    # Validate inputs
    target = validate_target(arguments["target"])

    # Rate limit
    rate_limiter = get_rate_limiter()
    await rate_limiter.acquire(target)

    # Build and execute command
    cmd = ["my-tool", "--option", target]
    result = await run_command(cmd, timeout=300)

    # Format output
    return format_output(result)
```

### 2. Register the Tool

Add to `src/tools/__init__.py`:

```python
from .my_tool import TOOL_DEFINITION as MY_TOOL_DEF, execute as my_tool_execute

TOOLS["my_tool"] = {
    **MY_TOOL_DEF,
    "_execute": my_tool_execute,
}
```

### 3. Update Dockerfile

Add the tool installation:

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    my-tool \
    && rm -rf /var/lib/apt/lists/*
```

### 4. Add Documentation

- Update README.md with tool reference
- Add usage examples to docs/EXAMPLES.md
- Document any special requirements

## Security Requirements

All contributions must:

1. **Validate all inputs** - Use the validation utilities
2. **Never use shell=True** - Execute commands as argument lists
3. **Respect rate limits** - Use the rate limiter
4. **Check target authorization** - Use validate_target()
5. **Set appropriate timeouts** - Prevent runaway processes
6. **Include authorization warnings** - All tool descriptions must warn about authorization

## Code Style

- Follow PEP 8 for Python code
- Use type hints
- Write docstrings for functions
- Keep functions focused and testable
- Use meaningful variable names

## Testing

- Test with authorized targets only (scanme.nmap.org, etc.)
- Include unit tests for validation logic
- Test error handling paths
- Verify blocked targets are rejected

## Documentation

- Update README for user-facing changes
- Add examples for new features
- Keep SECURITY.md current
- Document configuration options

## Pull Request Process

1. Ensure all tests pass
2. Update documentation
3. Add yourself to CONTRIBUTORS.md (optional)
4. Request review from maintainers
5. Address feedback promptly

## Questions?

Open an issue with the "question" label.

Thank you for contributing to defensive security!
