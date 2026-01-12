"""
SSL/TLS Analysis Tool (testssl.sh)

Analyzes SSL/TLS configuration of servers using testssl.sh,
checking for vulnerabilities, weak ciphers, and misconfigurations.

WARNING: Only use against servers you have explicit authorization to test.
"""

from typing import Any

from ..utils.validation import validate_target
from ..utils.execution import run_command
from ..utils.rate_limiter import get_rate_limiter

TOOL_DEFINITION = {
    "name": "ssl_analysis",
    "description": """Analyze SSL/TLS configuration using testssl.sh.

⚠️ AUTHORIZATION REQUIRED: Only test servers you own or have written permission to test.

testssl.sh checks for:
- Supported protocols (SSLv2, SSLv3, TLS 1.0-1.3)
- Cipher suites and their strength
- Known vulnerabilities (POODLE, BEAST, Heartbleed, etc.)
- Certificate validity and chain
- Security headers (HSTS, etc.)

Check levels:
- quick: Basic protocol and cipher checks (~1-2 min)
- standard: Protocols, ciphers, and common vulnerabilities (~3-5 min)
- full: Comprehensive analysis including all vulnerability checks (~10-15 min)""",
    "inputSchema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target host:port (e.g., 'example.com:443') or URL. Must be a server you have authorization to test."
            },
            "checks": {
                "type": "string",
                "enum": ["quick", "standard", "full"],
                "description": "Level of checks to perform. Default: standard"
            }
        },
        "required": ["target"]
    }
}

# Check level configurations
CHECK_CONFIGS = {
    "quick": {
        "args": ["-p", "-s", "-f"],  # Protocols, server preferences, forward secrecy
        "timeout": 180,
        "description": "Quick - protocols, ciphers, basic checks"
    },
    "standard": {
        "args": ["-p", "-s", "-f", "-U", "-S"],  # Add vulnerabilities and server defaults
        "timeout": 420,
        "description": "Standard - protocols, ciphers, common vulnerabilities"
    },
    "full": {
        "args": [],  # Full scan (default testssl.sh behavior)
        "timeout": 1200,
        "description": "Full - comprehensive analysis"
    }
}


def normalize_target(target: str) -> str:
    """
    Normalize target to host:port format.

    Handles:
    - hostname -> hostname:443
    - hostname:port -> hostname:port
    - https://hostname -> hostname:443
    - https://hostname:port -> hostname:port
    """
    target = target.strip()

    # Remove protocol prefix
    if target.startswith("https://"):
        target = target[8:]
    elif target.startswith("http://"):
        target = target[7:]

    # Remove trailing path
    target = target.split("/")[0]

    # Add default port if not specified
    if ":" not in target:
        target = f"{target}:443"

    return target


async def execute(arguments: dict[str, Any]) -> str:
    """
    Execute a testssl.sh SSL/TLS analysis.

    Args:
        arguments: Dictionary containing:
            - target (required): Host:port or URL to analyze
            - checks (optional): quick, standard, or full

    Returns:
        Formatted analysis results
    """
    # Normalize and validate target
    target = normalize_target(arguments["target"])

    # Extract hostname for validation and rate limiting
    hostname = target.split(":")[0]
    validate_target(hostname)

    # Rate limit
    rate_limiter = get_rate_limiter()
    await rate_limiter.acquire(hostname)

    # Get check level
    check_level = arguments.get("checks", "standard")
    if check_level not in CHECK_CONFIGS:
        check_level = "standard"

    config = CHECK_CONFIGS[check_level]

    # Build command
    cmd = ["testssl.sh"]
    cmd.extend(config["args"])
    cmd.extend([
        "--color", "0",  # No ANSI colors
        "--quiet",  # Less verbose
        target
    ])

    # Execute analysis
    result = await run_command(cmd, timeout=config["timeout"])

    # Format output
    output_parts = [
        f"testssl.sh SSL/TLS Analysis Results",
        f"Target: {target}",
        f"Check Level: {config['description']}",
        "",
        "=" * 60,
        ""
    ]

    if result.stdout:
        output_parts.append(result.stdout)
    else:
        output_parts.append("No output received from testssl.sh")

    if result.stderr:
        # testssl.sh often puts progress to stderr
        # Only show if there seem to be actual errors
        if "error" in result.stderr.lower() or "fatal" in result.stderr.lower():
            output_parts.append("")
            output_parts.append("--- Errors ---")
            output_parts.append(result.stderr)

    output_parts.append("")
    output_parts.append("=" * 60)
    output_parts.append("Legend: Rating A-F (A+ is best). Review any findings marked VULNERABLE.")

    return "\n".join(output_parts)
