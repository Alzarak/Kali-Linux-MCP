"""
SQL Injection Test Tool (SQLMap)

Tests web application parameters for SQL injection vulnerabilities
using SQLMap.

WARNING: Only use against applications you have explicit authorization to test.
SQL injection testing without permission is illegal and can cause data loss.
"""

from typing import Any
from urllib.parse import urlparse, parse_qs

from ..utils.validation import validate_url, validate_integer_range
from ..utils.execution import run_command
from ..utils.rate_limiter import get_rate_limiter

TOOL_DEFINITION = {
    "name": "sql_injection_test",
    "description": """Test web application parameters for SQL injection using SQLMap.

⚠️ AUTHORIZATION REQUIRED: Only test applications you own or have written permission to test.
⚠️ DATA RISK: This tool can potentially modify or delete database data. Use with extreme caution.

SQLMap can detect and exploit SQL injection in:
- GET/POST parameters
- Cookie values
- HTTP headers

Level controls how many tests are performed (1-5):
- Level 1: Basic tests
- Level 2-3: More thorough
- Level 4-5: Exhaustive (may be slow)

Risk controls potential for data modification (1-3):
- Risk 1: Safe, no data modification
- Risk 2: May use time-based tests
- Risk 3: May use OR-based tests (can modify data)

This tool runs in safe mode by default (--batch --no-cast --safe-url).""",
    "inputSchema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target URL with parameters to test. Example: http://example.com/page.php?id=1"
            },
            "level": {
                "type": "integer",
                "minimum": 1,
                "maximum": 5,
                "description": "Test thoroughness level (1-5). Higher = more tests, slower. Default: 1"
            },
            "risk": {
                "type": "integer",
                "minimum": 1,
                "maximum": 3,
                "description": "Risk level (1-3). Higher = more aggressive tests. Default: 1"
            },
            "technique": {
                "type": "string",
                "description": "SQL injection techniques to test: B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline. Default: BEUST"
            }
        },
        "required": ["target"]
    }
}

# Allowed techniques
VALID_TECHNIQUES = set("BEUSTQ")


def validate_technique(technique: str) -> str:
    """Validate SQLMap technique string."""
    if not technique:
        return "BEUST"

    technique = technique.upper().strip()

    if not all(c in VALID_TECHNIQUES for c in technique):
        raise ValueError(f"Invalid technique. Use only: B,E,U,S,T,Q. Got: {technique}")

    return technique


async def execute(arguments: dict[str, Any]) -> str:
    """
    Execute a SQLMap SQL injection test.

    Args:
        arguments: Dictionary containing:
            - target (required): URL with parameters to test
            - level (optional): Test level 1-5
            - risk (optional): Risk level 1-3
            - technique (optional): SQLi techniques to test

    Returns:
        Formatted test results
    """
    # Validate URL
    target_url = validate_url(arguments["target"])

    # Ensure URL has parameters to test
    parsed = urlparse(target_url)
    if not parsed.query:
        raise ValueError("Target URL must include parameters to test (e.g., ?id=1)")

    # Parse URL to get host for rate limiting
    hostname = parsed.hostname

    # Rate limit
    rate_limiter = get_rate_limiter()
    await rate_limiter.acquire(hostname)

    # Get and validate options
    level = arguments.get("level", 1)
    if isinstance(level, int):
        level = validate_integer_range(level, 1, 5, "level")
    else:
        level = 1

    risk = arguments.get("risk", 1)
    if isinstance(risk, int):
        risk = validate_integer_range(risk, 1, 3, "risk")
    else:
        risk = 1

    technique = validate_technique(arguments.get("technique", "BEUST"))

    # Build command - SQLMap with safety options
    cmd = [
        "sqlmap",
        "-u", target_url,
        "--level", str(level),
        "--risk", str(risk),
        "--technique", technique,
        "--batch",  # Non-interactive
        "--no-cast",  # Don't cast data types
        "--smart",  # Smart mode
        "--threads", "1",  # Single thread for safety
        "--timeout", "30",  # Connection timeout
        "--retries", "2",  # Retry count
        "--output-dir", "/tmp/sqlmap",  # Output directory
    ]

    # Execute test (SQLMap can take a while)
    result = await run_command(cmd, timeout=600)

    # Format output
    output_parts = [
        f"SQLMap SQL Injection Test Results",
        f"Target: {target_url}",
        f"Level: {level}, Risk: {risk}",
        f"Techniques: {technique}",
        "",
        "=" * 60,
        ""
    ]

    if result.stdout:
        # Filter out some noise from SQLMap output
        lines = result.stdout.split("\n")
        filtered = []
        for line in lines:
            # Skip some verbose lines
            if any(skip in line.lower() for skip in [
                "legal disclaimer",
                "usage of sqlmap",
                "detected potential",
            ]):
                continue
            filtered.append(line)
        output_parts.append("\n".join(filtered))

    if result.stderr and "error" in result.stderr.lower():
        output_parts.append("")
        output_parts.append("--- Errors ---")
        output_parts.append(result.stderr)

    output_parts.append("")
    output_parts.append("=" * 60)
    output_parts.append("⚠️ If vulnerabilities found, follow responsible disclosure practices.")

    return "\n".join(output_parts)
