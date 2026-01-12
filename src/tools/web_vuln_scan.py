"""
Web Vulnerability Scan Tool (Nikto)

Scans web servers for known vulnerabilities, misconfigurations,
and dangerous files using Nikto.

WARNING: Only use against web servers you have explicit authorization to scan.
Web vulnerability scanning without permission may be illegal.
"""

from typing import Any
from urllib.parse import urlparse

from ..utils.validation import validate_url, validate_target
from ..utils.execution import run_command
from ..utils.rate_limiter import get_rate_limiter

TOOL_DEFINITION = {
    "name": "web_vuln_scan",
    "description": """Scan web servers for vulnerabilities using Nikto.

⚠️ AUTHORIZATION REQUIRED: Only scan web servers you own or have written permission to test.

Nikto checks for:
- Known vulnerable scripts and programs
- Server misconfigurations
- Dangerous files and directories
- Outdated software versions
- Security headers

Tuning options control what types of checks are performed:
1 - Interesting File / Seen in logs
2 - Misconfiguration / Default File
3 - Information Disclosure
4 - Injection (XSS/Script/HTML)
5 - Remote File Retrieval - Inside Web Root
6 - Denial of Service
7 - Remote File Retrieval - Server Wide
8 - Command Execution / Remote Shell
9 - SQL Injection
0 - File Upload""",
    "inputSchema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target URL (http:// or https://). Must be a server you have authorization to test."
            },
            "tuning": {
                "type": "string",
                "description": "Nikto tuning options (1-9, 0). Combine multiple: '123' for file/misconfig/disclosure checks. Default: '123'"
            },
            "timeout": {
                "type": "integer",
                "description": "Maximum scan time in seconds. Default: 300"
            }
        },
        "required": ["target"]
    }
}

# Valid tuning options
VALID_TUNING = set("0123456789")


def validate_tuning(tuning: str) -> str:
    """Validate Nikto tuning options."""
    if not tuning:
        return "123"

    tuning = tuning.strip()

    # Check all characters are valid
    if not all(c in VALID_TUNING for c in tuning):
        raise ValueError(f"Invalid tuning option. Use digits 0-9 only. Got: {tuning}")

    return tuning


async def execute(arguments: dict[str, Any]) -> str:
    """
    Execute a Nikto web vulnerability scan.

    Args:
        arguments: Dictionary containing:
            - target (required): URL to scan
            - tuning (optional): Nikto tuning options
            - timeout (optional): Maximum scan time

    Returns:
        Formatted scan results
    """
    # Validate URL
    target_url = validate_url(arguments["target"])

    # Parse URL to get host for rate limiting
    parsed = urlparse(target_url)
    hostname = parsed.hostname

    # Rate limit
    rate_limiter = get_rate_limiter()
    await rate_limiter.acquire(hostname)

    # Get tuning options
    tuning = validate_tuning(arguments.get("tuning", "123"))

    # Get timeout
    timeout = arguments.get("timeout", 300)
    if not isinstance(timeout, int) or timeout < 30 or timeout > 3600:
        timeout = 300

    # Build command
    cmd = [
        "nikto",
        "-h", target_url,
        "-Tuning", tuning,
        "-maxtime", f"{timeout}s",
        "-nointeractive",
        "-Format", "txt",
        "-output", "-",  # Output to stdout
    ]

    # Execute scan
    result = await run_command(cmd, timeout=timeout + 60)  # Extra buffer for cleanup

    # Format output
    output_parts = [
        f"Nikto Web Vulnerability Scan Results",
        f"Target: {target_url}",
        f"Tuning: {tuning}",
        "",
        "=" * 60,
        ""
    ]

    if result.success:
        output_parts.append(result.stdout)
    else:
        # Nikto often returns non-zero on findings
        output_parts.append(result.stdout)
        if result.stderr and "error" in result.stderr.lower():
            output_parts.append("")
            output_parts.append("--- Errors ---")
            output_parts.append(result.stderr)

    output_parts.append("")
    output_parts.append("=" * 60)
    output_parts.append("Note: Review findings carefully. Not all items are vulnerabilities.")

    return "\n".join(output_parts)
