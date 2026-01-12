"""
Nuclei Vulnerability Scan Tool

Performs template-based vulnerability scanning using Nuclei,
a fast and customizable vulnerability scanner.

WARNING: Only use against systems you have explicit authorization to test.
"""

from typing import Any
from urllib.parse import urlparse

from ..utils.validation import validate_url, sanitize_input
from ..utils.execution import run_command
from ..utils.rate_limiter import get_rate_limiter

TOOL_DEFINITION = {
    "name": "nuclei_scan",
    "description": """Perform template-based vulnerability scanning using Nuclei.

⚠️ AUTHORIZATION REQUIRED: Only scan systems you own or have written permission to test.

Nuclei uses community-maintained templates to detect:
- Known CVEs and vulnerabilities
- Misconfigurations
- Exposed sensitive files
- Default credentials
- Security weaknesses

Template categories:
- cves: Known CVE vulnerabilities
- vulnerabilities: General vulnerability checks
- misconfigurations: Configuration issues
- exposures: Sensitive data exposure
- technologies: Technology detection

Severity levels filter which templates are used:
- info: Informational findings
- low: Low severity issues
- medium: Medium severity issues
- high: High severity issues
- critical: Critical vulnerabilities""",
    "inputSchema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target URL to scan. Must be a system you have authorization to test."
            },
            "templates": {
                "type": "string",
                "description": "Comma-separated template categories (e.g., 'cves,vulnerabilities'). Leave empty for all."
            },
            "severity": {
                "type": "string",
                "enum": ["info", "low", "medium", "high", "critical"],
                "description": "Minimum severity level for findings. Default: medium"
            },
            "rate_limit": {
                "type": "integer",
                "description": "Maximum requests per second. Default: 50"
            }
        },
        "required": ["target"]
    }
}

# Valid template categories
VALID_CATEGORIES = {
    "cves", "vulnerabilities", "misconfigurations", "exposures",
    "technologies", "default-logins", "takeovers", "file",
    "fuzzing", "workflows"
}

# Severity levels in order
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def validate_templates(templates: str) -> list[str]:
    """Validate and parse template categories."""
    if not templates:
        return []

    result = []
    for cat in templates.split(","):
        cat = cat.strip().lower()
        if cat and cat in VALID_CATEGORIES:
            result.append(cat)

    return result


def validate_severity(severity: str) -> str:
    """Validate severity level."""
    if not severity:
        return "medium"

    severity = severity.strip().lower()
    if severity not in SEVERITY_ORDER:
        return "medium"

    return severity


async def execute(arguments: dict[str, Any]) -> str:
    """
    Execute a Nuclei vulnerability scan.

    Args:
        arguments: Dictionary containing:
            - target (required): URL to scan
            - templates (optional): Template categories
            - severity (optional): Minimum severity level
            - rate_limit (optional): Requests per second

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

    # Get options
    templates = validate_templates(arguments.get("templates", ""))
    severity = validate_severity(arguments.get("severity", "medium"))

    rate_limit = arguments.get("rate_limit", 50)
    if not isinstance(rate_limit, int) or rate_limit < 1 or rate_limit > 150:
        rate_limit = 50

    # Build command
    cmd = [
        "nuclei",
        "-u", target_url,
        "-silent",  # Silent mode
        "-no-color",  # No color output
        "-rate-limit", str(rate_limit),
        "-timeout", "10",  # 10 second timeout per request
        "-retries", "2",
    ]

    # Add template categories if specified
    if templates:
        for cat in templates:
            cmd.extend(["-tags", cat])

    # Add severity filter
    # Build severity list from selected level and above
    severity_idx = SEVERITY_ORDER.index(severity)
    selected_severities = SEVERITY_ORDER[severity_idx:]
    cmd.extend(["-severity", ",".join(selected_severities)])

    # Execute scan
    result = await run_command(cmd, timeout=900)  # 15 minute timeout

    # Format output
    output_parts = [
        f"Nuclei Vulnerability Scan Results",
        f"Target: {target_url}",
        f"Templates: {', '.join(templates) if templates else 'all'}",
        f"Minimum Severity: {severity}",
        "",
        "=" * 60,
        ""
    ]

    if result.stdout:
        # Parse nuclei output (each line is a finding)
        lines = result.stdout.strip().split("\n")
        if lines and lines[0]:
            output_parts.append(f"Found {len(lines)} potential issue(s):")
            output_parts.append("")
            for line in lines:
                if line.strip():
                    output_parts.append(f"  • {line}")
        else:
            output_parts.append("No vulnerabilities detected with the selected templates and severity.")
    else:
        output_parts.append("No vulnerabilities detected with the selected templates and severity.")

    if result.stderr and "error" in result.stderr.lower():
        output_parts.append("")
        output_parts.append("--- Errors ---")
        output_parts.append(result.stderr)

    output_parts.append("")
    output_parts.append("=" * 60)
    output_parts.append("⚠️ Review findings carefully. Verify vulnerabilities before reporting.")

    return "\n".join(output_parts)
